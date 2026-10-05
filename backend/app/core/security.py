"""JWT authentication, request-identity, and password hashing utilities."""

from datetime import datetime, timedelta, timezone
from typing import Optional
import logging
import secrets
import bcrypt
from jose import JWTError, jwt
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.db.session import get_db

logger = logging.getLogger(__name__)

# JWT Bearer scheme
security = HTTPBearer()

# bcrypt truncates/limits input at 72 *bytes* (not characters) and raises
# ValueError beyond that. Password schemas validate against this same limit so
# the API never reaches the hashing layer with an unsupported password. Passwords
# are never silently truncated: the request is rejected with a clear message.
BCRYPT_MAX_PASSWORD_BYTES = 72


class PasswordTooLongError(ValueError):
    """Password exceeds the maximum length supported by the hashing algorithm."""

    def __init__(self, byte_length: int):
        self.byte_length = byte_length
        super().__init__(
            f"Password must not exceed {BCRYPT_MAX_PASSWORD_BYTES} bytes when "
            f"UTF-8 encoded (received {byte_length} bytes). Use a shorter password."
        )


def password_byte_length(password: str) -> int:
    """Return the UTF-8 byte length of a password."""
    return len(password.encode("utf-8"))


def assert_password_hashable(password: str) -> str:
    """Validate that a password can be passed to bcrypt, else raise ValueError."""
    if password_byte_length(password) > BCRYPT_MAX_PASSWORD_BYTES:
        raise PasswordTooLongError(password_byte_length(password))
    return password


def hash_password(password: str) -> str:
    """Hash a plain-text password using direct bcrypt."""
    assert_password_hashable(password)
    pwd_bytes = password.encode("utf-8")
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(pwd_bytes, salt).decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a plain-text password against a bcrypt hash."""
    try:
        pwd_bytes = plain_password.encode("utf-8")
        hash_bytes = hashed_password.encode("utf-8")
        return bcrypt.checkpw(pwd_bytes, hash_bytes)
    except Exception:
        return False


# A bcrypt hash of an unguessable value, used to spend the same amount of CPU
# on a login for an unknown account as on a known one. Without this the
# response time reveals whether an address is registered.
#
# The hash is generated at import time from a fresh random secret rather than
# hardcoded, so there is no secret in the source and the value is structurally
# valid on every bcrypt build. It must never correspond to a real password.
def _build_timing_decoy_hash() -> bytes:
    return bcrypt.hashpw(secrets.token_bytes(32), bcrypt.gensalt(rounds=12))


_TIMING_DECOY_HASH = _build_timing_decoy_hash()


def burn_password_verification_time() -> None:
    """Perform a dummy bcrypt comparison to equalise login response times."""
    try:
        bcrypt.checkpw(secrets.token_bytes(16), _TIMING_DECOY_HASH)
    except Exception:  # pragma: no cover - defensive only
        # A malformed decoy must never break authentication. Logged rather than
        # silently ignored, because this would reintroduce the timing leak.
        logger.error(
            "Timing decoy hash is unusable; login response times may reveal "
            "whether an account exists",
            exc_info=True,
        )


def client_ip_from_request(request: Request) -> str:
    """Return the caller's IP address for throttling and audit purposes.

    ``X-Forwarded-For`` is only honoured when ``TRUST_PROXY_HEADERS`` is
    enabled. Trusting it unconditionally would let any client spoof an
    arbitrary address and walk straight around the login throttle, so the
    direct peer address is used by default.
    """
    if settings.TRUST_PROXY_HEADERS:
        forwarded = request.headers.get("x-forwarded-for", "")
        if forwarded:
            first_hop = forwarded.split(",")[0].strip()
            if first_hop:
                return first_hop
        real_ip = request.headers.get("x-real-ip", "").strip()
        if real_ip:
            return real_ip
    client = request.client
    return client.host if client and client.host else "unknown"


def create_access_token(
    data: dict, expires_delta: Optional[timedelta] = None
) -> str:
    """Create a JWT access token with expiration."""
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (
        expires_delta
        or timedelta(minutes=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    to_encode.update({"exp": expire, "iat": datetime.now(timezone.utc)})
    return jwt.encode(
        to_encode, settings.jwt_secret_key, algorithm=settings.JWT_ALGORITHM
    )


def decode_access_token(token: str) -> dict:
    """Decode and validate a JWT access token.

    Returns the token payload if valid.
    Raises HTTPException if invalid or expired.
    """
    try:
        payload = jwt.decode(
            token,
            settings.jwt_secret_key,
            algorithms=[settings.JWT_ALGORITHM],
            # python-jose only checks ``exp`` when the claim happens to be
            # present, so a token without one decoded successfully and then
            # never expired. ``create_access_token`` always sets ``exp``; this
            # makes its absence an error instead of a silent lifetime extension.
            options={"require_exp": True},
        )
        return payload
    except JWTError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired authentication token",
            headers={"WWW-Authenticate": "Bearer"},
        ) from e


async def get_current_user_id(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: AsyncSession = Depends(get_db),
) -> int:
    """Extract and validate user ID from JWT token.

    This is the main dependency for protected routes.

    A signed token proves *who* the caller claims to be, not that the account is
    still usable. `is_active` used to be checked only at login, so
    deactivating or deleting an account left every already-issued token fully
    working until it expired. The account is therefore re-read on every request
    so revocation takes effect immediately.
    """
    payload = decode_access_token(credentials.credentials)
    user_id = payload.get("sub")
    if user_id is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token: missing user identity",
        )

    # ``sub`` is a claim inside the token, so it is untrusted input: a token
    # carrying a non-numeric subject used to reach ``int()`` unguarded and raise
    # ValueError, which surfaced as a 500 instead of a 401. Validate before use.
    try:
        user_id = int(user_id)
    except (TypeError, ValueError):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token: malformed user identity",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if user_id <= 0:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token: malformed user identity",
            headers={"WWW-Authenticate": "Bearer"},
        )

    from app.models.user import User

    active_id = (
        await db.execute(
            select(User.id).where(User.id == user_id, User.is_active.is_(True))
        )
    ).scalar_one_or_none()
    if active_id is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="This account is inactive or no longer exists",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return int(active_id)
