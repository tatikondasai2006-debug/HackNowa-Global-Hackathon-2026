"""Authentication and User Profile API Endpoints."""

import logging

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_db
from app.schemas.user import (
    UserRegister, UserLogin, UserResponse, TokenResponse,
    UserUpdate, PasswordChange
)
from app.services.user_service import UserService
from app.services.login_throttle import login_throttle
from app.core.exceptions import LoginThrottledError
from app.core.security import get_current_user_id, client_ip_from_request
from app.core.config import settings

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/auth", tags=["Authentication"])

# Every rejected login returns this exact message so a caller cannot tell a
# valid address from an invalid one.
INVALID_CREDENTIALS = "Incorrect email or password"


@router.post("/register", response_model=TokenResponse, status_code=status.HTTP_201_CREATED)
async def register(data: UserRegister, db: AsyncSession = Depends(get_db)):
    """Register a new user account and return JWT access token."""
    service = UserService(db)
    try:
        user = await service.register(data)
        token_data = service.create_token(user)
        return TokenResponse(
            access_token=token_data["access_token"],
            token_type="bearer",
            expires_in=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60,
            user=UserResponse.model_validate(user),
        )
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.post("/login", response_model=TokenResponse)
async def login(
    data: UserLogin,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Authenticate user with email and password and return JWT access token.

    Repeated failures are throttled with progressive backoff. The rejection
    message and status are identical for unknown accounts, wrong passwords and
    inactive accounts, so the endpoint cannot be used to enumerate users.
    """
    client_ip = client_ip_from_request(request)
    throttle_key = login_throttle.make_key(client_ip, data.email)

    delay = login_throttle.delay_for(throttle_key)
    if delay > 0:
        logger.warning(
            "Blocked throttled login attempt from client=%s retry_in=%ss",
            client_ip,
            delay,
        )
        raise LoginThrottledError(
            "Too many failed sign-in attempts. Please wait before trying again.",
            retry_after=delay,
        )

    service = UserService(db)
    user = await service.authenticate(data)
    if not user:
        login_throttle.record_failure(throttle_key)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=INVALID_CREDENTIALS,
            headers={"WWW-Authenticate": "Bearer"},
        )

    login_throttle.record_success(throttle_key)
    token_data = service.create_token(user)
    return TokenResponse(
        access_token=token_data["access_token"],
        token_type="bearer",
        expires_in=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        user=UserResponse.model_validate(user),
    )


@router.get("/me", response_model=UserResponse)
async def get_current_user(
    user_id: int = Depends(get_current_user_id),
    db: AsyncSession = Depends(get_db),
):
    """Retrieve profile data for the authenticated user."""
    service = UserService(db)
    user = await service.get_user_by_id(user_id)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    return UserResponse.model_validate(user)


@router.put("/me", response_model=UserResponse)
async def update_profile(
    data: UserUpdate,
    user_id: int = Depends(get_current_user_id),
    db: AsyncSession = Depends(get_db),
):
    """Update profile information."""
    service = UserService(db)
    user = await service.update_user(user_id, data)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    return UserResponse.model_validate(user)


@router.post("/change-password")
async def change_password(
    data: PasswordChange,
    user_id: int = Depends(get_current_user_id),
    db: AsyncSession = Depends(get_db),
):
    """Change current user password."""
    service = UserService(db)
    success = await service.change_password(user_id, data.current_password, data.new_password)
    if not success:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Current password incorrect")
    return {"message": "Password changed successfully"}
