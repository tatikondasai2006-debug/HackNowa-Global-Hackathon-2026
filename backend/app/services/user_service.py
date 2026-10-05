"""User service for authentication and user management."""

from datetime import datetime, timezone
from typing import Optional
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
import logging

from app.models.user import User
from app.schemas.user import UserRegister, UserLogin, UserUpdate
from app.core.security import (
    burn_password_verification_time,
    create_access_token,
    hash_password,
    verify_password,
)

logger = logging.getLogger(__name__)


class UserService:
    """Business logic for user operations."""

    def __init__(self, db: AsyncSession):
        self.db = db

    async def register(self, data: UserRegister) -> User:
        """Register a new user account.

        Raises ValueError if email or username already exists.
        """
        # Check for existing email
        existing = await self.db.execute(
            select(User).where(User.email == data.email)
        )
        if existing.scalar_one_or_none():
            raise ValueError("An account with this email already exists")

        # Check for existing username
        existing = await self.db.execute(
            select(User).where(User.username == data.username)
        )
        if existing.scalar_one_or_none():
            raise ValueError("This username is already taken")

        # Create user
        user = User(
            email=data.email,
            username=data.username,
            hashed_password=hash_password(data.password),
            full_name=data.full_name,
            company_name=data.company_name,
        )
        self.db.add(user)
        await self.db.flush()
        await self.db.refresh(user)

        logger.info(f"User registered: {user.email} (id={user.id})")
        return user

    async def authenticate(self, data: UserLogin) -> Optional[User]:
        """Authenticate user with email and password.

        Returns the User if credentials are valid, None otherwise.

        An unknown email still performs a dummy bcrypt comparison so the
        response time does not reveal which addresses are registered.
        """
        result = await self.db.execute(
            select(User).where(User.email == data.email)
        )
        user = result.scalar_one_or_none()

        if not user:
            # Unknown address: spend the same CPU as a real comparison so the
            # response time does not reveal which addresses are registered.
            burn_password_verification_time()
            return None

        # Exactly one bcrypt comparison on every path below. Doing a real check
        # and then an extra dummy one (or vice versa) would make some outcomes
        # measurably slower than others and re-open the enumeration channel.
        password_matches = verify_password(data.password, user.hashed_password)
        if not password_matches or not user.is_active:
            return None

        # Update last login
        user.last_login_at = datetime.now(timezone.utc)
        await self.db.flush()

        logger.info(f"User authenticated: {user.email} (id={user.id})")
        return user

    async def get_user_by_id(self, user_id: int) -> Optional[User]:
        """Get user by ID."""
        result = await self.db.execute(
            select(User).where(User.id == user_id)
        )
        return result.scalar_one_or_none()

    async def update_user(self, user_id: int, data: UserUpdate) -> Optional[User]:
        """Update user profile information."""
        user = await self.get_user_by_id(user_id)
        if not user:
            return None

        if data.full_name is not None:
            user.full_name = data.full_name
        if data.company_name is not None:
            user.company_name = data.company_name

        await self.db.flush()
        await self.db.refresh(user)
        return user

    async def change_password(
        self, user_id: int, current_password: str, new_password: str
    ) -> bool:
        """Change user password.

        Returns True if successful, False if current password is wrong.
        """
        user = await self.get_user_by_id(user_id)
        if not user:
            return False

        if not verify_password(current_password, user.hashed_password):
            return False

        user.hashed_password = hash_password(new_password)
        await self.db.flush()

        logger.info(f"Password changed for user: {user.email} (id={user.id})")
        return True

    @staticmethod
    def create_token(user: User) -> dict:
        """Create JWT token for authenticated user."""
        token = create_access_token(
            data={"sub": str(user.id), "email": user.email}
        )
        return {
            "access_token": token,
            "token_type": "bearer",
        }
