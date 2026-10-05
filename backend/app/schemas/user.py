"""User-related Pydantic schemas for request/response validation."""

from datetime import datetime
from typing import Optional
from pydantic import BaseModel, EmailStr, Field, field_validator
import re

from app.core.security import BCRYPT_MAX_PASSWORD_BYTES, PasswordTooLongError, password_byte_length

# Upper bound on characters. The real constraint is the bcrypt byte limit, which
# is enforced separately in `_validate_password_strength` because multi-byte
# characters can reach 72 bytes well before 72 characters.
PASSWORD_MAX_LENGTH = 128


def _validate_password_strength(v: str) -> str:
    """Shared password policy: composition rules plus the bcrypt byte limit."""
    if not re.search(r"[A-Z]", v):
        raise ValueError("Password must contain at least one uppercase letter")
    if not re.search(r"[a-z]", v):
        raise ValueError("Password must contain at least one lowercase letter")
    if not re.search(r"[0-9]", v):
        raise ValueError("Password must contain at least one digit")
    try:
        if password_byte_length(v) > BCRYPT_MAX_PASSWORD_BYTES:
            raise PasswordTooLongError(password_byte_length(v))
    except PasswordTooLongError as exc:
        raise ValueError(str(exc)) from exc
    return v


class UserRegister(BaseModel):
    """Schema for user registration request."""
    email: EmailStr
    username: str = Field(..., min_length=3, max_length=50)
    password: str = Field(..., min_length=8, max_length=PASSWORD_MAX_LENGTH)
    full_name: Optional[str] = Field(None, max_length=255)
    company_name: Optional[str] = Field(None, max_length=255)

    @field_validator("username")
    @classmethod
    def validate_username(cls, v: str) -> str:
        if not re.match(r"^[a-zA-Z0-9_-]+$", v):
            raise ValueError(
                "Username can only contain letters, numbers, underscores and hyphens"
            )
        return v.lower()

    @field_validator("password")
    @classmethod
    def validate_password(cls, v: str) -> str:
        return _validate_password_strength(v)


class UserLogin(BaseModel):
    """Schema for user login request."""
    email: EmailStr
    password: str


class UserResponse(BaseModel):
    """Schema for user data in API responses."""
    id: int
    email: str
    username: str
    full_name: Optional[str] = None
    company_name: Optional[str] = None
    is_active: bool
    created_at: datetime
    last_login_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class TokenResponse(BaseModel):
    """Schema for JWT token response."""
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    user: UserResponse


class UserUpdate(BaseModel):
    """Schema for updating user profile."""
    full_name: Optional[str] = Field(None, max_length=255)
    company_name: Optional[str] = Field(None, max_length=255)


class PasswordChange(BaseModel):
    """Schema for password change request."""
    current_password: str
    new_password: str = Field(..., min_length=8, max_length=PASSWORD_MAX_LENGTH)

    @field_validator("new_password")
    @classmethod
    def validate_password(cls, v: str) -> str:
        return _validate_password_strength(v)
