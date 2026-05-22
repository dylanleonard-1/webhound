from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, field_validator


_VALID_USE_CASES = {
    "developer",
    "security_engineer",
    "founder",
    "agency",
    "it_team",
    "other",
}


class UserCreate(BaseModel):
    email: str
    password: str
    full_name: str | None = None
    company_name: str | None = None
    use_case: str | None = None

    @field_validator("email")
    @classmethod
    def normalise_email(cls, v: str) -> str:
        return v.strip().lower()

    @field_validator("password")
    @classmethod
    def password_min_length(cls, v: str) -> str:
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters")
        return v

    @field_validator("full_name", "company_name")
    @classmethod
    def strip_optional(cls, v: str | None) -> str | None:
        if v is None:
            return v
        v = v.strip()
        return v or None

    @field_validator("use_case")
    @classmethod
    def validate_use_case(cls, v: str | None) -> str | None:
        if v is None or v == "":
            return None
        v = v.strip().lower()
        if v not in _VALID_USE_CASES:
            raise ValueError(f"use_case must be one of: {sorted(_VALID_USE_CASES)}")
        return v


class UserLogin(BaseModel):
    email: str
    password: str

    @field_validator("email")
    @classmethod
    def normalise_email(cls, v: str) -> str:
        return v.strip().lower()


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


class LoginChallengeResponse(BaseModel):
    # Returned after the password step succeeds. Holds the opaque challenge
    # token the client must echo back along with the 6-digit code from email.
    challenge_token: str
    email: str          # masked, e.g. d***l@gmail.com
    expires_in: int     # seconds


class LoginVerifyRequest(BaseModel):
    challenge_token: str
    code: str

    @field_validator("code")
    @classmethod
    def code_format(cls, v: str) -> str:
        v = v.strip()
        if not v.isdigit() or len(v) != 6:
            raise ValueError("Code must be 6 digits")
        return v


class LoginResendRequest(BaseModel):
    challenge_token: str


class PasswordResetRequest(BaseModel):
    email: str

    @field_validator("email")
    @classmethod
    def normalise_email(cls, v: str) -> str:
        return v.strip().lower()


class PasswordResetConfirm(BaseModel):
    token: str
    new_password: str

    @field_validator("new_password")
    @classmethod
    def password_min_length(cls, v: str) -> str:
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters")
        return v


class UserResponse(BaseModel):
    id: uuid.UUID
    email: str
    is_active: bool
    is_admin: bool
    email_verified: bool
    phone_number: str | None = None
    phone_verified: bool
    full_name: str | None = None
    company_name: str | None = None
    use_case: str | None = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)
