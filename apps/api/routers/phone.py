from __future__ import annotations

import random
import re
import string
from datetime import datetime, timedelta, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.database import get_db
from apps.api.models.user import User
from apps.api.security import get_current_user
from apps.api.services.sms import send_otp

router = APIRouter(prefix="/auth/phone", tags=["phone"])

_DB = Annotated[AsyncSession, Depends(get_db)]
_CurrentUser = Annotated[User, Depends(get_current_user)]

_E164 = re.compile(r"^\+[1-9]\d{6,14}$")


def _generate_otp() -> str:
    return "".join(random.choices(string.digits, k=6))


class PhoneRequest(BaseModel):
    phone_number: str  # must be E.164 format


class OtpRequest(BaseModel):
    otp: str


@router.post("/add")
async def add_phone(data: PhoneRequest, current_user: _CurrentUser, db: _DB) -> dict:
    phone = data.phone_number.strip()
    if not _E164.match(phone):
        raise HTTPException(400, "Phone number must be in E.164 format (e.g. +15551234567)")

    otp = _generate_otp()
    expires = datetime.now(timezone.utc) + timedelta(minutes=10)

    current_user.phone_number = phone
    current_user.phone_verified = False
    current_user.phone_otp = otp
    current_user.phone_otp_expires_at = expires
    await db.commit()

    await send_otp(phone, otp)
    return {"message": "OTP sent"}


@router.post("/verify")
async def verify_phone(data: OtpRequest, current_user: _CurrentUser, db: _DB) -> dict:
    if not current_user.phone_otp:
        raise HTTPException(400, "No pending phone verification")

    now = datetime.now(timezone.utc)
    if current_user.phone_otp_expires_at and current_user.phone_otp_expires_at < now:
        raise HTTPException(400, "OTP has expired. Please request a new one.")

    if current_user.phone_otp != data.otp.strip():
        raise HTTPException(400, "Incorrect code. Please try again.")

    current_user.phone_verified = True
    current_user.phone_otp = None
    current_user.phone_otp_expires_at = None
    await db.commit()
    return {"message": "Phone number verified"}


@router.post("/resend")
async def resend_otp(current_user: _CurrentUser, db: _DB) -> dict:
    if not current_user.phone_number:
        raise HTTPException(400, "No phone number on file")
    if current_user.phone_verified:
        raise HTTPException(400, "Phone number is already verified")

    otp = _generate_otp()
    expires = datetime.now(timezone.utc) + timedelta(minutes=10)
    current_user.phone_otp = otp
    current_user.phone_otp_expires_at = expires
    await db.commit()

    await send_otp(current_user.phone_number, otp)
    return {"message": "OTP resent"}


@router.delete("/remove")
async def remove_phone(current_user: _CurrentUser, db: _DB) -> dict:
    current_user.phone_number = None
    current_user.phone_verified = False
    current_user.phone_otp = None
    current_user.phone_otp_expires_at = None
    await db.commit()
    return {"message": "Phone number removed"}
