from __future__ import annotations

import logging

from apps.api.config import get_settings

logger = logging.getLogger(__name__)


async def send_otp(phone_number: str, otp: str) -> None:
    settings = get_settings()

    if not settings.twilio_account_sid:
        logger.info("Twilio not configured — OTP for %s: %s", phone_number, otp)
        print(f"\n[SMS] OTP for {phone_number}: {otp}\n")
        return

    try:
        from twilio.rest import Client  # type: ignore[import-untyped]
        from twilio.base.exceptions import TwilioRestException  # type: ignore[import-untyped]
        from fastapi import HTTPException
        client = Client(settings.twilio_account_sid, settings.twilio_auth_token)
        client.messages.create(
            body=f"Your WebHound verification code is {otp}. It expires in 10 minutes.",
            from_=settings.twilio_from_number,
            to=phone_number,
        )
    except TwilioRestException as exc:
        logger.warning("Twilio error for %s: %s", phone_number, exc.msg)
        raise HTTPException(status_code=400, detail=f"SMS delivery failed: {exc.msg}")
    except Exception:
        logger.exception("Failed to send OTP SMS to %s", phone_number)
        raise
