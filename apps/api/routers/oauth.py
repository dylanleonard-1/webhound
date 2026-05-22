from __future__ import annotations

import asyncio
import json
import logging
import time
from typing import Annotated
from urllib.parse import urlencode

import httpx
import jwt as pyjwt
from fastapi import APIRouter, Depends, Form, HTTPException
from fastapi.responses import RedirectResponse
from jwt import PyJWKClient
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.config import get_settings
from apps.api.database import get_db
from apps.api.security import create_access_token
from apps.api.services.oauth import OAuthUserInfo, find_or_create_oauth_user

router = APIRouter(prefix="/auth/oauth", tags=["oauth"])

_DB = Annotated[AsyncSession, Depends(get_db)]

_GOOGLE_AUTH  = "https://accounts.google.com/o/oauth2/v2/auth"
_GOOGLE_TOKEN = "https://oauth2.googleapis.com/token"
_GOOGLE_USER  = "https://www.googleapis.com/oauth2/v3/userinfo"

_GITHUB_AUTH   = "https://github.com/login/oauth/authorize"
_GITHUB_TOKEN  = "https://github.com/login/oauth/access_token"
_GITHUB_USER   = "https://api.github.com/user"
_GITHUB_EMAILS = "https://api.github.com/user/emails"

_APPLE_AUTH  = "https://appleid.apple.com/auth/authorize"
_APPLE_TOKEN = "https://appleid.apple.com/auth/token"
_APPLE_JWKS  = "https://appleid.apple.com/auth/keys"
_APPLE_ISSUER = "https://appleid.apple.com"

logger = logging.getLogger(__name__)


def _error_redirect(frontend_url: str, reason: str) -> RedirectResponse:
    return RedirectResponse(f"{frontend_url}/auth/callback?error={reason}")


def _apple_client_secret(settings) -> str:  # type: ignore[no-untyped-def]
    # Per Apple docs, client_secret JWT has max lifetime of 6 months. Use 5.
    now = int(time.time())
    return pyjwt.encode(
        {
            "iss": settings.apple_team_id,
            "iat": now,
            "exp": now + 86400 * 150,
            "aud": _APPLE_ISSUER,
            "sub": settings.apple_client_id,
        },
        settings.apple_private_key,
        algorithm="ES256",
        headers={"kid": settings.apple_key_id},
    )


# JWKS client cache — Apple rotates keys infrequently, PyJWKClient caches per
# instance. Module-level reuse avoids refetching on every callback.
_apple_jwks_client: PyJWKClient | None = None


def _get_apple_jwks_client() -> PyJWKClient:
    global _apple_jwks_client
    if _apple_jwks_client is None:
        _apple_jwks_client = PyJWKClient(_APPLE_JWKS, cache_keys=True)
    return _apple_jwks_client


def _verify_apple_id_token(token: str, client_id: str) -> dict:
    # PyJWKClient uses urllib (sync). Wrap to keep the async event loop free.
    jwks = _get_apple_jwks_client()
    signing_key = jwks.get_signing_key_from_jwt(token)
    return pyjwt.decode(
        token,
        signing_key.key,
        algorithms=["RS256"],
        audience=client_id,
        issuer=_APPLE_ISSUER,
    )


# ── Google ────────────────────────────────────────────────────────────────────

@router.get("/google/authorize")
async def google_authorize() -> RedirectResponse:
    settings = get_settings()
    if not settings.google_client_id:
        raise HTTPException(400, "Google OAuth is not configured")
    params = {
        "client_id": settings.google_client_id,
        "redirect_uri": f"{settings.api_base_url}/auth/oauth/google/callback",
        "response_type": "code",
        "scope": "openid email profile",
        "access_type": "online",
    }
    return RedirectResponse(f"{_GOOGLE_AUTH}?{urlencode(params)}")


@router.get("/google/callback")
async def google_callback(code: str, db: _DB) -> RedirectResponse:
    settings = get_settings()
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            tok = await client.post(_GOOGLE_TOKEN, data={
                "client_id": settings.google_client_id,
                "client_secret": settings.google_client_secret,
                "code": code,
                "grant_type": "authorization_code",
                "redirect_uri": f"{settings.api_base_url}/auth/oauth/google/callback",
            })
            tok.raise_for_status()
            access_token = tok.json()["access_token"]

            u_res = await client.get(
                _GOOGLE_USER, headers={"Authorization": f"Bearer {access_token}"}
            )
            u_res.raise_for_status()
            u = u_res.json()
    except Exception:
        return _error_redirect(settings.frontend_url, "google_auth_failed")

    info = OAuthUserInfo(
        provider="google",
        provider_id=u["sub"],
        email=u.get("email"),
        name=u.get("name"),
        avatar_url=u.get("picture"),
    )
    user = await find_or_create_oauth_user(db, info)
    await db.commit()
    jwt_token = create_access_token(user.id)
    return RedirectResponse(f"{settings.frontend_url}/auth/callback?token={jwt_token}")


# ── GitHub ────────────────────────────────────────────────────────────────────

@router.get("/github/authorize")
async def github_authorize() -> RedirectResponse:
    settings = get_settings()
    if not settings.github_client_id:
        raise HTTPException(400, "GitHub OAuth is not configured")
    params = {
        "client_id": settings.github_client_id,
        "redirect_uri": f"{settings.api_base_url}/auth/oauth/github/callback",
        "scope": "user:email",
    }
    return RedirectResponse(f"{_GITHUB_AUTH}?{urlencode(params)}")


@router.get("/github/callback")
async def github_callback(code: str, db: _DB) -> RedirectResponse:
    settings = get_settings()
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            tok = await client.post(
                _GITHUB_TOKEN,
                data={
                    "client_id": settings.github_client_id,
                    "client_secret": settings.github_client_secret,
                    "code": code,
                    "redirect_uri": f"{settings.api_base_url}/auth/oauth/github/callback",
                },
                headers={"Accept": "application/json"},
            )
            tok.raise_for_status()
            access_token = tok.json().get("access_token", "")

            gh_headers = {
                "Authorization": f"Bearer {access_token}",
                "Accept": "application/vnd.github+json",
            }
            u_res = await client.get(_GITHUB_USER, headers=gh_headers)
            u_res.raise_for_status()
            u = u_res.json()

            email: str | None = u.get("email")
            if not email:
                e_res = await client.get(_GITHUB_EMAILS, headers=gh_headers)
                if e_res.is_success:
                    for entry in e_res.json():
                        if entry.get("primary") and entry.get("verified"):
                            email = entry["email"]
                            break
    except Exception:
        return _error_redirect(settings.frontend_url, "github_auth_failed")

    info = OAuthUserInfo(
        provider="github",
        provider_id=str(u["id"]),
        email=email,
        name=u.get("name") or u.get("login"),
        avatar_url=u.get("avatar_url"),
    )
    user = await find_or_create_oauth_user(db, info)
    await db.commit()
    jwt_token = create_access_token(user.id)
    return RedirectResponse(f"{settings.frontend_url}/auth/callback?token={jwt_token}")


# ── Apple ─────────────────────────────────────────────────────────────────────

@router.get("/apple/authorize")
async def apple_authorize() -> RedirectResponse:
    settings = get_settings()
    if not settings.apple_client_id:
        raise HTTPException(400, "Apple OAuth is not configured")
    params = {
        "client_id": settings.apple_client_id,
        "redirect_uri": f"{settings.api_base_url}/auth/oauth/apple/callback",
        "response_type": "code",
        "scope": "name email",
        "response_mode": "form_post",
    }
    return RedirectResponse(f"{_APPLE_AUTH}?{urlencode(params)}")


@router.post("/apple/callback")
async def apple_callback(
    db: _DB,
    code: str = Form(...),
    id_token: str | None = Form(None),
    user: str | None = Form(None),
) -> RedirectResponse:
    # Apple posts back to this endpoint via form_post; the `user` payload (name +
    # email) is only present on the FIRST authentication. Subsequent sign-ins
    # only carry `code` and `id_token`. We always exchange `code` with Apple's
    # token endpoint and verify the returned id_token signature.
    settings = get_settings()
    try:
        user_data = json.loads(user) if user else {}
        name_data = user_data.get("name", {})
        email_from_form: str | None = user_data.get("email")

        async with httpx.AsyncClient(timeout=15) as client:
            tok = await client.post(_APPLE_TOKEN, data={
                "client_id": settings.apple_client_id,
                "client_secret": _apple_client_secret(settings),
                "code": code,
                "grant_type": "authorization_code",
                "redirect_uri": f"{settings.api_base_url}/auth/oauth/apple/callback",
            })
            tok.raise_for_status()
            verified_id_token = tok.json().get("id_token", "")

        if not verified_id_token:
            logger.warning("Apple token exchange returned no id_token")
            return _error_redirect(settings.frontend_url, "apple_no_id_token")

        # Verify signature, issuer, audience, expiration. JWKS fetch is sync;
        # run in a worker thread so we don't block the event loop.
        id_payload = await asyncio.to_thread(
            _verify_apple_id_token, verified_id_token, settings.apple_client_id
        )

        provider_id: str | None = id_payload.get("sub")
        if not provider_id:
            return _error_redirect(settings.frontend_url, "apple_no_subject")

        first = name_data.get("firstName", "")
        last = name_data.get("lastName", "")
        full_name = f"{first} {last}".strip() or None
        email = email_from_form or id_payload.get("email")

    except httpx.HTTPStatusError as e:
        logger.warning("Apple token exchange failed: %s — %s", e.response.status_code, e.response.text[:200])
        return _error_redirect(settings.frontend_url, "apple_auth_failed")
    except pyjwt.InvalidTokenError as e:
        logger.warning("Apple id_token verification failed: %s", e)
        return _error_redirect(settings.frontend_url, "apple_invalid_token")
    except Exception as e:
        logger.exception("Apple OAuth callback unexpected error: %s", e)
        return _error_redirect(settings.frontend_url, "apple_auth_failed")

    info = OAuthUserInfo(
        provider="apple",
        provider_id=provider_id,
        email=email,
        name=full_name,
        avatar_url=None,
    )
    user_obj = await find_or_create_oauth_user(db, info)
    await db.commit()
    jwt_token = create_access_token(user_obj.id)
    return RedirectResponse(f"{settings.frontend_url}/auth/callback?token={jwt_token}")
