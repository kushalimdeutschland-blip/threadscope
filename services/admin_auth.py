"""
Session-based admin authentication for homelab / public deployments.
"""

from __future__ import annotations

import hmac
import secrets
import time
from hashlib import sha256

import bcrypt
from starlette.requests import Request
from starlette.responses import Response

from config import Settings

ADMIN_SESSION_COOKIE = "threatscope_admin_session"
ADMIN_SESSION_MAX_AGE = 12 * 3600  # 12 hours
ADMIN_LOGIN_RATE_LIMIT = "5/minute"


def _sign_payload(secret: str, payload: str) -> str:
    return hmac.new(secret.encode(), payload.encode(), sha256).hexdigest()


def create_admin_session_token(secret: str) -> str:
    """Signed session token: issued_at.signature"""
    issued = str(int(time.time()))
    sig = _sign_payload(secret, issued)
    return f"{issued}.{sig}"


def verify_admin_session_token(secret: str, token: str | None) -> bool:
    if not token or "." not in token:
        return False
    issued, sig = token.rsplit(".", 1)
    if not issued.isdigit():
        return False
    expected = _sign_payload(secret, issued)
    if not hmac.compare_digest(sig, expected):
        return False
    age = int(time.time()) - int(issued)
    return 0 <= age <= ADMIN_SESSION_MAX_AGE


def admin_auth_configured(settings: Settings) -> bool:
    return bool(settings.admin_password or settings.admin_password_hash)


def verify_admin_password(settings: Settings, password: str) -> bool:
    if not password:
        return False
    if settings.admin_password_hash:
        try:
            return bcrypt.checkpw(
                password.encode("utf-8"),
                settings.admin_password_hash.encode("utf-8"),
            )
        except ValueError:
            return False
    if settings.admin_password:
        return hmac.compare_digest(password, settings.admin_password)
    return False


def is_admin_request(request: Request, settings: Settings, secret: str) -> bool:
    """Valid admin session, or dev-only THREATSCOPE_ADMIN bypass."""
    token = request.cookies.get(ADMIN_SESSION_COOKIE)
    if verify_admin_session_token(secret, token):
        return True
    if settings.is_production:
        return False
    if settings.threatscope_public:
        return False
    return settings.threatscope_admin


def set_admin_session_cookie(response: Response, secret: str, *, secure: bool) -> None:
    token = create_admin_session_token(secret)
    response.set_cookie(
        key=ADMIN_SESSION_COOKIE,
        value=token,
        httponly=True,
        samesite="strict",
        secure=secure,
        max_age=ADMIN_SESSION_MAX_AGE,
        path="/",
    )


def clear_admin_session_cookie(response: Response) -> None:
    response.delete_cookie(key=ADMIN_SESSION_COOKIE, path="/")
