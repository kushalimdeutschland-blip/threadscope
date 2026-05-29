"""
Double-submit CSRF protection for HTMX form POSTs.
"""

from __future__ import annotations

import hmac
import secrets
from hashlib import sha256

CSRF_COOKIE = "ts_csrf"
CSRF_FORM_FIELD = "csrf_token"
TOKEN_BYTES = 32


def generate_csrf_token(secret: str) -> str:
    """Create a random token bound to the app secret."""
    nonce = secrets.token_urlsafe(TOKEN_BYTES)
    sig = hmac.new(secret.encode(), nonce.encode(), sha256).hexdigest()
    return f"{nonce}.{sig}"


def validate_csrf_token(secret: str, token: str | None) -> bool:
    if not token or "." not in token:
        return False
    nonce, sig = token.rsplit(".", 1)
    if not nonce or not sig:
        return False
    expected = hmac.new(secret.encode(), nonce.encode(), sha256).hexdigest()
    return hmac.compare_digest(sig, expected)


def csrf_tokens_match(cookie_token: str | None, form_token: str | None) -> bool:
    if not cookie_token or not form_token:
        return False
    return hmac.compare_digest(cookie_token, form_token)
