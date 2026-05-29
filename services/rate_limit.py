"""
Client IP resolution and admin context for slowapi rate limiting.
"""

from __future__ import annotations

import ipaddress
from contextvars import ContextVar

from starlette.requests import Request

from config import Settings, get_settings

_admin_context: ContextVar[bool] = ContextVar("threatscope_admin_context", default=False)


def set_admin_context(is_admin: bool) -> object:
    """Set whether the current request is an authenticated admin (returns reset token)."""
    return _admin_context.set(is_admin)


def is_admin_context() -> bool:
    """True when the current request has an admin session (for slowapi exempt_when)."""
    return _admin_context.get()


def reset_admin_context(token: object) -> None:
    _admin_context.reset(token)


def _parse_ip(value: str | None) -> str | None:
    if not value:
        return None
    candidate = value.strip()
    if not candidate:
        return None
    # X-Forwarded-For may be "client, proxy1, proxy2"
    if "," in candidate:
        candidate = candidate.split(",", 1)[0].strip()
    try:
        ipaddress.ip_address(candidate)
    except ValueError:
        return None
    return candidate


def get_client_ip(request: Request, settings: Settings | None = None) -> str:
    """Return the client IP used for per-visitor rate limits."""
    cfg = settings or get_settings()
    if cfg.trust_proxy_headers:
        forwarded = request.headers.get("x-forwarded-for")
        real_ip = request.headers.get("x-real-ip")
        for raw in (forwarded, real_ip):
            parsed = _parse_ip(raw)
            if parsed:
                return parsed
    if request.client and request.client.host:
        return request.client.host
    return "127.0.0.1"
