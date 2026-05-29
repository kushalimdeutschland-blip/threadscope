"""
Email indicator intel — passive local DNS/MX checks by default.
Optional external API when EMAIL_LOOKUP_ENABLED=1 (sends address to third party).
"""

from __future__ import annotations

from typing import Any

import httpx

from config import get_settings
from services.enrichment import _resolve_domain_ips
from services.validation import email_domain

settings = get_settings()

_DISPOSABLE_DOMAINS = frozenset({
    "mailinator.com",
    "guerrillamail.com",
    "guerrillamailblock.com",
    "tempmail.com",
    "throwaway.email",
    "yopmail.com",
    "10minutemail.com",
    "trashmail.com",
    "getnada.com",
    "sharklasers.com",
})


def _lookup_mx_hosts(domain: str) -> list[str]:
    """MX lookup via dnspython when installed; otherwise empty (document in quick-start)."""
    try:
        import dns.resolver
    except ImportError:
        return []

    try:
        answers = dns.resolver.resolve(domain, "MX")
        hosts = [str(r.exchange).rstrip(".") for r in answers]
        return sorted(hosts)[:10]
    except Exception:
        return []


def build_local_email_intel(email: str) -> dict[str, Any]:
    """Passive local enrichment — no third-party calls."""
    domain = email_domain(email)
    mx_hosts = _lookup_mx_hosts(domain)
    resolved_ips = _resolve_domain_ips(domain)
    disposable = domain in _DISPOSABLE_DOMAINS or any(
        domain.endswith(f".{d}") for d in _DISPOSABLE_DOMAINS
    )
    intel: dict[str, Any] = {
        "domain": domain,
        "has_mx": bool(mx_hosts),
        "mx_hosts": mx_hosts,
        "disposable_hint": disposable,
        "provider": "local",
    }
    if resolved_ips:
        intel["resolved_ips"] = resolved_ips
    if not mx_hosts:
        intel["mx_note"] = (
            "MX records unavailable (install optional dnspython for MX lookup, "
            "or use dig on the domain)"
        )
    return intel


async def lookup_email_external(client: httpx.AsyncClient, email: str) -> dict[str, Any]:
    """
    Optional third-party email enrichment. Returns empty dict when disabled or on failure.
    Never affects risk_score.
    """
    if not settings.email_lookup_enabled or not settings.email_lookup_api_key:
        return {}

    provider = settings.email_lookup_provider
    if provider == "emailrep":
        return await _emailrep(client, email)
    return {}


async def _emailrep(client: httpx.AsyncClient, email: str) -> dict[str, Any]:
    try:
        resp = await client.get(
            f"https://emailrep.io/{email}",
            headers={"Key": settings.email_lookup_api_key},
            timeout=15.0,
        )
        resp.raise_for_status()
        data = resp.json()
        return {
            "provider": "emailrep",
            "reputation": data.get("reputation"),
            "suspicious": data.get("suspicious"),
            "references": data.get("references"),
            "details": data.get("details"),
        }
    except (httpx.HTTPStatusError, httpx.RequestError, KeyError, TypeError, ValueError):
        return {}
