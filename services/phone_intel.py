"""
Optional external phone number lookup (NumVerify). Disabled unless PHONE_LOOKUP_ENABLED=1.
"""

from __future__ import annotations

import httpx

from config import get_settings

settings = get_settings()

NUMVERIFY_URL = "http://apilayer.net/api/validate"


async def lookup_phone_external(client: httpx.AsyncClient, e164: str) -> dict:
    """
    Query configured phone API. Returns empty dict when disabled or on failure.
    Never affects risk_score — informational only.
    """
    if not settings.phone_lookup_enabled or not settings.phone_lookup_api_key:
        return {}

    provider = settings.phone_lookup_provider
    if provider == "numverify":
        return await _numverify(client, e164)
    return {}


async def _numverify(client: httpx.AsyncClient, e164: str) -> dict:
    number = e164.lstrip("+")
    try:
        resp = await client.get(
            NUMVERIFY_URL,
            params={
                "access_key": settings.phone_lookup_api_key,
                "number": number,
                "format": 1,
            },
            timeout=15.0,
        )
        resp.raise_for_status()
        data = resp.json()
        if not data.get("valid"):
            return {"valid": False, "provider": "numverify"}

        return {
            "valid": True,
            "provider": "numverify",
            "country_code": data.get("country_code"),
            "country_name": data.get("country_name"),
            "location": data.get("location"),
            "carrier": data.get("carrier"),
            "line_type": data.get("line_type"),
            "international_format": data.get("international_format"),
            "local_format": data.get("local_format"),
        }
    except (httpx.HTTPStatusError, httpx.RequestError, KeyError, TypeError):
        return {}
