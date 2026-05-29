"""Attach related narrative intel documents to indicator lookup payloads."""

from __future__ import annotations

from typing import Any

import database
from config import get_settings

_IOC_INTEL_TYPES = frozenset({"email", "domain", "hash", "ipv4", "ipv6"})


async def attach_intel_context(threat: dict[str, Any]) -> None:
    """Set threat.meta.intel_context when lookup intel context is enabled."""
    settings = get_settings()
    if not (settings.intel_ai_enabled and settings.intel_ai_lookup_context):
        return

    indicator_type = threat.get("type")
    value = threat.get("value")
    if not value or indicator_type not in _IOC_INTEL_TYPES:
        return

    items = await database.search_intel_items_for_ioc(
        value,
        indicator_type=indicator_type,
        limit=3,
    )
    if items:
        meta = threat.setdefault("meta", {})
        meta["intel_context"] = items
