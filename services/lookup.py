"""
Shared lookup logic — builds normalized threat payloads for UI and AI.
"""

from __future__ import annotations

from typing import Any

import database
from config import get_settings
from services.enrichment import enrich_indicator
from services.feed_credibility import apply_credibility
from services.freshness import evaluate_freshness
from services.email_intel import build_local_email_intel, lookup_email_external
from services.intel.context import attach_intel_context
from services.phone_intel import lookup_phone_external
from services.validation import (
    IndicatorType,
    email_domain,
    hash_algorithm,
    phone_display,
    phone_region_code,
    sanitize_tags,
)

settings = get_settings()


def verdict(score: int) -> str:
    if score >= 70:
        return "MALICIOUS"
    if score >= 20:
        return "SUSPICIOUS"
    return "CLEAN"


async def lookup_indicator(
    value: str,
    indicator_type: IndicatorType,
    *,
    http_client=None,
) -> dict[str, Any]:
    row = await database.get_indicator(value, indicator_type)
    sources = await database.get_indicator_sources(value, indicator_type) if row else []
    freshness = evaluate_freshness(row, sources)

    if row:
        meta = row.get("meta") or {}
        is_active = freshness["freshness_status"] == "active"
        stored_score = row["risk_score"]
        adjusted_score, credibility_adjusted = await apply_credibility(stored_score, sources)
        effective_score = adjusted_score if is_active else 0

        threat: dict[str, Any] = {
            "value": row["value"],
            "type": row["type"],
            "risk_score": effective_score,
            "stored_risk_score": stored_score,
            "tags": sanitize_tags(row["tags"]),
            "meta": meta,
            "last_updated": row["last_updated"],
            "in_database": True,
            "freshness_status": freshness["freshness_status"],
            "last_seen_label": freshness["last_seen_label"],
            "days_since_seen": freshness["days_since_seen"],
            "active_sources": freshness["active_sources"],
            "all_sources": freshness["all_sources"],
        }
        if credibility_adjusted:
            threat["credibility_adjusted"] = True

        if is_active:
            threat["verdict"] = verdict(effective_score)
        else:
            threat["verdict"] = "STALE"
    else:
        meta: dict[str, Any] = {}
        if indicator_type == "hash":
            meta["hash_type"] = hash_algorithm(value)
        if indicator_type == "phone":
            meta["phone_display"] = phone_display(value)
            meta["phone_region"] = phone_region_code(value)
        if indicator_type == "email":
            meta["email_domain"] = email_domain(value)
        threat = {
            "value": value,
            "type": indicator_type,
            "risk_score": 0,
            "stored_risk_score": 0,
            "tags": [],
            "meta": meta,
            "last_updated": None,
            "in_database": False,
            "freshness_status": "none",
            "last_seen_label": "—",
            "days_since_seen": None,
            "active_sources": [],
            "all_sources": [],
            "verdict": "UNKNOWN",
        }

    meta = threat.setdefault("meta", {})
    if indicator_type == "phone":
        meta.setdefault("phone_display", phone_display(value))
        meta.setdefault("phone_region", phone_region_code(value))
    if indicator_type == "email":
        meta.setdefault("email_domain", email_domain(value))

    enrichment = await enrich_indicator(
        value,
        indicator_type,
        tags=threat.get("tags") or [],
        meta=meta,
    )
    if enrichment:
        meta["enrichment"] = enrichment

    if indicator_type == "phone" and settings.phone_lookup_enabled and http_client is not None:
        phone_intel = await lookup_phone_external(http_client, value)
        if phone_intel:
            meta["phone_intel"] = phone_intel

    if indicator_type == "email":
        email_intel = build_local_email_intel(value)
        if settings.email_lookup_enabled and http_client is not None:
            external = await lookup_email_external(http_client, value)
            if external:
                email_intel = {**email_intel, **external}
        if email_intel:
            meta["email_intel"] = email_intel

    await attach_intel_context(threat)
    return threat
