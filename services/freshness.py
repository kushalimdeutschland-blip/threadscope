"""
Indicator freshness — TTL-based active/stale evaluation for feed-sourced intel.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Literal

FreshnessStatus = Literal["active", "stale", "none"]

# Days an indicator is considered actively listed per feed source.
SOURCE_TTL_DAYS: dict[str, int] = {
    "Blocklist.de": 90,
    "CINSscore": 90,
    "URLhaus": 60,
    "Phishing.Database": 30,
    "Feodo Tracker": 60,
    "MalwareBazaar": 60,
    "Spamhaus DROP": 90,
    "FireHOL Level1": 90,
    "OpenPhish": 30,
    "ThreatFox": 60,
    "CISA KEV": 180,
}

DEFAULT_TTL_DAYS = 90


def source_ttl_days(source: str) -> int:
    return SOURCE_TTL_DAYS.get(source, DEFAULT_TTL_DAYS)


def parse_iso_timestamp(ts: str) -> datetime:
    normalized = ts.replace("Z", "+00:00")
    dt = datetime.fromisoformat(normalized)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def days_since(ts: str) -> int:
    delta = datetime.now(timezone.utc) - parse_iso_timestamp(ts)
    return max(0, delta.days)


def format_last_seen(ts: str | None) -> str:
    if not ts:
        return "—"
    age = days_since(ts)
    if age == 0:
        return "today"
    if age == 1:
        return "1 day ago"
    return f"{age:,} days ago"


def is_source_active(last_seen: str, source: str) -> bool:
    return days_since(last_seen) <= source_ttl_days(source)


def evaluate_freshness(
    indicator: dict[str, Any] | None,
    sources: list[dict[str, Any]],
) -> dict[str, Any]:
    """
    Determine whether intel is actively listed in feeds or stale/recycled.

    Returns freshness_status, active_sources, latest_last_seen, last_seen_label.
    """
    if sources:
        active_sources = [s for s in sources if is_source_active(s["last_seen"], s["source"])]
        latest = max(sources, key=lambda s: s["last_seen"])
        return {
            "freshness_status": "active" if active_sources else "stale",
            "active_sources": active_sources,
            "all_sources": sources,
            "latest_last_seen": latest["last_seen"],
            "last_seen_label": format_last_seen(latest["last_seen"]),
            "days_since_seen": days_since(latest["last_seen"]),
        }

    if indicator and indicator.get("last_updated"):
        last_updated = indicator["last_updated"]
        age = days_since(last_updated)
        is_active = age <= DEFAULT_TTL_DAYS
        return {
            "freshness_status": "active" if is_active else "stale",
            "active_sources": [],
            "all_sources": [],
            "latest_last_seen": last_updated,
            "last_seen_label": format_last_seen(last_updated),
            "days_since_seen": age,
        }

    return {
        "freshness_status": "none",
        "active_sources": [],
        "all_sources": [],
        "latest_last_seen": None,
        "last_seen_label": "—",
        "days_since_seen": None,
    }
