"""Tests for passive indicator enrichment."""

from __future__ import annotations

import asyncio

from services.enrichment import _actor_hints, enrich_indicator


def test_enrich_ipv4_without_geoip_db() -> None:
    result = asyncio.run(enrich_indicator(
        "8.8.8.8",
        "ipv4",
        tags=["DNS"],
        meta={"malware_family": "TestFamily"},
    ))
    assert "actor_hints" in result
    assert "TestFamily" in result["actor_hints"]


def test_enrich_domain_resolves_or_empty() -> None:
    result = asyncio.run(enrich_indicator("example.com", "domain"))
    assert isinstance(result, dict)


def test_actor_hints_from_tags() -> None:
    hints = _actor_hints(["Emotet", "botnet"], {})
    assert "Emotet" in hints


def test_enrich_email_includes_domain() -> None:
    result = asyncio.run(enrich_indicator("user@example.com", "email"))
    assert result.get("email_domain") == "example.com"
