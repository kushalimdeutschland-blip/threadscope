"""Bulk IOC lookup tests."""

from __future__ import annotations

import asyncio

from services.bulk_lookup import bulk_lookup_indicators, parse_bulk_ioc_text


def test_parse_bulk_ioc_text_skips_comments():
    raw = "8.8.8.8\n# comment\nmalware.test\n"
    assert parse_bulk_ioc_text(raw) == ["8.8.8.8", "malware.test"]


def test_bulk_lookup_parses_lines():
    raw = "8.8.8.8\n# comment\nmalware.test\n"
    rows = asyncio.run(bulk_lookup_indicators(raw))
    assert len(rows) == 2
    assert rows[0]["type"] == "ipv4"
    assert rows[1]["type"] == "domain"


def test_bulk_lookup_invalid_line():
    rows = asyncio.run(bulk_lookup_indicators("not!!!an!!!indicator"))
    assert len(rows) == 1
    assert rows[0]["error"] is not None
