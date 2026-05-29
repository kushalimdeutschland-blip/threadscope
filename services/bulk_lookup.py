"""
Bulk indicator lookup for pentester IOC paste workflows.
"""

from __future__ import annotations

import re

from services.lookup import lookup_indicator
from services.validation import resolve_indicator

MAX_BULK_IOCS = 50
_LINE_RE = re.compile(r"[\s,;]+")


def parse_bulk_ioc_text(raw: str) -> list[str]:
    """
    Parse up to MAX_BULK_IOCS indicators from pasted or file text.
    One per line or comma/semicolon separated; # lines are comments.
    """
    tokens: list[str] = []
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        for part in _LINE_RE.split(line):
            part = part.strip()
            if part:
                tokens.append(part)
        if len(tokens) >= MAX_BULK_IOCS:
            break

    return tokens[:MAX_BULK_IOCS]


async def bulk_lookup_indicators(raw: str) -> list[dict]:
    """
    Parse up to 50 indicators (one per line or comma-separated) and lookup each.
    Returns list of row dicts for template rendering.
    """
    tokens = parse_bulk_ioc_text(raw)
    return await _bulk_lookup_tokens(tokens)


async def bulk_lookup_tokens(tokens: list[str]) -> list[dict]:
    """Lookup pre-parsed indicator tokens (e.g. from file import)."""
    return await _bulk_lookup_tokens(tokens[:MAX_BULK_IOCS])


async def _bulk_lookup_tokens(tokens: list[str]) -> list[dict]:
    rows: list[dict] = []

    for token in tokens:
        try:
            itype, normalized = resolve_indicator(token, "auto")
            threat = await lookup_indicator(normalized, itype)
            rows.append({
                "input": token,
                "value": normalized,
                "type": itype,
                "verdict": threat.get("verdict"),
                "risk_score": threat.get("risk_score"),
                "in_database": threat.get("in_database"),
                "error": None,
            })
        except ValueError as exc:
            rows.append({
                "input": token,
                "value": token,
                "type": None,
                "verdict": None,
                "risk_score": None,
                "in_database": False,
                "error": str(exc),
            })

    return rows
