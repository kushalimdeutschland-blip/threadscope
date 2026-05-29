"""Intel document search (FTS5 via database layer)."""

from __future__ import annotations

import re
from typing import Any

import httpx

import database
from config import get_settings
from markupsafe import Markup, escape
from services.intel.ai import expand_intel_query
from services.intel.extract import extract_iocs
from services.intel.sanitize import sanitize_for_display


def highlight_snippet(body: str, query: str, *, max_len: int = 240) -> Markup:
    """Return a short escaped snippet with safe <mark> emphasis for display."""
    if not body:
        return Markup("")
    tokens = re.findall(r"[\w\-.]+", query, flags=re.UNICODE)
    lower = body.lower()
    pos = 0
    for tok in tokens:
        idx = lower.find(tok.lower())
        if idx >= 0:
            pos = max(0, idx - 60)
            break
    snippet = body[pos : pos + max_len]
    if pos > 0:
        snippet = "…" + snippet
    if pos + max_len < len(body):
        snippet = snippet + "…"
    escaped = str(escape(snippet))
    for tok in tokens[:8]:
        if len(tok) < 2:
            continue
        pattern = re.compile(re.escape(tok), re.IGNORECASE)
        escaped = pattern.sub(lambda m: f"<mark>{m.group(0)}</mark>", escaped)
    return Markup(escaped)


def _lookup_iocs(body: str, *, source: str, limit: int = 5) -> list[dict[str, str]]:
    rows = extract_iocs(body, source=source)
    out: list[dict[str, str]] = []
    for row in rows:
        if row.type not in ("email", "domain", "ipv4", "hash"):
            continue
        out.append({"value": row.value, "type": row.type})
        if len(out) >= limit:
            break
    return out


def _enrich_intel_rows(rows: list[dict], query: str) -> list[dict]:
    settings = get_settings()
    for row in rows:
        safe_body = sanitize_for_display(
            row.get("body") or "",
            max_len=settings.intel_list_body_chars,
        )
        row["body_display"] = safe_body
        row["snippet"] = highlight_snippet(
            safe_body,
            query,
            max_len=settings.intel_list_snippet_chars,
        )
        row["lookup_iocs"] = _lookup_iocs(safe_body, source=row.get("source") or "intel")
    return rows


async def search_intel(
    query: str,
    *,
    tag: str | None = None,
    limit: int = 50,
) -> list[dict]:
    results, _meta = await search_intel_with_ai(query, tag=tag, limit=limit)
    return results


async def search_intel_with_ai(
    query: str,
    *,
    tag: str | None = None,
    limit: int = 50,
    client: httpx.AsyncClient | None = None,
) -> tuple[list[dict], dict[str, Any] | None]:
    original = query.strip()
    fts_query = original
    expansion_meta: dict[str, Any] | None = None

    expanded = await expand_intel_query(original, client=client)
    if expanded:
        tokens = expanded.get("fts_tokens") or []
        if tokens:
            fts_query = " ".join(tokens)
        expansion_meta = {
            "original": original,
            "expanded": fts_query,
            "suggested_tags": expanded.get("tags") or [],
        }

    rows = await database.search_intel_items(fts_query, tag=tag, limit=limit)
    return _enrich_intel_rows(rows, original), expansion_meta
