"""
Local Ollama helpers for intel ingest summaries and FTS query expansion.
"""

from __future__ import annotations

import json
import re
import time
from typing import Any

import httpx

from config import get_settings
from services.ai_analyst import _call_ollama, _cache_lock

_intel_summary_cache: dict[str, tuple[str, float]] = {}
_intel_query_cache: dict[str, tuple[dict[str, Any], float]] = {}

_PROMPT_INTEL_SUMMARY = """You are a SOC analyst summarizing local threat intelligence documents.
Write exactly 1-2 plain sentences (no bullets) summarizing the threat narrative.
Do not invent facts not present in the text.

Title: {title}
Tags: {tags}
Body:
{body}
"""

_PROMPT_INTEL_EXPAND = """You help expand intel search queries for a security analyst FTS database.
Given the user query, output ONLY valid JSON with:
- "fts_tokens": array of 3-8 search terms (single words or short phrases, no quotes)
- "tags": array of 0-3 suggested tag filters from: rat, trojan, phishing, cve, ransomware, news, paste, leak

User query: {query}
"""


def _normalize_query_key(query: str) -> str:
    return " ".join(query.strip().lower().split())


async def _get_intel_cache(cache: dict, key: str) -> Any | None:
    async with _cache_lock:
        entry = cache.get(key)
        if entry is None:
            return None
        value, expires_at = entry
        if time.monotonic() >= expires_at:
            del cache[key]
            return None
        return value


async def _set_intel_cache(cache: dict, key: str, value: Any) -> None:
    ttl = get_settings().summary_cache_ttl
    async with _cache_lock:
        cache[key] = (value, time.monotonic() + ttl)


def _parse_expand_json(raw: str) -> dict[str, Any] | None:
    text = raw.strip()
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?\s*", "", text, flags=re.IGNORECASE)
        text = re.sub(r"\s*```\s*$", "", text)
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return None
    if not isinstance(data, dict):
        return None
    fts_tokens = data.get("fts_tokens")
    tags = data.get("tags")
    if not isinstance(fts_tokens, list):
        return None
    tokens_out: list[str] = []
    for tok in fts_tokens[:12]:
        if isinstance(tok, str) and tok.strip():
            tokens_out.append(tok.strip()[:64])
    tags_out: list[str] = []
    if isinstance(tags, list):
        for tag in tags[:6]:
            if isinstance(tag, str) and tag.strip():
                tags_out.append(tag.strip().lower()[:32])
    if not tokens_out:
        return None
    return {"fts_tokens": tokens_out, "tags": tags_out}


async def generate_intel_doc_summary(
    title: str,
    body: str,
    tags: list[str] | None = None,
    *,
    client: httpx.AsyncClient | None = None,
) -> str | None:
    """One-line ingest summary from sanitized title/body/tags."""
    settings = get_settings()
    if not (settings.intel_ai_enabled and settings.intel_ai_ingest_summary):
        return None

    import hashlib

    body_for_llm = (body or "")[: settings.intel_ai_max_body_chars]
    digest = hashlib.sha256(body_for_llm.encode("utf-8")).hexdigest()
    cache_key = f"intel_sum:{digest}"
    cached = await _get_intel_cache(_intel_summary_cache, cache_key)
    if isinstance(cached, str):
        return cached

    tag_str = ", ".join((tags or [])[:12])
    prompt = _PROMPT_INTEL_SUMMARY.format(
        title=(title or "")[:500],
        tags=tag_str,
        body=body_for_llm,
    )
    summary = await _call_ollama(prompt, client, max_response_chars=500)
    if summary:
        summary = re.sub(r"\s+", " ", summary).strip()
        await _set_intel_cache(_intel_summary_cache, cache_key, summary)
    return summary


async def expand_intel_query(
    query: str,
    *,
    client: httpx.AsyncClient | None = None,
) -> dict[str, Any] | None:
    """Expand user intel search into FTS tokens and optional tag hints."""
    settings = get_settings()
    if not (settings.intel_ai_enabled and settings.intel_ai_query_expand):
        return None

    normalized = _normalize_query_key(query)
    if len(normalized) < 2:
        return None

    cache_key = f"intel_q:{normalized}"
    cached = await _get_intel_cache(_intel_query_cache, cache_key)
    if isinstance(cached, dict):
        return cached

    prompt = _PROMPT_INTEL_EXPAND.format(query=query.strip()[:256])
    raw = await _call_ollama(prompt, client, max_response_chars=800)
    parsed = _parse_expand_json(raw) if raw else None
    if parsed:
        await _set_intel_cache(_intel_query_cache, cache_key, parsed)
    return parsed
