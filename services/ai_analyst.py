"""
Local LLM analyst via Ollama — generates executive summaries without external APIs.
"""

from __future__ import annotations

import asyncio
import json
import re
import time
from typing import Any
from urllib.parse import urlparse

import httpx

from config import get_settings

settings = get_settings()

_PROMPT_INDICATOR = """You are a senior SOC analyst. Review the following JSON threat data and provide:
1) Exactly 2 sentences executive summary of the risk.
2) Then on new lines, three short bullet lines prefixed with "ACTION:" describing what a pentester should do next (e.g. block, investigate on isolated VM, passive DNS).

Do not include other conversational text.

If verdict is "UNKNOWN" or in_database is false, state clearly that the indicator was not found in local OSINT feeds — this is not a confirmation of safety. Do not call it clean or benign.

If freshness_status is "stale", note that the indicator was previously flagged but has not been seen in active feeds recently — it may have been cleaned, seized, or reassigned. Do not treat stale intel as currently malicious.

If meta.intel_context is present, it lists local narrative intel documents (RSS/paste summaries) that mention this indicator. Reference them for context only — they are analyst-curated narrative, not confirmed malicious verdicts.

Threat data:
{data}
"""

_PROMPT_FILE = """You are a senior reverse engineer and SOC lead. Review the following structured file analysis metadata (static parsers, YARA, local hash intelligence, optional sandbox). Provide:
1) Exactly 2 sentences for a corporate manager explaining malicious intent and recommended action.
2) Then three short bullet lines prefixed with "ACTION:" for pentester next steps (e.g. sandbox APK, copy sample to Ghidra VM, block hash).

Do not include other conversational filler.

Focus on: YARA rule names, suspicious PE/APK markers, hash database hits, and dynamic sandbox behaviors if present. Prefer signature/intel findings over pure heuristics when both exist.

If verdict is "UNKNOWN", state clearly that the file was not found in local hash feeds and had no YARA signature matches — this is not confirmation of safety.

If hash DB shows no match, state that absence of feed data is not proof the file is safe.

If analysis_mode includes dynamic results, incorporate behavioral IOCs.

File analysis data:
{data}
"""

_PROMPT_FILE_RE = """You are a senior malware reverse engineer. Review the file analysis JSON and output ONLY a JSON array of 3 to 5 reverse-engineering workflow steps tailored to THIS sample.

Each element must be an object with exactly two string fields: "title" (short step name) and "detail" (one sentence, specific to YARA hits, permissions, embedded URLs/IPs, file kind, and verdict).

Focus on the most important findings first. Do not include shell commands. Do not wrap in markdown. Output valid JSON only.

File analysis data:
{data}
"""

_ALLOWED_OLLAMA_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})

_ollama_semaphore = asyncio.Semaphore(settings.ollama_max_concurrent)
_summary_cache: dict[str, tuple[str, float]] = {}
_re_guidance_cache: dict[str, tuple[list[dict[str, str]], float]] = {}
_cache_lock = asyncio.Lock()


def _assert_safe_ollama_url(url: str) -> str:
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError("Invalid Ollama URL scheme")
    host = (parsed.hostname or "").lower()
    if host not in _ALLOWED_OLLAMA_HOSTS:
        raise ValueError("Ollama URL must point to localhost only")
    return url


OLLAMA_URL = _assert_safe_ollama_url(settings.ollama_url)
OLLAMA_MODEL = settings.ollama_model


def _cache_key(threat_data: dict) -> str:
    meta = threat_data.get("meta") or {}
    yara_matches = meta.get("yara_matches") or []
    yara_rules = [m.get("rule") for m in yara_matches if isinstance(m, dict)]
    return json.dumps(
        {
            "value": threat_data.get("value"),
            "type": threat_data.get("type"),
            "verdict": threat_data.get("verdict"),
            "risk_score": threat_data.get("risk_score"),
            "freshness_status": threat_data.get("freshness_status"),
            "last_updated": threat_data.get("last_updated"),
            "last_seen_label": threat_data.get("last_seen_label"),
            "analysis_mode": meta.get("analysis_mode"),
            "sandbox_backend": meta.get("sandbox_backend"),
            "yara_match_count": meta.get("yara_match_count"),
            "yara_rules": yara_rules[:8],
            "enrichment": (threat_data.get("meta") or {}).get("enrichment"),
            "phone_intel": (threat_data.get("meta") or {}).get("phone_intel"),
            "email_intel": (threat_data.get("meta") or {}).get("email_intel"),
            "lab_scan": (threat_data.get("meta") or {}).get("lab_scan"),
            "intel_context_ids": [
                c.get("id")
                for c in ((threat_data.get("meta") or {}).get("intel_context") or [])
                if isinstance(c, dict) and c.get("id") is not None
            ],
        },
        sort_keys=True,
    )


def _prompt_for_threat(threat_data: dict, payload: dict) -> str:
    if threat_data.get("type") == "file":
        return _PROMPT_FILE.format(data=json.dumps(payload, indent=2))
    return _PROMPT_INDICATOR.format(data=json.dumps(payload, indent=2))


async def _get_cached_summary(key: str) -> str | None:
    async with _cache_lock:
        entry = _summary_cache.get(key)
        if entry is None:
            return None
        summary, expires_at = entry
        if time.monotonic() >= expires_at:
            del _summary_cache[key]
            return None
        return summary


async def _set_cached_summary(key: str, summary: str) -> None:
    async with _cache_lock:
        _summary_cache[key] = (summary, time.monotonic() + settings.summary_cache_ttl)


def _file_payload_for_llm(threat_data: dict) -> dict[str, Any]:
    meta = threat_data.get("meta") or {}
    meta_out = {
        k: v
        for k, v in meta.items()
        if k
        in (
            "analysis_mode",
            "sandbox_backend",
            "yara_status",
            "yara_match_count",
            "yara_matches",
            "yara_rules_loaded",
            "file_kind",
            "size_bytes",
            "package",
            "permissions",
            "embedded_urls",
            "embedded_ips",
            "phone_numbers",
        )
    }
    return {
        "value": threat_data.get("value"),
        "type": threat_data.get("type"),
        "file_kind": threat_data.get("file_kind"),
        "risk_score": threat_data.get("risk_score"),
        "tags": threat_data.get("tags", []),
        "verdict": threat_data.get("verdict"),
        "in_database": threat_data.get("in_database"),
        "hash_db_match": threat_data.get("hash_db_match"),
        "hashes": threat_data.get("hashes"),
        "findings": (threat_data.get("findings") or [])[:12],
        "dynamic": threat_data.get("dynamic"),
        "meta": meta_out,
    }


def _parse_re_guidance_json(raw: str) -> list[dict[str, str]] | None:
    text = raw.strip()
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?\s*", "", text, flags=re.IGNORECASE)
        text = re.sub(r"\s*```\s*$", "", text)
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return None
    if not isinstance(data, list):
        return None
    steps: list[dict[str, str]] = []
    for item in data[:6]:
        if not isinstance(item, dict):
            continue
        title = item.get("title")
        detail = item.get("detail")
        if isinstance(title, str) and isinstance(detail, str) and title.strip() and detail.strip():
            steps.append({"title": title.strip()[:120], "detail": detail.strip()[:500]})
    return steps if steps else None


async def _get_cached_re_guidance(key: str) -> list[dict[str, str]] | None:
    async with _cache_lock:
        entry = _re_guidance_cache.get(key)
        if entry is None:
            return None
        steps, expires_at = entry
        if time.monotonic() >= expires_at:
            del _re_guidance_cache[key]
            return None
        return steps


async def _set_cached_re_guidance(key: str, steps: list[dict[str, str]]) -> None:
    async with _cache_lock:
        _re_guidance_cache[key] = (steps, time.monotonic() + settings.summary_cache_ttl)


async def _call_ollama(
    prompt: str,
    client: httpx.AsyncClient | None = None,
    *,
    max_response_chars: int = 2000,
) -> str | None:
    """POST to local Ollama; returns trimmed response text or None on failure."""
    payload = {"model": OLLAMA_MODEL, "prompt": prompt, "stream": False}
    owns_client = client is None
    if owns_client:
        client = httpx.AsyncClient(timeout=settings.ollama_timeout)

    try:
        async with _ollama_semaphore:
            resp = await client.post(OLLAMA_URL, json=payload)
        resp.raise_for_status()
        body = resp.json()
        raw = (body.get("response") or "").strip()
        if not raw:
            return None
        return raw[:max_response_chars]
    except (httpx.RequestError, httpx.HTTPStatusError, KeyError, ValueError):
        return None
    finally:
        if owns_client:
            await client.aclose()


async def generate_file_re_guidance(
    threat_data: dict,
    client: httpx.AsyncClient | None = None,
) -> list[dict[str, str]] | None:
    """Return finding-specific RE workflow steps, or None to use static fallback."""
    if threat_data.get("type") != "file":
        return None

    cache_key = "re:" + _cache_key(threat_data)
    cached = await _get_cached_re_guidance(cache_key)
    if cached is not None:
        return cached

    payload = _file_payload_for_llm(threat_data)
    prompt = _PROMPT_FILE_RE.format(data=json.dumps(payload, indent=2))
    raw = await _call_ollama(prompt, client, max_response_chars=4000)
    steps = _parse_re_guidance_json(raw) if raw else None
    if steps:
        await _set_cached_re_guidance(cache_key, steps)
    return steps


async def generate_threat_summary(threat_data: dict, client: httpx.AsyncClient | None = None) -> str:
    cache_key = _cache_key(threat_data)
    cached = await _get_cached_summary(cache_key)
    if cached is not None:
        return cached

    if threat_data.get("type") == "file":
        safe_payload = _file_payload_for_llm(threat_data)
        safe_payload["stored_risk_score"] = threat_data.get("stored_risk_score")
    else:
        meta = threat_data.get("meta") or {}
        meta_out = {k: v for k, v in meta.items() if k not in ("hashes",)}
        safe_payload = {
            "value": threat_data.get("value"),
            "type": threat_data.get("type"),
            "file_kind": threat_data.get("file_kind"),
            "risk_score": threat_data.get("risk_score"),
            "stored_risk_score": threat_data.get("stored_risk_score"),
            "tags": threat_data.get("tags", []),
            "verdict": threat_data.get("verdict"),
            "freshness_status": threat_data.get("freshness_status"),
            "last_seen_label": threat_data.get("last_seen_label"),
            "in_database": threat_data.get("in_database"),
            "hash_db_match": threat_data.get("hash_db_match"),
            "hashes": threat_data.get("hashes"),
            "findings": (threat_data.get("findings") or [])[:12],
            "dynamic": threat_data.get("dynamic"),
            "meta": meta_out,
            "enrichment": meta_out.get("enrichment"),
            "phone_intel": meta_out.get("phone_intel"),
            "email_intel": meta_out.get("email_intel"),
            "lab_scan": meta_out.get("lab_scan"),
        }
    prompt = _prompt_for_threat(threat_data, safe_payload)
    summary = await _call_ollama(prompt, client, max_response_chars=2000)
    if summary:
        await _set_cached_summary(cache_key, summary)
        return summary
    if summary is None:
        return (
            "AI analyst unavailable (ensure Ollama is running and "
            f"`ollama pull {OLLAMA_MODEL}` has been executed). "
            "Assessment below is based on local database intelligence only."
        )
    return "Local LLM returned an empty summary. Review the raw indicators below."
