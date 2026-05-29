"""IOC-only leak API adapters (email indicators only; no passwords)."""

from __future__ import annotations

import hashlib
import logging
from typing import Any

import httpx

import database
from config import get_settings
from services.intel.base import CollectorResult, IntelDocument
from services.intel.extract import extract_tags, parse_leak_row
from services.intel.sanitize import sanitize_meta

logger = logging.getLogger("threatscope.intel.leak")

DEHASHED_SEARCH = "https://api.dehashed.com/search"


class DehashedCollector:
    name = "leak"

    def __init__(self, config: dict[str, Any]) -> None:
        self._config = config

    async def collect(
        self,
        client: httpx.AsyncClient,
        *,
        if_changed: bool,
        dry_run: bool,
    ) -> CollectorResult:
        settings = get_settings()
        api_key = settings.dehashed_api_key
        email = settings.dehashed_api_email
        if not api_key:
            return CollectorResult(documents=[], indicators=[], error="DEHASHED_API_KEY not set")

        query = self._config.get("query") or "example.com"
        feed_key = "intel:leak:dehashed"
        force = not if_changed
        headers = {"Accept": "application/json"}
        auth = (email, api_key) if email else (api_key, "")

        try:
            resp = await client.get(
                DEHASHED_SEARCH,
                params={"query": query, "size": str(self._config.get("size", 50))},
                headers=headers,
                auth=auth,
                timeout=90.0,
            )
            resp.raise_for_status()
            raw = resp.content
        except httpx.HTTPError as exc:
            return CollectorResult(documents=[], indicators=[], error=str(exc))

        digest = hashlib.sha256(raw).hexdigest()
        stored = await database.get_feed_sync_state(feed_key)
        if not force and stored and stored.get("content_sha256") == digest:
            return CollectorResult(documents=[], indicators=[], skipped_fetch=True)

        try:
            data = resp.json()
        except ValueError:
            return CollectorResult(documents=[], indicators=[], error="invalid dehashed JSON")

        entries = data.get("entries") or data.get("results") or []
        source = "DeHashed"
        documents: list[IntelDocument] = []
        indicators = []

        for row in entries[:100]:
            if not isinstance(row, dict):
                continue
            ioc_rows = parse_leak_row(row, source=source)
            if not ioc_rows:
                continue
            email_val = ioc_rows[0].value
            source_id = hashlib.sha256(f"{email_val}:{query}".encode()).hexdigest()[:32]
            title = f"Breach IOC: {email_val}"
            body = f"Email observed in breach context (query={query}). Password not stored."
            doc_tags = extract_tags(body, ["leak", "breach-leak"])
            documents.append(
                IntelDocument(
                    source=source,
                    source_id=source_id,
                    title=title,
                    body=body,
                    url=None,
                    published_at=None,
                    tags=doc_tags,
                    meta=sanitize_meta(
                        {
                            "query": query,
                            "database": row.get("database"),
                            "extractor": "leak_ioc_only",
                        }
                    ),
                )
            )
            indicators.extend(ioc_rows)

        if not dry_run:
            await database.upsert_feed_sync_state(
                feed_key, content_sha256=digest, checked=True
            )
            await database.mark_feed_ingested(feed_key, len(documents))

        return CollectorResult(
            documents=documents,
            indicators=indicators,
            fetched=len(documents),
        )
