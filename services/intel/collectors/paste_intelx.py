"""Pastebin and Intelligence X paste/search APIs."""

from __future__ import annotations

import hashlib
import logging
from typing import Any

import httpx

import database
from config import get_settings
from services.intel.base import CollectorResult, IntelDocument
from services.intel.extract import extract_tags

logger = logging.getLogger("threatscope.intel.paste")

PASTEBIN_RECENT_URL = "https://scrape.pastebin.com/api_scraping.php"


class PastebinCollector:
    name = "paste"

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
        api_key = settings.pastebin_api_key
        if not api_key:
            return CollectorResult(documents=[], indicators=[], error="PASTEBIN_API_KEY not set")

        feed_key = "intel:paste"
        force = not if_changed
        headers = {"User-Agent": "ThreatScope/2.5 intel-ingest"}
        params = {"limit": str(self._config.get("limit", 20))}
        dev_key = {"api_dev_key": api_key}

        try:
            resp = await client.get(
                PASTEBIN_RECENT_URL,
                params={**params, **dev_key},
                headers=headers,
                timeout=60.0,
            )
            resp.raise_for_status()
            raw = resp.content
        except httpx.HTTPError as exc:
            return CollectorResult(documents=[], indicators=[], error=str(exc))

        digest = hashlib.sha256(raw).hexdigest()
        stored = await database.get_feed_sync_state(feed_key)
        if not force and stored and stored.get("content_sha256") == digest:
            return CollectorResult(documents=[], indicators=[], skipped_fetch=True)

        if not dry_run:
            await database.upsert_feed_sync_state(
                feed_key, content_sha256=digest, checked=True
            )

        try:
            entries = resp.json()
        except ValueError:
            return CollectorResult(documents=[], indicators=[], error="invalid pastebin JSON")

        if not isinstance(entries, list):
            return CollectorResult(documents=[], indicators=[], error="unexpected pastebin response")

        documents: list[IntelDocument] = []
        max_body = settings.intel_max_body_bytes

        for entry in entries[:50]:
            if not isinstance(entry, dict):
                continue
            paste_key = entry.get("key") or entry.get("full_url", "")
            if not paste_key:
                continue
            source_id = str(paste_key)[:512]
            title = (entry.get("title") or f"Paste {source_id}")[:500]
            scrape_url = entry.get("scrape_url") or entry.get("full_url")
            body = ""
            if scrape_url:
                try:
                    paste_resp = await client.get(scrape_url, headers=headers, timeout=45.0)
                    paste_resp.raise_for_status()
                    body = paste_resp.text[:max_body]
                except httpx.HTTPError as exc:
                    logger.warning("paste fetch %s: %s", source_id, exc)
                    continue

            if not body:
                continue

            source = "Pastebin"
            doc_tags = extract_tags(body, ["paste"])
            documents.append(
                IntelDocument(
                    source=source,
                    source_id=source_id,
                    title=title,
                    body=body,
                    url=entry.get("full_url"),
                    published_at=entry.get("date"),
                    tags=doc_tags,
                    meta={"paste_key": source_id},
                )
            )
        if not dry_run:
            await database.mark_feed_ingested(feed_key, len(documents))

        return CollectorResult(
            documents=documents,
            indicators=[],
            fetched=len(documents),
        )


class IntelXCollector:
    name = "intelx"

    INTELX_SEARCH = "https://2.intelx.io/intelligent/search"

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
        api_key = settings.intelx_api_key
        if not api_key:
            return CollectorResult(documents=[], indicators=[], error="INTELX_API_KEY not set")

        queries = self._config.get("queries") or ["malware", "ransomware"]
        headers = {"x-key": api_key, "User-Agent": "ThreatScope/2.5 intel-ingest"}
        documents: list[IntelDocument] = []
        fetched = 0
        feed_key = "intel:intelx"
        force = not if_changed

        aggregate = hashlib.sha256()
        for query in queries[:5]:
            try:
                resp = await client.post(
                    self.INTELX_SEARCH,
                    headers=headers,
                    json={"term": query, "maxresults": 25},
                    timeout=90.0,
                )
                resp.raise_for_status()
                aggregate.update(resp.content)
                data = resp.json()
            except httpx.HTTPError as exc:
                logger.warning("IntelX query %r: %s", query, exc)
                continue

            records = data.get("records") or data.get("results") or []
            if isinstance(data, dict) and not records and data.get("id"):
                records = [data]

            for rec in records[:25]:
                if not isinstance(rec, dict):
                    continue
                source_id = str(rec.get("systemid") or rec.get("id") or rec.get("storageid") or "")[:512]
                if not source_id:
                    source_id = hashlib.sha256(str(rec).encode()).hexdigest()[:32]
                preview = (
                    rec.get("preview")
                    or rec.get("name")
                    or rec.get("title")
                    or ""
                )
                body = str(preview)[: settings.intel_max_body_bytes]
                if not body:
                    continue
                source = "IntelX"
                doc_tags = extract_tags(body, ["paste", "intelx"])
                documents.append(
                    IntelDocument(
                        source=source,
                        source_id=source_id,
                        title=(rec.get("name") or rec.get("title") or f"IntelX {source_id}")[:500],
                        body=body,
                        url=rec.get("url"),
                        published_at=rec.get("date"),
                        tags=doc_tags,
                        meta={"query": query, "bucket": rec.get("bucket")},
                    )
                )
                fetched += 1

        digest = aggregate.hexdigest()
        if digest:
            stored = await database.get_feed_sync_state(feed_key)
            if not force and stored and stored.get("content_sha256") == digest:
                return CollectorResult(documents=[], indicators=[], skipped_fetch=True)
            if not dry_run:
                await database.upsert_feed_sync_state(
                    feed_key, content_sha256=digest, checked=True
                )
                await database.mark_feed_ingested(feed_key, fetched)

        return CollectorResult(documents=documents, indicators=[], fetched=fetched)
