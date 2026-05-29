"""Clear-web security RSS/Atom feeds (feedparser + conditional download)."""

from __future__ import annotations

import hashlib
import logging
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Any

import feedparser
import httpx

import database
from config import get_settings
from services.feed_download import download_feed_conditional
from services.intel.base import CollectorResult, IntelDocument
from services.intel.extract import extract_tags

logger = logging.getLogger("threatscope.intel.rss")

USER_AGENT = "ThreatScope/2.5 intel-ingest (+local)"


def _parse_published(entry: dict[str, Any]) -> str | None:
    for key in ("published_parsed", "updated_parsed"):
        parsed = entry.get(key)
        if parsed:
            try:
                dt = datetime(*parsed[:6], tzinfo=timezone.utc)
                return dt.isoformat()
            except (TypeError, ValueError):
                pass
    for key in ("published", "updated"):
        raw = entry.get(key)
        if raw:
            try:
                dt = parsedate_to_datetime(raw)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                return dt.astimezone(timezone.utc).isoformat()
            except (TypeError, ValueError):
                pass
    return None


def _entry_body(entry: dict[str, Any]) -> str:
    parts = [
        entry.get("title") or "",
        entry.get("summary") or entry.get("description") or "",
    ]
    return "\n\n".join(p for p in parts if p).strip()


class RssSecurityCollector:
    name = "rss"

    def __init__(self, feeds: list[dict[str, Any]]) -> None:
        self._feeds = feeds

    async def collect(
        self,
        client: httpx.AsyncClient,
        *,
        if_changed: bool,
        dry_run: bool,
    ) -> CollectorResult:
        settings = get_settings()
        documents: list[IntelDocument] = []
        fetched = 0
        force = not if_changed

        for feed in self._feeds:
            url = (feed.get("url") or "").strip()
            if not url:
                continue
            label = feed.get("name") or url
            source = f"RSS-{label}"
            feed_key = f"intel:rss:{label}"

            result = await download_feed_conditional(
                client,
                feed_key,
                url,
                force=force,
                max_bytes=settings.intel_max_body_bytes,
            )
            if result.status == "unchanged":
                continue
            if result.status == "error" or not result.content:
                logger.warning("RSS %s: %s", label, result.error or "empty")
                continue

            parsed = feedparser.parse(result.content)
            for entry in parsed.entries[:100]:
                source_id = (
                    entry.get("id")
                    or entry.get("guid")
                    or entry.get("link")
                    or hashlib.sha256(_entry_body(entry).encode()).hexdigest()[:16]
                )
                body = _entry_body(entry)
                if not body:
                    continue
                extra_tags = list(feed.get("tags") or [])
                doc_tags = extract_tags(body, extra_tags)
                documents.append(
                    IntelDocument(
                        source=source,
                        source_id=str(source_id)[:512],
                        title=(entry.get("title") or label)[:500],
                        body=body,
                        url=entry.get("link"),
                        published_at=_parse_published(entry),
                        tags=doc_tags,
                        meta={"feed": label, "url": url},
                    )
                )
                fetched += 1

            if not dry_run and result.status == "downloaded":
                await database.mark_feed_ingested(feed_key, fetched)

        return CollectorResult(documents=documents, indicators=[], fetched=fetched)
