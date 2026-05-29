"""Allowlisted clear-web page scraper (httpx + HTML-to-text; no JS execution)."""

from __future__ import annotations

import hashlib
import logging
import time
from datetime import timezone
from email.utils import parsedate_to_datetime
from typing import Any
from urllib.parse import urlparse
from urllib.robotparser import RobotFileParser

import httpx

import database
from config import get_settings
from services.feed_download import download_feed_conditional
from services.intel.base import CollectorResult, IntelDocument
from services.intel.extract import extract_tags
from services.intel.sanitize import strip_html

logger = logging.getLogger("threatscope.intel.web_scrape")

USER_AGENT = "ThreatScope/2.5 intel-ingest (+local homelab; security-research)"


class _DomainRateLimiter:
    def __init__(self, delay_seconds: float) -> None:
        self._delay = max(delay_seconds, 0.0)
        self._last: dict[str, float] = {}

    async def wait(self, domain: str) -> None:
        if self._delay <= 0 or not domain:
            return
        now = time.monotonic()
        last = self._last.get(domain, 0.0)
        elapsed = now - last
        if elapsed < self._delay:
            import asyncio

            await asyncio.sleep(self._delay - elapsed)
        self._last[domain] = time.monotonic()


class _RobotsCache:
    def __init__(self) -> None:
        self._parsers: dict[str, RobotFileParser | None] = {}

    async def allowed(
        self,
        client: httpx.AsyncClient,
        url: str,
        *,
        user_agent: str,
    ) -> bool:
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            return False
        base = f"{parsed.scheme}://{parsed.netloc}"
        if base not in self._parsers:
            robots_url = f"{base}/robots.txt"
            rp = RobotFileParser()
            try:
                resp = await client.get(robots_url, timeout=15.0, follow_redirects=True)
                if resp.status_code == 200 and resp.text:
                    rp.parse(resp.text.splitlines())
                else:
                    rp = None
            except httpx.HTTPError:
                rp = None
            self._parsers[base] = rp
        rp = self._parsers[base]
        if rp is None:
            return True
        return rp.can_fetch(user_agent, url)


def _parse_last_modified(header: str | None) -> str | None:
    if not header:
        return None
    try:
        dt = parsedate_to_datetime(header)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc).isoformat()
    except (TypeError, ValueError):
        return None


class WebScrapeCollector:
    name = "web"

    def __init__(self, config: dict[str, Any]) -> None:
        self._config = config
        self._targets = [
            t
            for t in (config.get("targets") or [])
            if t.get("enabled", True) and (t.get("url") or "").strip()
        ]
        delay = float(config.get("delay_seconds", 2.0))
        self._rate_limiter = _DomainRateLimiter(delay)
        self._robots = _RobotsCache()

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
        respect_robots = settings.intel_scrape_respect_robots
        max_bytes = settings.intel_max_body_bytes

        for target in self._targets:
            url = (target.get("url") or "").strip()
            label = target.get("name") or url
            source = f"Web-{label}"
            feed_key = f"intel:web:{label}"
            domain = urlparse(url).netloc.lower()

            if respect_robots:
                allowed = await self._robots.allowed(client, url, user_agent=USER_AGENT)
                if not allowed:
                    logger.warning("robots.txt disallows %s", url)
                    continue

            await self._rate_limiter.wait(domain)

            result = await download_feed_conditional(
                client,
                feed_key,
                url,
                force=force,
                max_bytes=max_bytes,
                binary=True,
            )
            if result.status == "unchanged":
                continue
            if result.status == "error" or not result.content_bytes:
                logger.warning("web scrape %s: %s", label, result.error or "empty")
                continue

            raw_html = result.content_bytes.decode("utf-8", errors="replace")
            body = strip_html(raw_html)
            if not body:
                logger.warning("web scrape %s: no extractable text", label)
                continue

            title = (target.get("title") or label)[:500]
            extra_tags = list(target.get("tags") or ["scrape"])
            doc_tags = extract_tags(body, extra_tags)
            source_id = hashlib.sha256(url.encode()).hexdigest()[:32]

            documents.append(
                IntelDocument(
                    source=source,
                    source_id=source_id,
                    title=title,
                    body=body,
                    url=url,
                    published_at=_parse_last_modified(result.last_modified),
                    tags=doc_tags,
                    meta={
                        "target": label,
                        "url": url,
                        "collector": "web_scrape",
                    },
                )
            )
            fetched += 1

            if not dry_run and result.status == "downloaded":
                await database.mark_feed_ingested(feed_key, 1)

        return CollectorResult(documents=documents, indicators=[], fetched=fetched)
