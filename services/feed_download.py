"""
Conditional OSINT feed downloads (ETag / Last-Modified / content hash).
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Literal

import httpx

import database

DownloadStatus = Literal["downloaded", "unchanged", "error"]


@dataclass(frozen=True)
class DownloadResult:
    status: DownloadStatus
    content: str | None = None
    content_bytes: bytes | None = None
    etag: str | None = None
    last_modified: str | None = None
    content_sha256: str | None = None
    error: str | None = None


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


async def download_feed_conditional(
    client: httpx.AsyncClient,
    feed_key: str,
    url: str,
    *,
    force: bool,
    max_bytes: int,
    binary: bool = False,
) -> DownloadResult:
    """
    Download a feed when forced or when validators indicate new content.
    Returns unchanged when a conditional request gets 304 or body hash matches stored state.
    """
    stored = await database.get_feed_sync_state(feed_key)
    headers: dict[str, str] = {}
    if not force and stored:
        if stored.get("etag"):
            headers["If-None-Match"] = stored["etag"]
        if stored.get("last_modified"):
            headers["If-Modified-Since"] = stored["last_modified"]

    try:
        resp = await client.get(url, headers=headers, follow_redirects=True)
    except httpx.HTTPError as exc:
        await database.upsert_feed_sync_state(feed_key, checked=True)
        return DownloadResult(status="error", error=str(exc))

    if resp.status_code == 304:
        await database.upsert_feed_sync_state(feed_key, checked=True)
        return DownloadResult(status="unchanged")

    if resp.status_code >= 400:
        await database.upsert_feed_sync_state(feed_key, checked=True)
        return DownloadResult(
            status="error",
            error=f"HTTP {resp.status_code} for {url}",
        )
    if len(resp.content) > max_bytes:
        return DownloadResult(
            status="error",
            error=f"response exceeds {max_bytes} byte limit",
        )

    raw = resp.content
    digest = _sha256_bytes(raw)
    etag = resp.headers.get("etag")
    last_modified = resp.headers.get("last-modified")

    if not force and stored and stored.get("content_sha256") == digest:
        await database.upsert_feed_sync_state(
            feed_key,
            etag=etag,
            last_modified=last_modified,
            content_sha256=digest,
            checked=True,
        )
        return DownloadResult(status="unchanged")

    await database.upsert_feed_sync_state(
        feed_key,
        etag=etag,
        last_modified=last_modified,
        content_sha256=digest,
        checked=True,
    )
    if binary:
        return DownloadResult(
            status="downloaded",
            content_bytes=raw,
            etag=etag,
            last_modified=last_modified,
            content_sha256=digest,
        )
    return DownloadResult(
        status="downloaded",
        content=raw.decode("utf-8", errors="replace"),
        etag=etag,
        last_modified=last_modified,
        content_sha256=digest,
    )


async def mark_feed_ingested(feed_key: str, row_count: int) -> None:
    stored = await database.get_feed_sync_state(feed_key)
    await database.upsert_feed_sync_state(
        feed_key,
        etag=stored.get("etag") if stored else None,
        last_modified=stored.get("last_modified") if stored else None,
        content_sha256=stored.get("content_sha256") if stored else None,
        checked=True,
        ingested=True,
        last_row_count=row_count,
    )
