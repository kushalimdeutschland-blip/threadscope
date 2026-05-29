"""Collector protocol and normalized intel documents."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol

from services.feed_parser import FeedIndicator


@dataclass(frozen=True)
class IntelDocument:
    source: str
    source_id: str
    title: str
    body: str
    url: str | None = None
    published_at: str | None = None
    tags: list[str] = field(default_factory=list)
    meta: dict[str, Any] = field(default_factory=dict)


@dataclass
class CollectorResult:
    documents: list[IntelDocument]
    indicators: list[FeedIndicator]
    fetched: int = 0
    skipped_fetch: bool = False
    error: str | None = None


class IntelCollector(Protocol):
    name: str

    async def collect(
        self,
        client: Any,
        *,
        if_changed: bool,
        dry_run: bool,
    ) -> CollectorResult:
        """Fetch and parse documents from this collector."""
