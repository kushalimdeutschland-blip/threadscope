#!/usr/bin/env python3
"""
Ingest intel from paste/leak APIs and clear-web RSS into intel_items + indicators.

Usage:
    python ingest_intel.py
    python ingest_intel.py --if-changed
    python ingest_intel.py --collector rss
    python ingest_intel.py --dry-run
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import sys
from datetime import datetime, timezone

import httpx

import database
from config import get_settings
from services.feed_parser import deduplicate_indicators
from services.intel.ai import generate_intel_doc_summary
from services.intel.extract import extract_iocs
from services.intel.registry import get_enabled_collectors, load_intel_config
from services.intel.sanitize import prepare_intel_document

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
logger = logging.getLogger("threatscope.ingest_intel")

USER_AGENT = "ThreatScope/2.5 intel-ingest"
DOWNLOAD_TIMEOUT = 120.0


async def ingest_documents(
    collector_name: str,
    result,
    *,
    dry_run: bool,
    client: httpx.AsyncClient | None = None,
    no_ai: bool = False,
) -> tuple[int, int, int]:
    """Persist intel documents and IOC rows. Returns (new, updated, skipped)."""
    new_items = 0
    updated = 0
    skipped = 0

    if result.skipped_fetch:
        logger.info("%s: unchanged since last run", collector_name)
        return 0, 0, 0

    if result.error:
        logger.error("%s: %s", collector_name, result.error)
        return 0, 0, 1

    indicators = deduplicate_indicators(result.indicators)
    if indicators and not dry_run:
        by_source: dict[str, list] = {}
        for row in indicators:
            src = row.meta.get("source") or collector_name
            by_source.setdefault(src, []).append(row)
        for src, rows in by_source.items():
            stats = await database.bulk_upsert_feed_snapshot(rows, source=src)
            logger.info(
                "%s IOCs [%s]: inserted=%d updated=%d skipped=%d",
                collector_name,
                src,
                stats.inserted,
                stats.updated,
                stats.skipped,
            )

    settings = get_settings()
    max_body = settings.intel_max_body_bytes

    for doc in result.documents:
        title, body, meta, digest = prepare_intel_document(
            doc.title,
            doc.body,
            doc.meta,
            max_bytes=max_body,
        )
        doc_tags = list(doc.tags)
        doc_iocs = extract_iocs(body, source=doc.source, extra_tags=doc_tags)
        ioc_count = len(doc_iocs)
        if dry_run:
            logger.info(
                "dry-run %s %s: %s (%d IOCs)",
                doc.source,
                doc.source_id,
                title[:80],
                ioc_count,
            )
            continue

        if doc_iocs and not dry_run:
            stats = await database.bulk_upsert_feed_snapshot(doc_iocs, source=doc.source)
            logger.debug(
                "%s doc IOCs [%s]: inserted=%d updated=%d",
                doc.source,
                doc.source_id,
                stats.inserted,
                stats.updated,
            )

        existing = await database.get_intel_item(doc.source, doc.source_id)
        will_write = existing is None or existing.get("body_sha256") != digest
        if (
            will_write
            and not no_ai
            and settings.intel_ai_enabled
            and settings.intel_ai_ingest_summary
        ):
            summary = await generate_intel_doc_summary(
                title,
                body,
                doc_tags,
                client=client,
            )
            if summary:
                meta["ai_summary"] = summary
                meta["ai_summary_at"] = datetime.now(timezone.utc).isoformat()

        status, _item_id = await database.upsert_intel_item(
            source=doc.source,
            source_id=doc.source_id,
            title=title,
            body=body,
            url=doc.url,
            published_at=doc.published_at,
            tags=doc_tags,
            meta=meta,
            ioc_count=ioc_count,
            body_sha256=digest,
        )
        if status == "inserted":
            new_items += 1
        elif status == "updated":
            updated += 1
        else:
            skipped += 1

    return new_items, updated, skipped


async def run_collector(
    name: str,
    collector,
    client: httpx.AsyncClient,
    *,
    if_changed: bool,
    dry_run: bool,
    no_ai: bool = False,
) -> None:
    run_id = 0 if dry_run else await database.create_collector_run(name)
    try:
        result = await collector.collect(client, if_changed=if_changed, dry_run=dry_run)
        new_items, updated, skipped = await ingest_documents(
            name,
            result,
            dry_run=dry_run,
            client=client,
            no_ai=no_ai,
        )
        errors = 1 if result.error else 0
        logger.info(
            "%s done: fetched=%d new=%d updated=%d skipped=%d errors=%d",
            name,
            result.fetched,
            new_items,
            updated,
            skipped,
            errors,
        )
        if not dry_run and run_id:
            await database.finish_collector_run(
                run_id,
                fetched=result.fetched,
                new_items=new_items,
                skipped=skipped + (1 if result.skipped_fetch else 0),
                errors=errors,
                error_text=result.error,
            )
    except Exception as exc:
        logger.exception("%s failed", name)
        if not dry_run and run_id:
            await database.finish_collector_run(
                run_id, errors=1, error_text=str(exc)[:500]
            )


async def main_async(args: argparse.Namespace) -> int:
    settings = get_settings()
    if not settings.intel_collection_enabled:
        logger.error("INTEL_COLLECTION_ENABLED is not set — refusing to run")
        return 1

    await database.init_db()
    config = load_intel_config()
    collectors = get_enabled_collectors(config)

    if args.collector:
        if args.collector not in collectors:
            logger.error(
                "Collector %r not enabled or missing API keys. Available: %s",
                args.collector,
                ", ".join(sorted(collectors)) or "(none)",
            )
            return 1
        collectors = {args.collector: collectors[args.collector]}

    if not collectors:
        logger.warning("No collectors enabled — check data/intel_feeds.yaml and API keys")
        return 0

    async with httpx.AsyncClient(
        headers={"User-Agent": USER_AGENT},
        timeout=DOWNLOAD_TIMEOUT,
        follow_redirects=True,
    ) as client:
        for name, collector in collectors.items():
            await run_collector(
                name,
                collector,
                client,
                if_changed=args.if_changed,
                dry_run=args.dry_run,
                no_ai=args.no_ai,
            )
    return 0


def main() -> None:
    parser = argparse.ArgumentParser(description="ThreatScope intel collection ingest")
    parser.add_argument(
        "--if-changed",
        action="store_true",
        help="Skip sources unchanged since last run (feed_sync_state)",
    )
    parser.add_argument(
        "--collector",
        choices=["rss", "web", "paste", "intelx", "leak"],
        help="Run a single collector",
    )
    parser.add_argument("--dry-run", action="store_true", help="Fetch/parse only; no DB writes")
    parser.add_argument(
        "--no-ai",
        action="store_true",
        help="Skip Ollama ingest summaries for this run",
    )
    args = parser.parse_args()
    raise SystemExit(asyncio.run(main_async(args)))


if __name__ == "__main__":
    main()
