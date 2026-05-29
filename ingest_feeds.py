#!/usr/bin/env python3
"""
Download and ingest OSINT feeds into the local indicators database.

Feeds:
  - Blocklist.de, CINSscore, URLhaus, Phishing.Database, Feodo Tracker (original five)
  - MalwareBazaar, Spamhaus DROP, FireHOL Level1, OpenPhish, CISA KEV
  - ThreatFox (optional; set ABUSE_CH_AUTH_KEY in environment)

Usage:
    python ingest_feeds.py              # ingest all feeds (force download)
    python ingest_feeds.py --if-changed # skip feeds unchanged since last run
    python ingest_feeds.py --feed feodo
    python ingest_feeds.py --dry-run
"""

from __future__ import annotations

import argparse
import asyncio
import io
import logging
import os
import sys
import time
import zipfile
from pathlib import Path
from typing import Callable

import httpx

import database
from services.feed_download import DownloadResult, download_feed_conditional, mark_feed_ingested
from services.feed_parser import (
    FeedIndicator,
    IngestStats,
    deduplicate_indicators,
    parse_blocklist_text,
    parse_cinsscore_text,
    parse_cisa_kev_json,
    parse_feodo_text,
    parse_firehol_level1_text,
    parse_malwarebazaar_csv,
    parse_openphish_text,
    parse_phishing_urls_text,
    parse_spamhaus_drop_text,
    parse_threatfox_csv,
    parse_urlhaus_text,
    parse_email_scam_csv,
    parse_phone_scam_csv,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
logger = logging.getLogger("threatscope.ingest")

USER_AGENT = "ThreatScope/2.4 feed-ingest (+https://github.com/threatscope)"
MAX_DOWNLOAD_BYTES = 100 * 1024 * 1024
DOWNLOAD_TIMEOUT = 120.0
PHONE_SCAM_PATH = Path(__file__).resolve().parent / "data" / "feeds" / "phone_scam.csv"
EMAIL_SCAM_PATH = Path(__file__).resolve().parent / "data" / "feeds" / "email_scam.csv"
GITHUB_PHISHING_API = (
    "https://api.github.com/repos/mitchellkrogza/Phishing.Database/commits"
    "?path=phishing-links-ACTIVE.txt&per_page=1"
)

FEEDS: dict[str, str] = {
    "blocklist": "https://lists.blocklist.de/lists/all.txt",
    "cinsscore": "https://cinsscore.com/list/ci-badguys.txt",
    "urlhaus": "https://urlhaus.abuse.ch/downloads/text/",
    "phishing": "https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-links-ACTIVE.txt",
    "feodo": "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
    "malwarebazaar": "https://bazaar.abuse.ch/export/csv/recent/",
    "spamhaus_drop": "https://www.spamhaus.org/drop/drop.txt",
    "firehol": "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset",
    "openphish": "https://openphish.com/feed.txt",
    "cisa_kev": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
}

FEED_LABELS: dict[str, str] = {
    "blocklist": "Blocklist.de",
    "cinsscore": "CINSscore",
    "urlhaus": "URLhaus",
    "phishing": "Phishing.Database",
    "feodo": "Feodo Tracker",
    "malwarebazaar": "MalwareBazaar",
    "spamhaus_drop": "Spamhaus DROP",
    "firehol": "FireHOL Level1",
    "openphish": "OpenPhish",
    "cisa_kev": "CISA KEV",
    "threatfox": "ThreatFox",
    "phone_scam": "PhoneScamList",
    "email_scam": "EmailScamList",
}

PARSERS: dict[str, Callable[[str], list[FeedIndicator]]] = {
    "blocklist": parse_blocklist_text,
    "cinsscore": parse_cinsscore_text,
    "urlhaus": parse_urlhaus_text,
    "phishing": parse_phishing_urls_text,
    "feodo": parse_feodo_text,
    "malwarebazaar": parse_malwarebazaar_csv,
    "spamhaus_drop": parse_spamhaus_drop_text,
    "firehol": parse_firehol_level1_text,
    "openphish": parse_openphish_text,
    "cisa_kev": parse_cisa_kev_json,
    "threatfox": parse_threatfox_csv,
    "phone_scam": parse_phone_scam_csv,
    "email_scam": parse_email_scam_csv,
}


def _threatfox_url() -> str | None:
    auth_key = os.getenv("ABUSE_CH_AUTH_KEY", "").strip()
    if not auth_key:
        return None
    return f"https://threatfox-api.abuse.ch/v2/files/exports/{auth_key}/full.csv.zip"


def _resolve_feed_urls(feed_names: list[str]) -> dict[str, str]:
    urls = {name: FEEDS[name] for name in feed_names if name in FEEDS}
    if "threatfox" in feed_names:
        threatfox_url = _threatfox_url()
        if threatfox_url:
            urls["threatfox"] = threatfox_url
    return urls


def parse_feed(name: str, content: str) -> list[FeedIndicator]:
    parser = PARSERS.get(name)
    if parser is None:
        raise ValueError(f"Unknown feed: {name}")
    return parser(content)


def _extract_threatfox_csv(zip_bytes: bytes) -> str:
    with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
        for name in zf.namelist():
            if name.endswith(".csv"):
                return zf.read(name).decode("utf-8", errors="replace")
    raise ValueError("ThreatFox export ZIP contains no CSV file")


def _indicator_label(rows: list[FeedIndicator]) -> str:
    ip_count = sum(1 for row in rows if row.type in ("ipv4", "ipv6"))
    domain_count = sum(1 for row in rows if row.type == "domain")
    hash_count = sum(1 for row in rows if row.type == "hash")
    phone_count = sum(1 for row in rows if row.type == "phone")
    email_count = sum(1 for row in rows if row.type == "email")
    if email_count and not ip_count and not domain_count and not hash_count and not phone_count:
        return "email addresses"
    if phone_count and not ip_count and not domain_count and not hash_count:
        return "phone numbers"
    if hash_count and not ip_count and not domain_count:
        return "hashes"
    if domain_count and not ip_count:
        return "domains"
    if ip_count and not domain_count:
        return "IPs"
    return "indicators"


async def _github_phishing_commit_sha(client: httpx.AsyncClient) -> str | None:
    try:
        resp = await client.get(
            GITHUB_PHISHING_API,
            headers={"Accept": "application/vnd.github+json"},
        )
        resp.raise_for_status()
        return resp.json()[0]["sha"]
    except (httpx.HTTPError, KeyError, IndexError, ValueError) as exc:
        logger.warning("GitHub commit check failed for phishing feed: %s", exc)
        return None


async def _github_phishing_unchanged(client: httpx.AsyncClient, force: bool) -> bool:
    """Return True if GitHub commit SHA matches stored state (skip download)."""
    if force:
        return False
    stored = await database.get_feed_sync_state("phishing")
    if not stored or not stored.get("etag"):
        return False
    sha = await _github_phishing_commit_sha(client)
    if sha is None:
        return False
    if sha == stored["etag"]:
        await database.upsert_feed_sync_state("phishing", checked=True)
        return True
    return False


async def _fetch_feed_content(
    client: httpx.AsyncClient,
    name: str,
    url: str,
    *,
    force: bool,
) -> DownloadResult:
    if name == "phishing" and await _github_phishing_unchanged(client, force):
        return DownloadResult(status="unchanged")

    if name == "threatfox":
        result = await download_feed_conditional(
            client,
            name,
            url,
            force=force,
            max_bytes=MAX_DOWNLOAD_BYTES,
            binary=True,
        )
        if result.status != "downloaded" or result.content_bytes is None:
            return result
        try:
            csv_text = _extract_threatfox_csv(result.content_bytes)
        except (zipfile.BadZipFile, ValueError) as exc:
            return DownloadResult(status="error", error=str(exc))
        return DownloadResult(
            status="downloaded",
            content=csv_text,
            etag=result.etag,
            last_modified=result.last_modified,
            content_sha256=result.content_sha256,
        )

    return await download_feed_conditional(
        client, name, url, force=force, max_bytes=MAX_DOWNLOAD_BYTES
    )


def _load_local_phone_feed() -> str | None:
    if not PHONE_SCAM_PATH.is_file():
        return None
    return PHONE_SCAM_PATH.read_text(encoding="utf-8", errors="replace")


def _load_local_email_feed() -> str | None:
    if not EMAIL_SCAM_PATH.is_file():
        return None
    return EMAIL_SCAM_PATH.read_text(encoding="utf-8", errors="replace")


async def run_ingest(
    feed_names: list[str],
    dry_run: bool,
    *,
    force: bool,
) -> int:
    if "threatfox" in feed_names and not _threatfox_url():
        print(
            "  SKIP: ThreatFox requires ABUSE_CH_AUTH_KEY in environment "
            "(free key at https://auth.abuse.ch/)",
            file=sys.stderr,
        )
        feed_names = [n for n in feed_names if n != "threatfox"]

    run_started = time.perf_counter()
    await database.init_db()

    feed_urls = _resolve_feed_urls(feed_names)
    download_started = time.perf_counter()
    mode = "forced" if force else "if-changed"
    print(f"Downloading {len(feed_urls)} feed(s) ({mode}) ...")

    downloads: dict[str, DownloadResult] = {}
    unchanged_count = 0
    failed_count = 0

    async with httpx.AsyncClient(
        timeout=DOWNLOAD_TIMEOUT,
        follow_redirects=True,
        headers={"User-Agent": USER_AGENT},
    ) as client:
        for name, url in feed_urls.items():
            result = await _fetch_feed_content(client, name, url, force=force)
            downloads[name] = result
            if result.status == "unchanged":
                unchanged_count += 1
            elif result.status == "error":
                failed_count += 1

    download_elapsed = time.perf_counter() - download_started
    logger.info(
        "Download phase completed in %.1fs for %d feed(s)",
        download_elapsed,
        len(feed_urls),
    )

    exit_code = 0
    totals = IngestStats()
    updated_count = 0

    for name in feed_names:
        if name not in feed_urls:
            continue
        label = FEED_LABELS.get(name, name)
        result = downloads.get(name)
        if result is None:
            continue

        if result.status == "unchanged":
            print(f"  Unchanged: {label}")
            logger.info("Feed %s: unchanged", label)
            continue

        if result.status == "error" or result.content is None:
            print(f"  ERROR: failed to download {label}: {result.error}", file=sys.stderr)
            logger.error("Feed download failed: %s — %s", label, result.error)
            exit_code = 1
            continue

        feed_started = time.perf_counter()
        parsed = deduplicate_indicators(parse_feed(name, result.content))
        kind = _indicator_label(parsed)
        count = len(parsed)

        if name == "phishing" and not dry_run:
            async with httpx.AsyncClient(
                timeout=30.0,
                follow_redirects=True,
                headers={"Accept": "application/vnd.github+json", "User-Agent": USER_AGENT},
            ) as gh_client:
                sha = await _github_phishing_commit_sha(gh_client)
                if sha:
                    await database.upsert_feed_sync_state(
                        "phishing",
                        etag=sha,
                        checked=True,
                        ingested=True,
                    )

        if dry_run:
            feed_elapsed = time.perf_counter() - feed_started
            print(f"  Parsed {count:,} {kind} from {label}")
            logger.info("Feed %s: parsed %d rows in %.1fs", label, count, feed_elapsed)
            totals.parsed += count
            updated_count += 1
            continue

        stats: IngestStats = await database.bulk_upsert_feed_snapshot(parsed, source=label)
        ingested = stats.inserted + stats.updated
        await mark_feed_ingested(name, count)
        feed_elapsed = time.perf_counter() - feed_started
        print(
            f"  Ingested {ingested:,} {kind} from {label} "
            f"(pruned {stats.pruned:,} stale source rows)"
        )
        logger.info(
            "Feed %s: upserted %d rows, pruned %d, in %.1fs",
            label,
            ingested,
            stats.pruned,
            feed_elapsed,
        )
        totals.inserted += stats.inserted
        totals.updated += stats.updated
        totals.skipped += stats.skipped
        totals.parsed += count
        totals.pruned += stats.pruned
        updated_count += 1

    if "phone_scam" in feed_names:
        local_content = _load_local_phone_feed()
        if local_content is None:
            print(f"  SKIP: PhoneScamList — create {PHONE_SCAM_PATH} to ingest phone numbers")
        else:
            label = FEED_LABELS["phone_scam"]
            feed_started = time.perf_counter()
            parsed = deduplicate_indicators(parse_phone_scam_csv(local_content))
            count = len(parsed)
            if dry_run:
                print(f"  Parsed {count:,} phone numbers from {label}")
                totals.parsed += count
                updated_count += 1
            else:
                stats = await database.bulk_upsert_feed_snapshot(parsed, source=label)
                ingested = stats.inserted + stats.updated
                feed_elapsed = time.perf_counter() - feed_started
                print(
                    f"  Ingested {ingested:,} phone numbers from {label} "
                    f"(pruned {stats.pruned:,} stale source rows)"
                )
                totals.inserted += stats.inserted
                totals.updated += stats.updated
                totals.skipped += stats.skipped
                totals.parsed += count
                totals.pruned += stats.pruned
                updated_count += 1

    if "email_scam" in feed_names:
        local_content = _load_local_email_feed()
        if local_content is None:
            print(f"  SKIP: EmailScamList — create {EMAIL_SCAM_PATH} to ingest email addresses")
        else:
            label = FEED_LABELS["email_scam"]
            feed_started = time.perf_counter()
            parsed = deduplicate_indicators(parse_email_scam_csv(local_content))
            count = len(parsed)
            if dry_run:
                print(f"  Parsed {count:,} email addresses from {label}")
                totals.parsed += count
                updated_count += 1
            else:
                stats = await database.bulk_upsert_feed_snapshot(parsed, source=label)
                ingested = stats.inserted + stats.updated
                feed_elapsed = time.perf_counter() - feed_started
                print(
                    f"  Ingested {ingested:,} email addresses from {label} "
                    f"(pruned {stats.pruned:,} stale source rows)"
                )
                totals.inserted += stats.inserted
                totals.updated += stats.updated
                totals.skipped += stats.skipped
                totals.parsed += count
                totals.pruned += stats.pruned
                updated_count += 1

    run_elapsed = time.perf_counter() - run_started
    checked = len(feed_urls)

    if dry_run:
        print(f"\nDry run — parsed {totals.parsed:,} indicators total; no database changes made.")
        logger.info("Dry run finished in %.1fs", run_elapsed)
        return exit_code

    print(
        f"\nChecked {checked} feed(s): {updated_count} updated, "
        f"{unchanged_count} unchanged, {failed_count} failed"
    )
    print(
        f"Done. Inserted: {totals.inserted:,} | Updated: {totals.updated:,} | "
        f"Pruned: {totals.pruned:,} | Skipped: {totals.skipped:,}"
    )
    logger.info(
        "Ingest complete in %.1fs — inserted=%d updated=%d pruned=%d skipped=%d",
        run_elapsed,
        totals.inserted,
        totals.updated,
        totals.pruned,
        totals.skipped,
    )
    return exit_code


def main() -> None:
    parser = argparse.ArgumentParser(description="Ingest OSINT feeds into ThreatScope")
    parser.add_argument(
        "--feed",
        choices=sorted(set(FEEDS) | {"threatfox", "phone_scam", "email_scam"}),
        action="append",
        dest="feeds",
        help="Ingest a specific feed (repeatable). Default: all feeds.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Download and parse only; do not write to the database.",
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--if-changed",
        action="store_true",
        help="Skip feeds that have not changed since the last successful check.",
    )
    mode.add_argument(
        "--force",
        action="store_true",
        help="Always download and ingest all feeds (default).",
    )
    args = parser.parse_args()
    force = not args.if_changed
    feed_names = args.feeds or sorted(set(FEEDS) | {"threatfox", "phone_scam", "email_scam"})
    exit_code = asyncio.run(run_ingest(feed_names, args.dry_run, force=force))
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
