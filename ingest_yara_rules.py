#!/usr/bin/env python3
"""
Download and extract YARA rules into data/yara_rules/ with conditional sync.

Uses the same feed_sync_state pattern as OSINT ingest (ETag / content SHA-256).

Usage:
  python ingest_yara_rules.py           # skip if bundle unchanged
  python ingest_yara_rules.py --force   # always re-download
"""

from __future__ import annotations

import argparse
import asyncio
import io
import logging
import shutil
import sys
import zipfile
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import database
from config import get_settings
from services.feed_download import download_feed_conditional, mark_feed_ingested
from services.yara_scan import invalidate_rules_cache

logger = logging.getLogger("ingest_yara_rules")
FEED_KEY = "yara_rules_bundle"
MAX_ZIP_BYTES = 120 * 1024 * 1024


def _extract_yar_files(zip_bytes: bytes, dest: Path) -> int:
    dest.mkdir(parents=True, exist_ok=True)
    staging = dest.parent / ".yara_extract_tmp"
    if staging.exists():
        shutil.rmtree(staging)
    staging.mkdir(parents=True)

    count = 0
    with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
        for info in zf.infolist():
            if info.is_dir():
                continue
            name = info.filename
            if not (name.endswith(".yar") or name.endswith(".yara")):
                continue
            if info.file_size > 2 * 1024 * 1024:
                continue
            target = staging / Path(name).name
            # avoid name collisions from different folders
            base = target.stem
            suffix = target.suffix
            n = 1
            while target.exists():
                target = staging / f"{base}_{n}{suffix}"
                n += 1
            target.write_bytes(zf.read(info))

    extracted = list(staging.rglob("*.yar")) + list(staging.rglob("*.yara"))
    count = len(extracted)
    if count == 0:
        shutil.rmtree(staging, ignore_errors=True)
        raise RuntimeError("zip contained no .yar / .yara files")

    if dest.exists():
        shutil.rmtree(dest)
    dest.mkdir(parents=True)
    for path in extracted:
        shutil.move(str(path), dest / path.name)

    shutil.rmtree(staging, ignore_errors=True)
    return count


async def run_ingest(*, force: bool) -> int:
    settings = get_settings()
    dest = Path(settings.yara_rules_dir)
    url = settings.yara_rules_bundle_url

    await database.init_db()
    await database.open_read_pool()

    try:
        async with httpx.AsyncClient(timeout=120.0) as client:
            result = await download_feed_conditional(
                client,
                FEED_KEY,
                url,
                force=force,
                max_bytes=MAX_ZIP_BYTES,
                binary=True,
            )

        if result.status == "error":
            logger.error("Download failed: %s", result.error)
            return 1

        if result.status == "unchanged":
            logger.info("YARA rules bundle unchanged — skipping extract")
            return 0

        if not result.content_bytes:
            logger.error("Empty download")
            return 1

        rule_count = _extract_yar_files(result.content_bytes, dest)
        invalidate_rules_cache()
        await mark_feed_ingested(FEED_KEY, rule_count)
        logger.info("Installed %s YARA rule files to %s", rule_count, dest)
        return 0
    finally:
        await database.close_read_pool()


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    parser = argparse.ArgumentParser(description="Sync YARA rules bundle")
    parser.add_argument(
        "--force",
        action="store_true",
        help="Re-download even if validators say unchanged",
    )
    args = parser.parse_args()
    raise SystemExit(asyncio.run(run_ingest(force=args.force)))


if __name__ == "__main__":
    main()
