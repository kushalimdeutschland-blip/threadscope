#!/usr/bin/env python3
"""
Periodic intel collection worker (run separately from the web app).

Usage:
  source venv/bin/activate
  INTEL_COLLECTION_ENABLED=1 python scripts/intel_worker.py
"""

from __future__ import annotations

import asyncio
import logging
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import httpx

import database
import ingest_intel
from config import get_settings
from services.intel.registry import get_enabled_collectors, load_intel_config

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("intel_worker")


async def run_once(client: httpx.AsyncClient) -> None:
    collectors = get_enabled_collectors(load_intel_config())
    for name, collector in collectors.items():
        await ingest_intel.run_collector(
            name,
            collector,
            client,
            if_changed=True,
            dry_run=False,
        )


async def worker_loop() -> None:
    settings = get_settings()
    if not settings.intel_collection_enabled:
        logger.error("INTEL_COLLECTION_ENABLED is not set — refusing to start intel worker")
        sys.exit(1)

    await database.init_db()
    interval = max(settings.intel_worker_interval, 60)
    logger.info("Intel worker started (interval=%ds)", interval)

    async with httpx.AsyncClient(
        headers={"User-Agent": ingest_intel.USER_AGENT},
        timeout=ingest_intel.DOWNLOAD_TIMEOUT,
        follow_redirects=True,
    ) as client:
        while True:
            try:
                await run_once(client)
            except Exception:
                logger.exception("Intel ingest cycle failed")
            await asyncio.sleep(interval)


def main() -> None:
    try:
        asyncio.run(worker_loop())
    except KeyboardInterrupt:
        logger.info("Intel worker stopped")


if __name__ == "__main__":
    main()
