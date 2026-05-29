#!/usr/bin/env python3
"""
Process queued lab scan jobs (run separately from the web app).

Usage:
  source venv/bin/activate
  LAB_SCAN_ENABLED=1 python scripts/scan_worker.py
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

import database
from config import get_settings
from services.lab_scan import run_lab_scan

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("scan_worker")


async def process_job(job: dict) -> None:
    settings = get_settings()
    job_id = job["id"]
    host = job.get("resolved_ip") or job["target"]
    logger.info("Scanning job %s target=%s", job_id, host)

    try:
        report = await asyncio.to_thread(run_lab_scan, host)
        await database.update_scan_job(
            job_id,
            status="completed",
            report=report,
            finished=True,
        )
        logger.info("Completed scan job %s — %d open ports", job_id, len(report.get("open_ports", [])))
    except Exception as exc:
        await database.update_scan_job(
            job_id,
            status="failed",
            error_text=str(exc)[:500],
            finished=True,
        )
        logger.exception("Scan job %s failed", job_id)


async def worker_loop() -> None:
    settings = get_settings()
    if not settings.lab_scan_enabled:
        logger.error("LAB_SCAN_ENABLED is not set — refusing to start scan worker")
        sys.exit(1)

    await database.init_db()
    logger.info("Lab scan worker started (max concurrent=%d)", settings.lab_scan_max_concurrent)

    while True:
        running = await database.count_running_scan_jobs()
        if running >= settings.lab_scan_max_concurrent:
            await asyncio.sleep(settings.lab_scan_poll_interval)
            continue

        job = await database.claim_next_scan_job()
        if job is None:
            await asyncio.sleep(settings.lab_scan_poll_interval)
            continue

        await process_job(job)


def main() -> None:
    try:
        asyncio.run(worker_loop())
    except KeyboardInterrupt:
        logger.info("Scan worker stopped")


if __name__ == "__main__":
    main()
