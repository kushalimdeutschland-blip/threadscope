#!/usr/bin/env python3
"""
Process queued dynamic analysis jobs (run separately from the web app).

Usage:
  source venv/bin/activate
  python scripts/sandbox_worker.py
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
from services.analysis_merge import merge_dynamic_into_threat
from services.sandbox.base import DynamicReport
from services.sandbox.registry import get_adapter
from services.sandbox.staging import delete_job_samples, sample_path_for_job

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("sandbox_worker")


async def process_job(job: dict) -> None:
    settings = get_settings()
    job_id = job["id"]
    sample = sample_path_for_job(job_id, file_hash=job.get("file_hash"))
    if not sample.is_file():
        await database.update_analysis_job(
            job_id,
            status="failed",
            error_text="Sample file missing on disk",
            finished=True,
        )
        return

    adapter = get_adapter(job["backend"], settings)
    logger.info("Submitting job %s to %s", job_id, adapter.name)

    try:
        external_id = await adapter.submit(sample, job["filename"], job["file_kind"])
        await database.update_analysis_job(job_id, external_job_id=external_id)

        deadline = time.monotonic() + settings.sandbox_job_timeout
        report: DynamicReport | None = None

        while time.monotonic() < deadline:
            status, report = await adapter.poll(external_id)
            if status == "pending":
                await asyncio.sleep(settings.sandbox_poll_interval)
                continue
            if status == "failed":
                err = report.error if report else "Sandbox analysis failed"
                await database.update_analysis_job(
                    job_id,
                    status="failed",
                    error_text=err,
                    report=report.to_dict() if report else None,
                    finished=True,
                )
                return
            if status == "completed" and report is not None:
                break
            await asyncio.sleep(settings.sandbox_poll_interval)
        else:
            await database.update_analysis_job(
                job_id,
                status="failed",
                error_text=f"Timed out after {settings.sandbox_job_timeout}s",
                finished=True,
            )
            return

        assert report is not None
        static_threat = job.get("static_threat") or {}
        merged_threat = merge_dynamic_into_threat(static_threat, report)

        await database.update_analysis_job(
            job_id,
            status="completed",
            report={
                "dynamic": report.to_dict(),
                "threat": merged_threat,
            },
            finished=True,
        )
        logger.info("Job %s completed (%s)", job_id, adapter.name)

    except Exception as exc:
        logger.exception("Job %s failed", job_id)
        await database.update_analysis_job(
            job_id,
            status="failed",
            error_text=str(exc)[:500],
            finished=True,
        )
    finally:
        delete_job_samples(job_id)


async def worker_loop() -> None:
    settings = get_settings()
    await database.init_db()
    await database.open_read_pool()
    logger.info(
        "Sandbox worker started (backend default=%s, max_concurrent=%s)",
        settings.sandbox_backend,
        settings.sandbox_max_concurrent,
    )

    try:
        while True:
            running = await database.count_running_analysis_jobs()
            if running >= settings.sandbox_max_concurrent:
                await asyncio.sleep(2)
                continue

            job = await database.claim_next_analysis_job()
            if job is None:
                await asyncio.sleep(2)
                continue

            await process_job(job)
    finally:
        await database.close_read_pool()


def main() -> None:
    try:
        asyncio.run(worker_loop())
    except KeyboardInterrupt:
        logger.info("Worker stopped")


if __name__ == "__main__":
    main()
