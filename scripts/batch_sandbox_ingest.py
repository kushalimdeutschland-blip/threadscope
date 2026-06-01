#!/usr/bin/env python3
"""
Lab-only scaffold: enqueue dynamic analysis jobs for hashes already in SQLite.

Does NOT download or detonate samples automatically on a public VPS.
Run only on a homelab with SANDBOX_BACKEND configured and sandbox_worker.py running.

Usage:
  python scripts/batch_sandbox_ingest.py --dry-run
  python scripts/batch_sandbox_ingest.py --limit 10 --confirm-lab
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import sys
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import database
from config import get_settings
from services.sample_store import sample_path_for_hash

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("batch_sandbox_ingest")


async def _hash_candidates(limit: int, source_prefix: str | None) -> list[dict]:
    rows = await database.list_indicators_for_export(
        min_score=0,
        indicator_type="hash",
        limit=limit,
    )
    if not source_prefix:
        return rows
    out: list[dict] = []
    for row in rows:
        sources = await database.get_indicator_sources(row["value"], "hash")
        if any(str(s.get("source", "")).startswith(source_prefix) for s in sources):
            out.append(row)
    return out


async def run_batch(*, limit: int, dry_run: bool, source_prefix: str | None) -> int:
    settings = get_settings()

    if settings.threatscope_public:
        logger.error(
            "Refusing to run: THREATSCOPE_PUBLIC=1 (public VPS). "
            "Use a lab host only."
        )
        return 1

    if settings.sandbox_backend.strip().lower() == "off":
        logger.error("SANDBOX_BACKEND=off — enable mock/cape/mobsf on the lab first.")
        return 1

    await database.init_db()
    await database.open_read_pool()
    rows = await _hash_candidates(limit, source_prefix)
    logger.info("Found %d hash indicator(s) to consider", len(rows))

    enqueued = 0
    for row in rows:
        sha = row["value"]
        sample = sample_path_for_hash(sha)
        if not sample.is_file():
            logger.debug("No on-disk sample for %s — skip", sha)
            continue

        if dry_run:
            logger.info("[dry-run] would enqueue dynamic job for %s", sha)
            enqueued += 1
            continue

        job_id = str(uuid.uuid4())
        await database.create_analysis_job(
            job_id,
            file_hash=sha,
            filename=sample.name,
            file_kind="unknown",
            backend=settings.sandbox_backend,
            static_threat={"value": sha, "type": "hash", "verdict": "UNKNOWN"},
        )
        logger.info("Enqueued job %s for %s", job_id, sha)
        enqueued += 1

    print(f"{'Would enqueue' if dry_run else 'Enqueued'}: {enqueued} job(s)")
    print("Run sandbox_worker.py in another terminal to process the queue.")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Lab-only: enqueue analysis_jobs for hashes with on-disk samples"
    )
    parser.add_argument("--limit", type=int, default=50)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument(
        "--source-prefix",
        default="SampleRepo:",
        help="Only hashes seen from this feed source prefix",
    )
    parser.add_argument(
        "--confirm-lab",
        action="store_true",
        help="Required on non-dry-run to acknowledge lab-only detonation",
    )
    args = parser.parse_args()

    if not args.dry_run and not args.confirm_lab:
        print(
            "Refusing live enqueue without --confirm-lab "
            "(batch detonation is lab-only).",
            file=sys.stderr,
        )
        return 1

    return asyncio.run(
        run_batch(
            limit=args.limit,
            dry_run=args.dry_run,
            source_prefix=args.source_prefix or None,
        )
    )


if __name__ == "__main__":
    raise SystemExit(main())
