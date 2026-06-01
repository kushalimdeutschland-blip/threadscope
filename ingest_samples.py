#!/usr/bin/env python3
"""
Lab-only: clone private malware sample repos and ingest file hashes into SQLite.

Hashes are stored via bulk_upsert_feed_snapshot (FeedIndicator type=hash).
Samples stay on disk under temp clones — never executed by this script.

Usage:
    cp data/sample_repos.yaml.example data/sample_repos.yaml
    export SAMPLE_REPO_ACME_PASSWORD=...   # per-repo password_env in yaml
    python ingest_samples.py
    python ingest_samples.py --repo acme-samples --dry-run
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import os
import shutil
import subprocess
import sys
from pathlib import Path
from urllib.parse import quote, urlparse, urlunparse

import yaml

import database
from services.feed_parser import FeedIndicator, IngestStats, deduplicate_indicators
from services.sample_repos import (
    SampleHashRecord,
    ZipSafetyError,
    hash_single_blob,
    iter_zip_members,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
logger = logging.getLogger("threatscope.ingest_samples")

REPO_ROOT = Path(__file__).resolve().parent
DEFAULT_CONFIG = REPO_ROOT / "data" / "sample_repos.yaml"
CLONE_ROOT = REPO_ROOT / "temp_repo_clones"
SAMPLE_HASH_SCORE = 92
ARCHIVE_SUFFIXES = {".zip", ".7z", ".rar", ".gz", ".tar", ".bz2"}


def load_repo_config(path: Path) -> list[dict]:
    if not path.is_file():
        raise FileNotFoundError(
            f"Config not found: {path}\n"
            f"Copy data/sample_repos.yaml.example to data/sample_repos.yaml"
        )
    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    repos = raw.get("repos") or []
    if not isinstance(repos, list):
        raise ValueError("sample_repos.yaml: 'repos' must be a list")
    return repos


def _repo_password(repo: dict) -> str:
    env_key = (repo.get("password_env") or "").strip()
    if not env_key:
        return ""
    return os.environ.get(env_key, "").strip()


def _auth_url(url: str, password: str) -> str:
    """Embed HTTPS credentials when password_env is set (token or password)."""
    if not password:
        return url
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return url
    if parsed.username:
        return url
    user = quote("token", safe="")
    pwd = quote(password, safe="")
    host = parsed.hostname or ""
    port = f":{parsed.port}" if parsed.port else ""
    netloc = f"{user}:{pwd}@{host}{port}"
    return urlunparse(
        (parsed.scheme, netloc, parsed.path, parsed.params, parsed.query, parsed.fragment)
    )


def shallow_clone(repo: dict, dest: Path) -> None:
    url = str(repo["url"]).strip()
    name = str(repo.get("name") or dest.name)
    branch = (repo.get("branch") or "main").strip()
    tag = (repo.get("tag") or "").strip()
    password = _repo_password(repo)
    clone_url = _auth_url(url, password)

    if dest.exists():
        shutil.rmtree(dest, ignore_errors=True)
    dest.parent.mkdir(parents=True, exist_ok=True)

    cmd = [
        "git",
        "clone",
        "--depth",
        "1",
        "--single-branch",
    ]
    if tag:
        cmd.extend(["--branch", tag])
    else:
        cmd.extend(["--branch", branch])
    cmd.extend([clone_url, str(dest)])

    logger.info("Cloning %s -> %s", name, dest)
    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        err = (proc.stderr or proc.stdout or "").strip()
        raise RuntimeError(f"git clone failed for {name}: {err}")


def _walk_sample_files(root: Path) -> list[Path]:
    skip_dirs = {".git", "__MACOSX"}
    files: list[Path] = []
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if any(part in skip_dirs for part in path.parts):
            continue
        if path.name.startswith("."):
            continue
        files.append(path)
    return files


def _records_from_path(path: Path, repo_name: str) -> list[SampleHashRecord]:
    rel = path.name
    try:
        data = path.read_bytes()
    except OSError as exc:
        logger.warning("Skip unreadable %s: %s", path, exc)
        return []

    suffix = path.suffix.lower()
    if suffix == ".zip":
        try:
            members = iter_zip_members(data)
        except ZipSafetyError as exc:
            logger.warning("Skip unsafe zip %s: %s", rel, exc)
            return []
        return members

    if suffix in ARCHIVE_SUFFIXES and suffix != ".zip":
        logger.debug("Skip unsupported archive type %s", rel)
        return []

    return [hash_single_blob(data, inner_filename=rel)]


def records_to_indicators(
    records: list[SampleHashRecord],
    *,
    repo_name: str,
) -> list[FeedIndicator]:
    indicators: list[FeedIndicator] = []
    for rec in records:
        indicators.append(
            FeedIndicator(
                value=rec.sha256,
                type="hash",
                risk_score=SAMPLE_HASH_SCORE,
                tags=["Malware Sample", repo_name],
                meta={
                    "md5": rec.md5,
                    "sha1": rec.sha1,
                    "inner_filename": rec.inner_filename,
                    "repo": repo_name,
                },
            )
        )
    return indicators


async def ingest_repo(repo: dict, *, dry_run: bool, keep_clone: bool) -> IngestStats:
    name = str(repo.get("name") or "unnamed").strip()
    if not name:
        raise ValueError("repo entry missing 'name'")
    source_label = f"SampleRepo:{name}"
    clone_dir = CLONE_ROOT / name

    shallow_clone(repo, clone_dir)
    stats = IngestStats()
    all_records: list[SampleHashRecord] = []

    try:
        for path in _walk_sample_files(clone_dir):
            all_records.extend(_records_from_path(path, name))

        indicators = deduplicate_indicators(
            records_to_indicators(all_records, repo_name=name)
        )
        stats.parsed = len(indicators)

        if dry_run:
            logger.info(
                "Dry-run %s: would ingest %d unique SHA256 hashes",
                name,
                len(indicators),
            )
            return stats

        db_stats = await database.bulk_upsert_feed_snapshot(indicators, source=source_label)
        stats.inserted = db_stats.inserted
        stats.updated = db_stats.updated
        stats.skipped = db_stats.skipped
        stats.pruned = db_stats.pruned
        logger.info(
            "Ingested %s: inserted=%d updated=%d pruned=%d",
            name,
            stats.inserted,
            stats.updated,
            stats.pruned,
        )
        return stats
    finally:
        if not keep_clone and clone_dir.exists():
            shutil.rmtree(clone_dir, ignore_errors=True)


async def run_ingest(
    repo_names: list[str] | None,
    *,
    dry_run: bool,
    keep_clone: bool,
    config_path: Path,
) -> int:
    repos = load_repo_config(config_path)
    if repo_names:
        wanted = set(repo_names)
        repos = [r for r in repos if str(r.get("name", "")).strip() in wanted]
        missing = wanted - {str(r.get("name", "")).strip() for r in repos}
        if missing:
            logger.error("Unknown repo name(s): %s", ", ".join(sorted(missing)))
            return 1

    if not repos:
        logger.error("No repos configured in %s", config_path)
        return 1

    await database.init_db()
    exit_code = 0
    totals = IngestStats()

    for repo in repos:
        try:
            stats = await ingest_repo(repo, dry_run=dry_run, keep_clone=keep_clone)
            totals.parsed += stats.parsed
            totals.inserted += stats.inserted
            totals.updated += stats.updated
            totals.pruned += stats.pruned
        except Exception:
            logger.exception("Failed repo %s", repo.get("name"))
            exit_code = 1

    print(
        f"Done: parsed={totals.parsed:,} inserted={totals.inserted:,} "
        f"updated={totals.updated:,} pruned={totals.pruned:,}"
    )
    return exit_code


def main() -> int:
    parser = argparse.ArgumentParser(description="Ingest malware sample hashes from git repos")
    parser.add_argument(
        "--config",
        type=Path,
        default=DEFAULT_CONFIG,
        help="Path to sample_repos.yaml",
    )
    parser.add_argument("--repo", action="append", dest="repos", help="Only process named repo(s)")
    parser.add_argument("--dry-run", action="store_true", help="Parse and hash only; no DB writes")
    parser.add_argument(
        "--keep-clone",
        action="store_true",
        help="Leave temp_repo_clones/<name> on disk after ingest",
    )
    args = parser.parse_args()
    return asyncio.run(
        run_ingest(
            args.repos,
            dry_run=args.dry_run,
            keep_clone=args.keep_clone,
            config_path=args.config,
        )
    )


if __name__ == "__main__":
    raise SystemExit(main())
