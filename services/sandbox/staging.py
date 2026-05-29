"""
On-disk staging for sandbox samples (worker reads, web app writes).

Primary storage is content-addressed under data/samples/<sha256>.
Legacy per-job copies under data/uploads/ remain as fallback.
"""

from __future__ import annotations

import os
from pathlib import Path

from services.sample_store import sample_path_for_hash, store_sample

UPLOADS_ROOT = Path(__file__).resolve().parents[2] / "data" / "uploads"


def job_sample_dir(job_id: str) -> Path:
    path = UPLOADS_ROOT / job_id
    path.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(path, 0o700)
    except OSError:
        pass
    return path


def sample_path_for_job(job_id: str, file_hash: str | None = None) -> Path:
    """Resolve sample path — prefer content-addressed store by SHA256."""
    if file_hash:
        canonical = sample_path_for_hash(file_hash)
        if canonical.is_file():
            return canonical
    return job_sample_dir(job_id) / "sample.bin"


def write_sample(job_id: str, data: bytes, file_hash: str | None = None) -> Path:
    """Store sample by hash and ensure worker can resolve it."""
    sha256, path = store_sample(data)
    if file_hash:
        sha256 = file_hash.lower()
        path = sample_path_for_hash(sha256)
        if not path.is_file():
            path = store_sample(data)[1]

    legacy = job_sample_dir(job_id) / "sample.bin"
    if not legacy.is_file() and path.is_file():
        try:
            os.link(path, legacy)
        except OSError:
            legacy.write_bytes(data)
            try:
                os.chmod(legacy, 0o600)
            except OSError:
                pass
    return path


def delete_job_samples(job_id: str) -> None:
    path = UPLOADS_ROOT / job_id
    if not path.is_dir():
        return
    for child in path.iterdir():
        try:
            child.unlink()
        except OSError:
            pass
    try:
        path.rmdir()
    except OSError:
        pass
