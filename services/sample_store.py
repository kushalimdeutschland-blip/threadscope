"""
Content-addressed on-disk sample storage (SHA256-keyed, not in SQLite).
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path

SAMPLES_ROOT = Path(__file__).resolve().parents[1] / "data" / "samples"


def sample_path_for_hash(sha256: str) -> Path:
    sha256 = sha256.lower()
    if len(sha256) != 64 or not all(c in "0123456789abcdef" for c in sha256):
        raise ValueError("invalid sha256")
    return SAMPLES_ROOT / sha256[:2] / sha256


def store_sample(data: bytes) -> tuple[str, Path]:
    """Write sample once keyed by SHA256; return (hash, path)."""
    digest = hashlib.sha256(data).hexdigest()
    path = sample_path_for_hash(digest)
    if path.is_file():
        return digest, path

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    try:
        os.chmod(path.parent, 0o700)
        os.chmod(path, 0o600)
    except OSError:
        pass
    return digest, path


def read_sample(sha256: str) -> bytes | None:
    path = sample_path_for_hash(sha256)
    if not path.is_file():
        return None
    return path.read_bytes()
