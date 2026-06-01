"""
Walk malware sample archives in memory (zip-in-RAM) with zip-bomb guards.

Used by ingest_samples.py on the lab tier only — never executes file contents.
"""

from __future__ import annotations

import hashlib
import io
import zipfile
from dataclasses import dataclass
from pathlib import PurePosixPath

# Zip bomb / resource limits (tunable via ingest CLI if needed later)
MAX_ZIP_MEMBERS = 10_000
MAX_UNCOMPRESSED_BYTES = 512 * 1024 * 1024  # 512 MiB total inflated
MAX_MEMBER_UNCOMPRESSED = 64 * 1024 * 1024  # 64 MiB per entry
MAX_COMPRESSION_RATIO = 200  # uncompressed / compressed


@dataclass(frozen=True)
class SampleHashRecord:
    """One file entry inside an archive or a loose sample blob."""

    sha256: str
    md5: str
    sha1: str
    inner_filename: str


class ZipSafetyError(ValueError):
    """Archive rejected by safety limits or path traversal."""


def _safe_inner_path(name: str) -> str:
    """Reject path traversal and absolute paths inside zip members."""
    raw = name.replace("\\", "/").strip()
    if not raw or raw.startswith("/"):
        raise ZipSafetyError(f"unsafe zip path: {name!r}")
    parts = PurePosixPath(raw).parts
    if ".." in parts:
        raise ZipSafetyError(f"path traversal in zip entry: {name!r}")
    return "/".join(parts)


def _hashes_for_blob(data: bytes) -> tuple[str, str, str]:
    md5 = hashlib.md5(data).hexdigest()
    sha1 = hashlib.sha1(data).hexdigest()
    sha256 = hashlib.sha256(data).hexdigest()
    return md5, sha1, sha256


def iter_zip_members(
    data: bytes,
    *,
    max_members: int = MAX_ZIP_MEMBERS,
    max_total_uncompressed: int = MAX_UNCOMPRESSED_BYTES,
    max_member_uncompressed: int = MAX_MEMBER_UNCOMPRESSED,
    max_ratio: int = MAX_COMPRESSION_RATIO,
) -> list[SampleHashRecord]:
    """
    Extract member file hashes from a zip archive held fully in RAM.

    Skips directory entries and zero-length files. Raises ZipSafetyError on
    suspicious archives (zip bombs, traversal, too many members).
    """
    if not data:
        return []

    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile as exc:
        raise ZipSafetyError(f"invalid zip: {exc}") from exc

    records: list[SampleHashRecord] = []
    total_uncompressed = 0
    member_count = 0

    with zf:
        infos = [i for i in zf.infolist() if not i.is_dir()]
        if len(infos) > max_members:
            raise ZipSafetyError(f"too many zip members ({len(infos)} > {max_members})")

        for info in infos:
            inner = _safe_inner_path(info.filename)
            compressed = max(info.compress_size, 1)
            declared = info.file_size
            if declared > max_member_uncompressed:
                raise ZipSafetyError(
                    f"member {inner!r} declares {declared} bytes "
                    f"(max {max_member_uncompressed})"
                )
            if declared > 0 and declared / compressed > max_ratio:
                raise ZipSafetyError(f"compression ratio too high for {inner!r}")

            total_uncompressed += declared
            if total_uncompressed > max_total_uncompressed:
                raise ZipSafetyError(
                    f"total uncompressed size exceeds {max_total_uncompressed} bytes"
                )

            blob = zf.read(info.filename)
            if not blob:
                continue

            actual = len(blob)
            if actual > max_member_uncompressed:
                raise ZipSafetyError(f"member {inner!r} inflated to {actual} bytes")
            total_uncompressed = total_uncompressed - declared + actual
            if total_uncompressed > max_total_uncompressed:
                raise ZipSafetyError("total uncompressed size exceeded after read")

            md5, sha1, sha256 = _hashes_for_blob(blob)
            records.append(
                SampleHashRecord(
                    sha256=sha256,
                    md5=md5,
                    sha1=sha1,
                    inner_filename=inner,
                )
            )
            member_count += 1
            if member_count > max_members:
                raise ZipSafetyError(f"too many non-directory members (>{max_members})")

    return records


def hash_single_blob(data: bytes, *, inner_filename: str = "") -> SampleHashRecord:
    """Hash one raw file (non-archive sample)."""
    md5, sha1, sha256 = _hashes_for_blob(data)
    return SampleHashRecord(
        sha256=sha256,
        md5=md5,
        sha1=sha1,
        inner_filename=inner_filename or "(root)",
    )
