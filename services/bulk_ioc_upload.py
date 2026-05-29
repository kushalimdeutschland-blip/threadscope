"""
Secure text-file upload for bulk IOC import (.txt, .csv, .list).
Files are never executed — read as UTF-8 text only.
"""

from __future__ import annotations

import csv
import io
import re
from pathlib import Path

from fastapi import UploadFile

from services.bulk_lookup import MAX_BULK_IOCS, parse_bulk_ioc_text
from services.file_upload import FileUploadError

ALLOWED_EXTENSIONS = frozenset({".txt", ".csv", ".list"})
MAX_BULK_IOC_FILE_BYTES = 256 * 1024
_MAX_REPLACEMENT_RATIO = 0.05
_HEADER_NAMES = frozenset({"value", "ioc", "indicator"})
_SAFE_NAME = re.compile(r"[^a-zA-Z0-9._-]")


def _sanitize_filename(name: str) -> str:
    base = Path(name).name
    cleaned = _SAFE_NAME.sub("_", base).strip("._")
    if not cleaned or cleaned.startswith("."):
        raise FileUploadError("Invalid filename")
    return cleaned[:128]


def _extension(name: str) -> str:
    ext = Path(name).suffix.lower()
    if ext not in ALLOWED_EXTENSIONS:
        raise FileUploadError("Supported bulk IOC files: .txt, .csv, .list")
    return ext


def _normalize_text(text: str) -> str:
    if text.startswith("\ufeff"):
        text = text.lstrip("\ufeff")
    return text.replace("\r\n", "\n").replace("\r", "\n")


def _decode_text(data: bytes) -> str:
    if not data:
        raise FileUploadError("Empty file")
    text = data.decode("utf-8", errors="replace")
    repl = text.count("\ufffd")
    if repl and repl / max(len(text), 1) > _MAX_REPLACEMENT_RATIO:
        raise FileUploadError("File does not appear to be valid UTF-8 text")
    text = _normalize_text(text)
    if not text.strip():
        raise FileUploadError("Empty file")
    return text


def _csv_to_line_text(text: str) -> str:
    reader = csv.reader(io.StringIO(text))
    rows = list(reader)
    if not rows:
        raise FileUploadError("Empty file")

    col_idx = 0
    start = 0
    header = [cell.strip().lower() for cell in rows[0]]
    for name in _HEADER_NAMES:
        if name in header:
            col_idx = header.index(name)
            start = 1
            break

    lines: list[str] = []
    for row in rows[start:]:
        if col_idx >= len(row):
            continue
        cell = row[col_idx].strip()
        if cell and not cell.startswith("#"):
            lines.append(cell)
    if not lines:
        raise FileUploadError("No IOCs found in CSV")
    return "\n".join(lines)


def parse_bulk_ioc_file(data: bytes, filename: str) -> list[str]:
    """
    Validate upload bytes and filename; return up to MAX_BULK_IOCS parsed tokens.
    """
    safe_name = _sanitize_filename(filename)
    ext = _extension(safe_name)

    if len(data) > MAX_BULK_IOC_FILE_BYTES:
        raise FileUploadError(
            f"File exceeds maximum size ({MAX_BULK_IOC_FILE_BYTES // 1024} KiB)"
        )

    text = _decode_text(data)
    if ext == ".csv":
        text = _csv_to_line_text(text)

    tokens = parse_bulk_ioc_text(text)
    if not tokens:
        raise FileUploadError("No IOCs found in file")
    return tokens


async def read_bulk_ioc_upload(upload: UploadFile) -> list[str]:
    """Read multipart upload with size cap; return parsed IOC tokens."""
    if not upload.filename:
        raise FileUploadError("No filename provided")

    safe_name = _sanitize_filename(upload.filename)
    _extension(safe_name)

    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = await upload.read(1024 * 64)
        if not chunk:
            break
        total += len(chunk)
        if total > MAX_BULK_IOC_FILE_BYTES:
            raise FileUploadError(
                f"File exceeds maximum size ({MAX_BULK_IOC_FILE_BYTES // 1024} KiB)"
            )
        chunks.append(chunk)

    data = b"".join(chunks)
    return parse_bulk_ioc_file(data, safe_name)
