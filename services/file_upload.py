"""
Secure file upload handling for static malware analysis.
Files are never executed — analyzed in memory / temp and deleted immediately.
"""

from __future__ import annotations

import re
import tempfile
from pathlib import Path

from fastapi import UploadFile

ALLOWED_EXTENSIONS = frozenset({
    ".exe",
    ".apk",
    ".zip",
    ".pdf",
    ".doc",
    ".docx",
    ".xls",
    ".xlsx",
    ".ppt",
    ".pptx",
    ".rtf",
    ".dotm",
    ".xlsm",
})
_SAFE_NAME = re.compile(r"[^a-zA-Z0-9._-]")

_PE_MAGIC = b"MZ"
_APK_MAGIC = b"PK\x03\x04"
_PDF_MAGIC = b"%PDF"
_OLE_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"

_ZIP_EXTENSIONS = frozenset({".zip", ".docx", ".xlsx", ".pptx", ".xlsm", ".dotm", ".apk"})
_OFFICE_OLE_EXTENSIONS = frozenset({".doc", ".xls", ".ppt", ".rtf"})


class FileUploadError(ValueError):
    pass


def _sanitize_filename(name: str) -> str:
    base = Path(name).name
    cleaned = _SAFE_NAME.sub("_", base).strip("._")
    if not cleaned or cleaned.startswith("."):
        raise FileUploadError("Invalid filename")
    return cleaned[:128]


def _extension(name: str) -> str:
    ext = Path(name).suffix.lower()
    if ext not in ALLOWED_EXTENSIONS:
        raise FileUploadError(
            "Supported: .exe, .apk, .zip, .pdf, and Office (.doc, .docx, .xls, .xlsx, .ppt, .pptx, …)"
        )
    return ext


def _validate_magic(data: bytes, ext: str) -> None:
    if ext == ".exe":
        if not data.startswith(_PE_MAGIC):
            raise FileUploadError("File does not appear to be a valid PE executable")
        return
    if ext == ".pdf":
        if not data.startswith(_PDF_MAGIC):
            raise FileUploadError("File does not appear to be a valid PDF")
        return
    if ext in _OFFICE_OLE_EXTENSIONS:
        if not data.startswith(_OLE_MAGIC):
            raise FileUploadError("File does not appear to be a valid OLE Office document")
        return
    if ext in _ZIP_EXTENSIONS:
        if not data.startswith(_APK_MAGIC):
            raise FileUploadError("File does not appear to be a valid ZIP-based archive")
        return


async def read_upload_file(upload: UploadFile, max_bytes: int) -> tuple[bytes, str, str]:
    """
    Read upload with size cap. Returns (data, safe_filename, extension).
    """
    if not upload.filename:
        raise FileUploadError("No filename provided")

    safe_name = _sanitize_filename(upload.filename)
    ext = _extension(safe_name)

    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = await upload.read(1024 * 64)
        if not chunk:
            break
        total += len(chunk)
        if total > max_bytes:
            raise FileUploadError(f"File exceeds maximum size ({max_bytes // (1024 * 1024)} MB)")
        chunks.append(chunk)

    data = b"".join(chunks)
    if not data:
        raise FileUploadError("Empty file")

    _validate_magic(data, ext)

    return data, safe_name, ext


def write_temp_file(data: bytes, suffix: str) -> Path:
    """Write to a temp file for libraries that need a path. Caller must unlink."""
    fd = tempfile.NamedTemporaryFile(delete=False, suffix=suffix)
    try:
        fd.write(data)
        fd.flush()
        return Path(fd.name)
    finally:
        fd.close()
