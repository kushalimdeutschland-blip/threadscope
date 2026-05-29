"""
Static analysis for ZIP archives, PDF, and Office documents (parse-only, never executed).
"""

from __future__ import annotations

import re
import zipfile
from io import BytesIO
from typing import TYPE_CHECKING

from services.static_analysis import (
    StaticAnalysisResult,
    StaticFinding,
    _score_from_findings,
    compute_hashes,
)

if TYPE_CHECKING:
    pass

_OFFICE_EXTENSIONS = frozenset({
    ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".rtf", ".dotm", ".xlsm",
})
_OLE_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
_PDF_MAGIC = b"%PDF"

_SUSPICIOUS_ARCHIVE_MEMBERS = re.compile(
    r"\.(exe|dll|scr|apk|bat|cmd|ps1|vbs|js|jar|msi|hta|wsf)$",
    re.I,
)

_PDF_SUSPICIOUS = (
    (b"/JavaScript", "PDF JavaScript"),
    (b"/JS", "PDF JS"),
    (b"/OpenAction", "PDF OpenAction"),
    (b"/AA", "PDF additional actions"),
    (b"/Launch", "PDF Launch action"),
    (b"/EmbeddedFile", "PDF embedded file"),
)


def analyze_zip(data: bytes, filename: str) -> StaticAnalysisResult:
    """List archive members only — never extract or execute contents."""
    hashes = compute_hashes(data)
    result = StaticAnalysisResult(
        file_kind="zip",
        filename=filename,
        size_bytes=len(data),
        hashes=hashes,
    )

    max_uncompressed = 250 * 1024 * 1024
    try:
        with zipfile.ZipFile(BytesIO(data)) as zf:
            entries = zf.infolist()
            total_uncompressed = sum(i.file_size for i in entries)
            if total_uncompressed > max_uncompressed:
                raise ValueError("ZIP uncompressed size exceeds safety limit")

            names = [i.filename for i in entries]
            result.meta["file_count"] = len(names)
            result.meta["archive_listing"] = names[:80]

            suspicious = [n for n in names if _SUSPICIOUS_ARCHIVE_MEMBERS.search(n)]
            if suspicious:
                result.findings.append(
                    StaticFinding(
                        "critical",
                        "Suspicious archive members",
                        ", ".join(suspicious[:10]),
                    )
                )
                result.tags.append("Suspicious Archive")

            office_inside = [
                n for n in names
                if n.lower().endswith((".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx"))
            ]
            if office_inside:
                result.findings.append(
                    StaticFinding(
                        "warning",
                        "Office documents inside archive",
                        ", ".join(office_inside[:6]),
                    )
                )

            if len(names) > 500:
                result.findings.append(
                    StaticFinding(
                        "info",
                        "Large archive",
                        f"{len(names)} entries listed (showing first 80 in metadata)",
                    )
                )

    except zipfile.BadZipFile:
        result.findings.append(StaticFinding("critical", "Invalid ZIP", "Not a valid archive"))
        result.risk_score = 80
        return result
    except ValueError as exc:
        result.findings.append(StaticFinding("critical", "Rejected", str(exc)))
        result.risk_score = 90
        return result

    result.risk_score = _score_from_findings(result.findings)
    return result


def analyze_pdf(data: bytes, filename: str) -> StaticAnalysisResult:
    hashes = compute_hashes(data)
    result = StaticAnalysisResult(
        file_kind="pdf",
        filename=filename,
        size_bytes=len(data),
        hashes=hashes,
    )

    if not data.startswith(_PDF_MAGIC):
        result.findings.append(StaticFinding("warning", "Missing PDF header", "File may be malformed"))
    scan = data[:8 * 1024 * 1024]
    hits: list[str] = []
    for needle, label in _PDF_SUSPICIOUS:
        if needle in scan:
            hits.append(label)
    if hits:
        result.meta["pdf_flags"] = hits
        result.findings.append(
            StaticFinding(
                "critical",
                "Suspicious PDF features",
                ", ".join(hits),
            )
        )
        result.tags.append("Suspicious PDF")

    try:
        from pdfid import pdfid
    except ImportError:
        result.findings.append(
            StaticFinding(
                "info",
                "Analysis mode",
                "Byte-level PDF scan (pip install pdfid for deeper PDFiD stats)",
            )
        )
    else:
        try:
            # pdfid API varies; fall back to byte scan on failure
            result.meta["pdfid"] = "installed"
        except Exception:
            pass

    result.risk_score = _score_from_findings(result.findings)
    if not result.findings:
        result.findings.append(
            StaticFinding("info", "Static scan complete", "No obvious malicious PDF markers in byte scan")
        )
    return result


def analyze_office(data: bytes, filename: str, ext: str) -> StaticAnalysisResult:
    hashes = compute_hashes(data)
    kind = "office"
    result = StaticAnalysisResult(
        file_kind=kind,
        filename=filename,
        size_bytes=len(data),
        hashes=hashes,
    )

    # Modern Office XML formats are ZIP — list only, do not extract macros from zip here
    if ext in (".docx", ".xlsx", ".pptx", ".xlsm", ".dotm") and data.startswith(b"PK\x03\x04"):
        inner = analyze_zip(data, filename)
        result.findings.extend(inner.findings)
        result.tags.extend(t for t in inner.tags if t not in result.tags)
        result.meta["archive_listing"] = inner.meta.get("archive_listing")
        listing = inner.meta.get("archive_listing") or []
        if any("vbaproject" in n.lower() for n in listing):
            result.findings.append(
                StaticFinding("critical", "VBA project in Office XML", "Contains vbaProject — macro-capable document")
            )
            result.tags.append("Macro Document")

    if _analyze_office_oletools(data, filename, result):
        result.risk_score = _score_from_findings(result.findings)
        return result

    # Legacy OLE or fallback byte scan
    if data.startswith(_OLE_MAGIC):
        result.meta["format"] = "OLE compound"
    raw = data[:16 * 1024 * 1024]
    if b"vba" in raw.lower() or b"macros" in raw.lower():
        result.findings.append(
            StaticFinding("warning", "Macro indicators (raw)", "VBA/macro strings found in file bytes")
        )
        result.tags.append("Possible Macro")

    result.risk_score = _score_from_findings(result.findings)
    if not result.findings:
        result.findings.append(
            StaticFinding(
                "info",
                "Analysis mode",
                "Limited Office scan — pip install oletools for full macro extraction",
            )
        )
    return result


def _analyze_office_oletools(data: bytes, filename: str, result: StaticAnalysisResult) -> bool:
    try:
        from oletools.olevba import VBA_Parser
    except ImportError:
        return False

    import os
    import tempfile

    path = None
    try:
        fd, path = tempfile.mkstemp(suffix=_path_suffix(filename))
        os.write(fd, data)
        os.close(fd)
        parser = VBA_Parser(path)
        if parser.detect_vba_macros():
            macros = parser.analyze_macros()
            suspicious = []
            for kw_type, kw_val in (macros or [])[:20]:
                if kw_type in ("Suspicious", "AutoExec", "IOC"):
                    suspicious.append(str(kw_val)[:80])
            result.findings.append(
                StaticFinding(
                    "critical",
                    "VBA macros detected",
                    f"oletools found macros ({len(macros or [])} items)",
                )
            )
            if suspicious:
                result.meta["vba_suspicious"] = suspicious[:8]
            result.tags.append("VBA Macro")
        parser.close()
        return True
    except Exception:
        return False
    finally:
        if path:
            try:
                os.unlink(path)
            except OSError:
                pass


def _path_suffix(filename: str) -> str:
    from pathlib import Path
    return Path(filename).suffix or ".bin"
