"""
Static analysis for PE (.exe) and APK (.apk) files.
No execution — parse-only inspection. Optional dynamic analysis runs via scripts/sandbox_worker.py.
"""

from __future__ import annotations

import hashlib
import math
import re
import zipfile
from dataclasses import dataclass, field
from io import BytesIO
from pathlib import Path
from typing import Any

# ── PE suspicious indicators ──────────────────────────────────────────────

_SUSPICIOUS_IMPORTS = frozenset({
    "VirtualAlloc", "VirtualAllocEx", "VirtualProtect", "WriteProcessMemory",
    "ReadProcessMemory", "CreateRemoteThread", "NtCreateThreadEx",
    "URLDownloadToFileA", "URLDownloadToFileW", "WinExec", "ShellExecuteA",
    "ShellExecuteW", "InternetOpenA", "InternetOpenUrlA", "HttpSendRequestA",
    "RegSetValueExA", "RegCreateKeyExA", "CryptEncrypt", "CryptDecrypt",
    "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "GetAsyncKeyState",
})

_HIGH_ENTROPY = 7.2

# ── APK dangerous permissions ─────────────────────────────────────────────

_DANGEROUS_PERMISSIONS = frozenset({
    "android.permission.SEND_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.READ_SMS",
    "android.permission.RECEIVE_BOOT_COMPLETED",
    "android.permission.READ_CONTACTS",
    "android.permission.WRITE_CONTACTS",
    "android.permission.RECORD_AUDIO",
    "android.permission.CAMERA",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_BACKGROUND_LOCATION",
    "android.permission.READ_CALL_LOG",
    "android.permission.CALL_PHONE",
    "android.permission.PROCESS_OUTGOING_CALLS",
    "android.permission.REQUEST_INSTALL_PACKAGES",
    "android.permission.SYSTEM_ALERT_WINDOW",
    "android.permission.BIND_DEVICE_ADMIN",
    "android.permission.READ_PHONE_STATE",
    "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.REQUEST_DELETE_PACKAGES",
})

_URL_RE = re.compile(r"https?://[a-zA-Z0-9._~:/?#\[\]@!$&'()*+,;=%-]{4,}", re.I)
_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_PHONE_IN_TEXT_RE = re.compile(r"(?:\+?\d[\d\s().\-]{6,}\d)")
_EMAIL_IN_TEXT_RE = re.compile(
    r"[a-z0-9._%+\-]+@[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+",
    re.IGNORECASE,
)
_STRING_RE = re.compile(rb"[\x20-\x7e]{6,}")


@dataclass
class StaticFinding:
    severity: str  # info | warning | critical
    title: str
    detail: str
    source: str = "heuristic"  # heuristic | signature | intel


@dataclass
class StaticAnalysisResult:
    file_kind: str
    filename: str
    size_bytes: int
    hashes: dict[str, str]
    findings: list[StaticFinding] = field(default_factory=list)
    meta: dict[str, Any] = field(default_factory=dict)
    risk_score: int = 0
    tags: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "file_kind": self.file_kind,
            "filename": self.filename,
            "size_bytes": self.size_bytes,
            "hashes": self.hashes,
            "findings": [
                {
                    "severity": f.severity,
                    "title": f.title,
                    "detail": f.detail,
                    "source": f.source,
                }
                for f in self.findings
            ],
            "meta": self.meta,
            "risk_score": self.risk_score,
            "tags": self.tags,
        }


def compute_hashes(data: bytes) -> dict[str, str]:
    return {
        "md5": hashlib.md5(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    length = len(data)
    return -sum(
        (c / length) * math.log2(c / length)
        for c in freq if c
    )


def _extract_strings(data: bytes, limit: int = 500) -> list[str]:
    found: list[str] = []
    for match in _STRING_RE.finditer(data[:8 * 1024 * 1024]):
        s = match.group().decode("ascii", errors="ignore")
        if len(s) >= 6:
            found.append(s)
        if len(found) >= limit:
            break
    return found


def _extract_phone_numbers(strings: list[str], limit: int = 8) -> list[str]:
    from services.validation import validate_phone

    phones: list[str] = []
    seen: set[str] = set()
    for s in strings:
        for match in _PHONE_IN_TEXT_RE.finditer(s):
            raw = match.group().strip()
            try:
                e164 = validate_phone(raw)
            except ValueError:
                continue
            if e164 not in seen:
                seen.add(e164)
                phones.append(e164)
            if len(phones) >= limit:
                return phones
    return phones


def _extract_emails(strings: list[str], limit: int = 8) -> list[str]:
    from services.validation import validate_email

    emails: list[str] = []
    seen: set[str] = set()
    for s in strings:
        for match in _EMAIL_IN_TEXT_RE.finditer(s):
            raw = match.group().strip()
            try:
                normalized = validate_email(raw)
            except ValueError:
                continue
            if normalized not in seen:
                seen.add(normalized)
                emails.append(normalized)
            if len(emails) >= limit:
                return emails
    return emails


def _append_email_findings(result: StaticAnalysisResult, strings: list[str]) -> None:
    emails = _extract_emails(strings)
    if not emails:
        return
    result.meta["email_addresses"] = emails
    preview = ", ".join(emails[:4])
    if len(emails) > 4:
        preview += f" (+{len(emails) - 4} more)"
    result.findings.append(StaticFinding(
        "info",
        "Email addresses in file",
        preview,
        source="heuristic",
    ))


def _append_phone_findings(result: StaticAnalysisResult, strings: list[str]) -> None:
    phones = _extract_phone_numbers(strings)
    if not phones:
        return
    result.meta["phone_numbers"] = phones
    preview = ", ".join(phones[:4])
    if len(phones) > 4:
        preview += f" (+{len(phones) - 4} more)"
    result.findings.append(StaticFinding(
        "info",
        "Phone numbers in file",
        preview,
        source="heuristic",
    ))


def _score_from_findings(findings: list[StaticFinding]) -> int:
    score = 0
    for f in findings:
        if f.severity == "critical":
            score += 25
        elif f.severity == "warning":
            score += 12
        elif f.severity == "info":
            score += 3
    return min(100, score)


def analyze_bytes(data: bytes, filename: str, ext: str) -> StaticAnalysisResult:
    ext = ext.lower()
    if ext == ".exe":
        result = analyze_pe(data, filename)
    elif ext == ".apk":
        result = analyze_apk(data, filename)
    elif ext == ".zip":
        from services.static_documents import analyze_zip
        result = analyze_zip(data, filename)
    elif ext == ".pdf":
        from services.static_documents import analyze_pdf
        result = analyze_pdf(data, filename)
    elif ext in {
        ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".rtf", ".dotm", ".xlsm",
    }:
        from services.static_documents import analyze_office
        result = analyze_office(data, filename, ext)
    else:
        raise ValueError("Unsupported file type")

    from services.yara_scan import apply_yara_to_result

    apply_yara_to_result(result, data)
    return result


def analyze_pe(data: bytes, filename: str) -> StaticAnalysisResult:
    import pefile

    hashes = compute_hashes(data)
    result = StaticAnalysisResult(
        file_kind="exe",
        filename=filename,
        size_bytes=len(data),
        hashes=hashes,
    )

    try:
        pe = pefile.PE(data=data, fast_load=True)
    except pefile.PEFormatError as exc:
        result.findings.append(StaticFinding("critical", "Invalid PE", str(exc)))
        result.risk_score = 80
        result.tags.append("Corrupt PE")
        return result

    pe.parse_data_directories(
        directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]]
    )

    result.meta["machine"] = hex(pe.FILE_HEADER.Machine)
    if pe.FILE_HEADER.TimeDateStamp:
        result.meta["compile_timestamp"] = pe.FILE_HEADER.TimeDateStamp

    # Sections & entropy
    high_entropy_sections: list[str] = []
    for section in pe.sections:
        name = section.Name.decode("utf-8", errors="ignore").strip("\x00")
        ent = _entropy(section.get_data())
        if ent >= _HIGH_ENTROPY:
            high_entropy_sections.append(f"{name} ({ent:.2f})")

    if high_entropy_sections:
        result.findings.append(StaticFinding(
            "warning",
            "High-entropy sections",
            "May indicate packing or encryption: " + ", ".join(high_entropy_sections[:4]),
        ))
        result.tags.append("Possible Packer")

    # Imports
    suspicious_hits: list[str] = []
    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll = entry.dll.decode("utf-8", errors="ignore")
            for imp in entry.imports:
                if imp.name:
                    name = imp.name.decode("utf-8", errors="ignore")
                    if name in _SUSPICIOUS_IMPORTS:
                        suspicious_hits.append(f"{name} ({dll})")

    if suspicious_hits:
        result.findings.append(StaticFinding(
            "critical",
            "Suspicious API imports",
            "; ".join(suspicious_hits[:8]),
        ))
        result.tags.append("Suspicious Imports")

    # Strings — URLs and IPs embedded in binary
    strings = _extract_strings(data, limit=300)
    urls = list(dict.fromkeys(u for s in strings for u in _URL_RE.findall(s)))[:10]
    ips = list(dict.fromkeys(i for s in strings for i in _IP_RE.findall(s)))[:10]

    if urls:
        result.meta["embedded_urls"] = urls
        result.findings.append(StaticFinding(
            "warning",
            "Embedded URLs",
            ", ".join(urls[:5]),
        ))
        result.tags.append("Network IOCs")

    if ips:
        result.meta["embedded_ips"] = ips
        result.findings.append(StaticFinding(
            "info",
            "Embedded IP addresses",
            ", ".join(ips[:5]),
        ))

    _append_phone_findings(result, strings)
    _append_email_findings(result, strings)

    if len(strings) < 20 and len(data) > 50_000:
        result.findings.append(StaticFinding(
            "warning",
            "Few readable strings",
            "Large binary with very few strings — may be packed.",
        ))

    result.risk_score = _score_from_findings(result.findings)
    if not result.tags and result.risk_score < 20:
        result.findings.append(StaticFinding(
            "info",
            "Static scan complete",
            "No major suspicious indicators detected in PE structure.",
        ))
    return result


def analyze_apk(data: bytes, filename: str) -> StaticAnalysisResult:
    hashes = compute_hashes(data)
    result = StaticAnalysisResult(
        file_kind="apk",
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
                raise ValueError("APK uncompressed size exceeds safety limit")

            names = [i.filename for i in entries]
            result.meta["file_count"] = len(names)

            if "AndroidManifest.xml" not in names:
                result.findings.append(StaticFinding("critical", "Missing manifest", "No AndroidManifest.xml"))
            if not any(n.endswith("classes.dex") for n in names):
                result.findings.append(StaticFinding("warning", "Missing DEX", "No classes.dex found"))

            native_libs = [n for n in names if n.startswith("lib/") and n.endswith(".so")]
            if native_libs:
                result.meta["native_libs"] = native_libs[:10]
                result.findings.append(StaticFinding(
                    "info",
                    "Native libraries",
                    f"{len(native_libs)} native .so file(s) present",
                ))

            # Try androguard for rich manifest parsing when available
            if _analyze_apk_androguard(data, result):
                pass
            else:
                _analyze_apk_fallback(data, names, result)

    except zipfile.BadZipFile:
        result.findings.append(StaticFinding("critical", "Invalid APK", "Not a valid ZIP/APK archive"))
        result.risk_score = 90
        result.tags.append("Invalid APK")
        return result
    except ValueError as exc:
        result.findings.append(StaticFinding("critical", "Rejected", str(exc)))
        result.risk_score = 90
        return result

    result.risk_score = max(result.risk_score, _score_from_findings(result.findings))
    return result


def _analyze_apk_androguard(data: bytes, result: StaticAnalysisResult) -> bool:
    try:
        from androguard.core.apk import APK
    except ImportError:
        return False

    import tempfile
    import os

    path = None
    try:
        fd, path = tempfile.mkstemp(suffix=".apk")
        os.write(fd, data)
        os.close(fd)
        apk = APK(path)
        result.meta["package"] = apk.get_package()
        result.meta["app_name"] = apk.get_app_name()
        result.meta["min_sdk"] = apk.get_min_sdk_version()
        result.meta["target_sdk"] = apk.get_target_sdk_version()
        result.meta["androidversion"] = apk.get_androidversion_name()

        perms = apk.get_permissions()
        result.meta["permissions"] = perms
        dangerous = [p for p in perms if p in _DANGEROUS_PERMISSIONS]
        if dangerous:
            result.findings.append(StaticFinding(
                "critical",
                "Dangerous permissions",
                ", ".join(dangerous[:8]),
            ))
            result.tags.append("Dangerous Permissions")

        activities = apk.get_activities()
        result.meta["activity_count"] = len(activities)
        return True
    except Exception:
        return False
    finally:
        if path:
            try:
                os.unlink(path)
            except OSError:
                pass


def _analyze_apk_fallback(data: bytes, names: list[str], result: StaticAnalysisResult) -> None:
    """Permission/IOC scan without androguard — searches raw APK bytes."""
    raw = data[:16 * 1024 * 1024]
    found_perms = [p for p in _DANGEROUS_PERMISSIONS if p.encode() in raw]
    if found_perms:
        result.meta["permissions"] = found_perms
        result.findings.append(StaticFinding(
            "critical",
            "Dangerous permissions (raw scan)",
            ", ".join(found_perms[:8]),
        ))
        result.tags.append("Dangerous Permissions")

    strings = _extract_strings(raw, limit=400)
    urls = list(dict.fromkeys(u for s in strings for u in _URL_RE.findall(s)))[:10]
    if urls:
        result.meta["embedded_urls"] = urls
        result.findings.append(StaticFinding(
            "warning",
            "Embedded URLs",
            ", ".join(urls[:5]),
        ))
        result.tags.append("Network IOCs")

    _append_phone_findings(result, strings)
    _append_email_findings(result, strings)

    dex_count = sum(1 for n in names if n.endswith(".dex"))
    result.meta["dex_count"] = dex_count
    if dex_count > 1:
        result.findings.append(StaticFinding(
            "info",
            "Multiple DEX files",
            f"{dex_count} DEX files — common in larger apps",
        ))

    result.findings.append(StaticFinding(
        "info",
        "Analysis mode",
        "Basic static scan (install androguard for deeper APK manifest parsing)",
    ))


def analyze_file_path(path: Path, filename: str, ext: str) -> StaticAnalysisResult:
    data = path.read_bytes()
    return analyze_bytes(data, filename, ext)
