"""
Build pentester escalation hints for result templates (copy targets + suggested CLI).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from config import get_settings
from services.sample_store import sample_path_for_hash

settings = get_settings()


def _re_workflow_for_kind(file_kind: str) -> list[dict[str, str]]:
    """Numbered RE workflow steps for manual lab triage (display only)."""
    common_verify = {
        "title": "Verify sample identity",
        "detail": "Confirm SHA256 matches the uploaded file before copying to a lab VM.",
    }
    if file_kind == "exe":
        return [
            common_verify,
            {
                "title": "Static triage",
                "detail": "Run strings and local YARA; note imports, sections, and entropy with PE tools.",
            },
            {
                "title": "Disassembly / decompile",
                "detail": "Load in Ghidra or IDA; map entry points, suspicious API calls, and packed sections.",
            },
            {
                "title": "Capability & string analysis",
                "detail": "Optional: FLOSS for obfuscated strings, capa for MITRE-aligned behavior rules.",
            },
            {
                "title": "Dynamic analysis (optional)",
                "detail": "CAPE/KVM if available; homelab default is static + YARA only.",
            },
        ]
    if file_kind == "apk":
        return [
            common_verify,
            {
                "title": "Decode & decompile",
                "detail": "Use jadx or apktool to recover manifest, smali, and Java/Kotlin sources.",
            },
            {
                "title": "Manifest review",
                "detail": "Inspect permissions, exported components, deep links, and certificate metadata.",
            },
            {
                "title": "Static YARA",
                "detail": "Scan APK bytes with local rules; correlate with embedded URLs/IPs from static report.",
            },
            {
                "title": "Dynamic analysis (optional)",
                "detail": "Enable MobSF on upload, then run python scripts/sandbox_worker.py on an isolated host.",
            },
        ]
    if file_kind == "pdf":
        return [
            common_verify,
            {
                "title": "PDF structure check",
                "detail": "Run pdfid for suspicious features (JS, launch actions, embedded files).",
            },
            {
                "title": "Extract strings & URLs",
                "detail": "Search strings output for C2, phishing lures, and embedded file markers.",
            },
        ]
    if file_kind == "zip":
        return [
            common_verify,
            {
                "title": "List contents only",
                "detail": "Use unzip -l — never extract blindly; treat nested executables as untrusted.",
            },
            {
                "title": "Identify embedded objects",
                "detail": "binwalk in list/identify mode only; manually inspect suspicious members in isolation.",
            },
        ]
    if file_kind == "office":
        return [
            common_verify,
            {
                "title": "OLE structure check",
                "detail": "Run oleid to detect macros, encryption, and external relationships.",
            },
            {
                "title": "Macro extraction",
                "detail": "If macros present, use olevba on an isolated VM; do not enable editing on host.",
            },
        ]
    return [
        common_verify,
        {
            "title": "Static triage",
            "detail": "Run strings and YARA; inspect file type and embedded indicators.",
        },
        {
            "title": "Manual RE",
            "detail": "Use appropriate tooling for the format on an isolated VM.",
        },
    ]


def _suggested_commands_for_kind(
    file_kind: str,
    path_str: str,
    sha256: str,
) -> list[str]:
    """Display-only CLI suggestions; prefix with # when unsafe to run blindly."""
    commands: list[str] = []
    if not path_str:
        return commands

    commands.append(f"sha256sum '{path_str}'")
    commands.append(f"strings '{path_str}' | less")
    if sha256:
        commands.append(f"yara -s data/yara_rules/*.yar '{path_str}'")

    if file_kind == "exe":
        commands.append(f"file '{path_str}'")
        commands.append(f"# pefile / readpe / objdump -x '{path_str}'  # PE headers, imports, sections")
        commands.append(f"# Ghidra GUI or headless: analyze '{path_str}'")
        commands.append(f"# floss '{path_str}'  # extract obfuscated strings")
        commands.append(f"# capa '{path_str}'   # MITRE-aligned capability rules")
    elif file_kind == "apk":
        commands.append(f"# jadx-gui '{path_str}'  # or: jadx -d out/ '{path_str}'")
        commands.append(f"# apktool d '{path_str}' -o apktool_out/")
        commands.append(f"# aapt dump badging '{path_str}'")
    elif file_kind == "pdf":
        commands.append(f"pdfid '{path_str}'")
    elif file_kind == "zip":
        commands.append(f"unzip -l '{path_str}'  # list only — do not extract blindly")
        commands.append(f"binwalk '{path_str}'  # identify/list only — never auto-extract")
    elif file_kind == "office":
        commands.append(f"# oleid '{path_str}'")
        commands.append(f"# olevba '{path_str}'")

    return commands


def file_escalation_context(
    threat: dict[str, Any],
    *,
    sample_path: Path | str | None = None,
) -> dict[str, Any]:
    """Template context for file_result escalation panel."""
    verdict = threat.get("verdict", "")
    if verdict not in ("MALICIOUS", "SUSPICIOUS", "UNKNOWN"):
        return {}

    hashes = threat.get("hashes") or {}
    sha256 = hashes.get("sha256", "")
    meta = threat.get("meta") or {}
    file_kind = threat.get("file_kind") or meta.get("file_kind") or "file"

    if sample_path is None and sha256:
        try:
            sample_path = sample_path_for_hash(sha256)
        except ValueError:
            sample_path = None

    path_str = str(sample_path) if sample_path else ""

    commands = _suggested_commands_for_kind(file_kind, path_str, sha256)
    re_workflow = _re_workflow_for_kind(file_kind)

    hints: list[str] = []
    if file_kind == "apk":
        hints.append("APK dynamic: enable MobSF on upload, run python scripts/sandbox_worker.py")
    elif file_kind == "exe":
        hints.append("EXE dynamic requires KVM + CAPE; homelab default is static + YARA only")
    elif file_kind == "zip":
        hints.append("Never auto-extract archives from unknown sources on your main workstation")
    elif file_kind == "office":
        hints.append("Disable macros; analyze OLE/macro artifacts only on an isolated VM")
    if verdict == "UNKNOWN":
        hints.append("No feed/YARA hit — treat as untrusted until manual RE on an isolated VM")

    return {
        "verdict": verdict,
        "copy_sha256": sha256 or None,
        "copy_sample_path": path_str or None,
        "suggested_commands": commands,
        "escalation_hints": hints,
        "re_workflow": re_workflow,
    }


def indicator_escalation_context(threat: dict[str, Any]) -> dict[str, Any]:
    """Template context for indicator lookup escalation panel."""
    verdict = threat.get("verdict", "")
    if verdict not in ("MALICIOUS", "SUSPICIOUS", "UNKNOWN", "STALE"):
        return {}

    value = threat.get("value", "")
    itype = threat.get("type", "")
    meta = threat.get("meta") or {}
    commands: list[str] = []
    hints: list[str] = []

    if itype in ("ipv4", "ipv6"):
        if settings.lab_scan_enabled:
            hints.append("Use the Run lab scan button above for in-app nmap (requires scan_worker.py)")
        else:
            commands.append(f"nmap -sV --top-ports 100 {value}")
            commands.append(f"curl -m 5 -I http://{value}/ 2>/dev/null | head")
            hints.append("Test from an isolated lab VM — never from your main workstation without intent")
    elif itype == "domain":
        if settings.lab_scan_enabled:
            hints.append("Use the Run lab scan button above to resolve and nmap the host")
        else:
            commands.append(f"dig +short {value}")
            commands.append(f"curl -m 5 -I https://{value}/ 2>/dev/null | head")
            hints.append("Consider passive DNS and phishing kit checks if domain is suspicious")
    elif itype == "hash":
        commands.append(f"# Search MalwareBazaar / local DB already done; hunt sample by hash in lab")
        hints.append("If you obtain the file, upload it on the File tab for YARA + static analysis")
    elif itype == "phone":
        hints.append("Search local phone scam feed; enable PHONE_LOOKUP_ENABLED for optional carrier lookup")
    elif itype == "email":
        domain = (meta or {}).get("email_domain") or (value.split("@")[-1] if "@" in value else value)
        commands.append(f"dig +short MX {domain}")
        hints.append("Search local email_scam feed; passive MX/DNS is local; EMAIL_LOOKUP_ENABLED sends address to third party")

    if verdict == "STALE":
        hints.insert(0, "Intel is stale — re-verify with live queries before blocking production traffic")

    return {
        "verdict": verdict,
        "copy_value": value or None,
        "suggested_commands": commands,
        "escalation_hints": hints,
    }
