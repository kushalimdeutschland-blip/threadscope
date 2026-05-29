"""
Build plain-text reports matching ThreatScope result panels (clipboard export).
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any


def _section(title: str) -> str:
    return f"\n=== {title} ===\n"


def _lines(*parts: str) -> str:
    return "\n".join(p for p in parts if p)


def build_file_report_text(
    threat: dict[str, Any],
    summary: str,
    escalation: dict[str, Any] | None,
) -> str:
    meta = threat.get("meta") or {}
    hashes = threat.get("hashes") or {}
    verdict = threat.get("verdict", "")
    score = threat.get("risk_score", 0)
    parts = [
        "ThreatScope — File Analysis Report",
        f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
        _section("Overview"),
        f"Filename: {threat.get('value', '')}",
        f"Type: {threat.get('file_kind', meta.get('file_kind', ''))}",
        f"Verdict: {verdict}",
        f"Risk score: {score if verdict != 'UNKNOWN' else '—'}",
        f"Hash DB: {'Match' if threat.get('in_database') else 'No match'}",
        f"Analysis mode: {meta.get('analysis_mode', 'static')}",
    ]
    if meta.get("package"):
        parts.append(f"Package: {meta['package']}")
    if meta.get("app_name"):
        parts.append(f"App name: {meta['app_name']}")
    if meta.get("size_bytes"):
        parts.append(f"Size: {round(meta['size_bytes'] / 1024, 1)} KB")

    if hashes:
        parts.append(_section("Hashes"))
        for label in ("sha256", "sha1", "md5"):
            if hashes.get(label):
                parts.append(f"{label.upper()}: {hashes[label]}")

    if meta.get("permissions"):
        parts.append(_section("Permissions"))
        for perm in meta["permissions"][:20]:
            parts.append(f"  - {perm}")
        if len(meta["permissions"]) > 20:
            parts.append(f"  … and {len(meta['permissions']) - 20} more")

    if meta.get("embedded_urls"):
        parts.append(_section("Embedded URLs"))
        for url in meta["embedded_urls"][:15]:
            parts.append(f"  {url}")

    if meta.get("embedded_ips"):
        parts.append(_section("Embedded IPs"))
        parts.append(", ".join(meta["embedded_ips"][:15]))

    yara_matches = meta.get("yara_matches") or []
    if meta.get("yara_status"):
        parts.append(_section("YARA"))
        count = meta.get("yara_match_count", 0)
        if count:
            parts.append(f"Matches: {count} ({meta.get('yara_rules_loaded', '?')} rules loaded)")
            for m in yara_matches[:15]:
                if isinstance(m, dict):
                    rule = m.get("rule", "")
                    tags = m.get("tags")
                    line = f"  - {rule}"
                    if tags:
                        line += f" ({', '.join(tags) if isinstance(tags, list) else tags})"
                    parts.append(line)
        else:
            parts.append(f"No signature matches ({meta.get('yara_rules_loaded', '?')} rules loaded)")

    tags = threat.get("tags") or []
    if tags:
        parts.append(_section("Tags"))
        parts.append(", ".join(tags))

    findings = threat.get("findings") or []
    if findings:
        parts.append(_section("Findings"))
        for f in findings:
            if isinstance(f, dict):
                sev = f.get("severity", "")
                title = f.get("title", "")
                detail = f.get("detail", "")
                src = f.get("source", "")
                parts.append(f"  [{sev}] {title} ({src}): {detail}")

    if escalation:
        parts.append(_section("Next steps (manual lab)"))
        source = escalation.get("re_workflow_source", "static")
        if source == "ai":
            parts.append("RE workflow: Tailored to this sample (local Ollama)")
        else:
            parts.append(f"RE workflow: Generic workflow for {threat.get('file_kind', 'file')}")
        for i, step in enumerate(escalation.get("re_workflow") or [], 1):
            parts.append(f"  {i}. {step.get('title', '')} — {step.get('detail', '')}")
        cmds = escalation.get("suggested_commands") or []
        if cmds:
            parts.append("\nSuggested commands (isolated VM only):")
            for cmd in cmds:
                parts.append(f"  {cmd}")
        for hint in escalation.get("escalation_hints") or []:
            parts.append(f"  • {hint}")
        if escalation.get("copy_sample_path"):
            parts.append(f"\nSample path: {escalation['copy_sample_path']}")

    parts.append(_section("AI analyst summary"))
    parts.append(summary.strip())

    return _lines(*parts)


def build_indicator_report_text(
    threat: dict[str, Any],
    summary: str,
    escalation: dict[str, Any] | None,
) -> str:
    meta = threat.get("meta") or {}
    verdict = threat.get("verdict", "")
    parts = [
        "ThreatScope — Indicator Lookup Report",
        f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
        _section("Overview"),
        f"Indicator: {threat.get('value', '')}",
        f"Type: {threat.get('type', '')}",
        f"Verdict: {verdict}",
        f"Risk score: {threat.get('risk_score', 0) if verdict not in ('UNKNOWN',) else '—'}",
        f"Database: {'Match found' if threat.get('in_database') else 'No match'}",
        f"Feed status: {threat.get('freshness_status', '')}",
        f"Last seen: {threat.get('last_seen_label', '—')}",
    ]
    if meta.get("malware_family") or meta.get("category"):
        parts.append(f"Class: {meta.get('malware_family') or meta.get('category')}")

    if threat.get("type") == "phone":
        if meta.get("phone_display"):
            parts.append(f"Display: {meta['phone_display']}")
        if meta.get("phone_region"):
            parts.append(f"Region: {meta['phone_region']}")
        if meta.get("phone_intel"):
            parts.append(f"Phone intel: {meta['phone_intel']}")

    if threat.get("type") == "email":
        if meta.get("email_domain"):
            parts.append(f"Domain: {meta['email_domain']}")
        if meta.get("email_intel"):
            parts.append(f"Email intel: {meta['email_intel']}")

    enrichment = meta.get("enrichment") or {}
    if enrichment.get("geoip"):
        parts.append(_section("GeoIP"))
        geo = enrichment["geoip"]
        if isinstance(geo, dict):
            parts.append(
                _lines(
                    f"Country: {geo.get('country_name', '?')}",
                    f"ASN: {geo.get('asn', '')} {geo.get('asn_org', '')}".strip(),
                )
            )
        elif isinstance(geo, list):
            for g in geo[:5]:
                if isinstance(g, dict):
                    parts.append(
                        f"  {g.get('ip', '')} — {g.get('country_name', '?')} "
                        f"({g.get('asn_org', '')})"
                    )

    if enrichment.get("actor_hints"):
        parts.append(_section("Threat actor hints"))
        parts.append(", ".join(enrichment["actor_hints"]))

    active = threat.get("active_sources") or []
    if active:
        parts.append(_section("Active sources"))
        for src in active:
            if isinstance(src, dict):
                parts.append(f"  - {src.get('source', src)}")

    tags = threat.get("tags") or []
    if tags:
        parts.append(_section("Tags"))
        parts.append(", ".join(tags))

    lab_scan = meta.get("lab_scan")
    if lab_scan:
        parts.append(_section("Lab scan"))
        parts.append(f"Host up: {lab_scan.get('host_up', False)}")
        for port in (lab_scan.get("open_ports") or [])[:20]:
            if isinstance(port, dict):
                parts.append(
                    f"  {port.get('port')}/{port.get('protocol', 'tcp')} "
                    f"{port.get('service', '')}"
                )

    if escalation:
        parts.append(_section("Next steps (manual lab)"))
        for cmd in escalation.get("suggested_commands") or []:
            parts.append(f"  {cmd}")
        for hint in escalation.get("escalation_hints") or []:
            parts.append(f"  • {hint}")

    parts.append(_section("AI analyst summary"))
    parts.append(summary.strip())

    return _lines(*parts)


def build_bulk_report_text(rows: list[dict[str, Any]]) -> str:
    parts = [
        "ThreatScope — Bulk IOC Lookup Report",
        f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
        f"Indicators: {len(rows)} (max 50 per request)",
        _section("Results"),
        f"{'Input':<36} {'Type':<8} {'Verdict':<12} {'Score':>5}  DB",
        "-" * 72,
    ]
    for row in rows:
        inp = (row.get("value") or row.get("input") or "")[:34]
        itype = (row.get("type") or "—")[:6]
        if row.get("error"):
            verdict = "ERROR"
            score = "—"
        else:
            verdict = (row.get("verdict") or "—")[:10]
            rs = row.get("risk_score")
            score = str(rs) if rs is not None else "—"
        db = "yes" if row.get("in_database") else "no"
        parts.append(f"{inp:<36} {itype:<8} {verdict:<12} {score:>5}  {db}")
        if row.get("error"):
            parts.append(f"    Error: {row['error'][:60]}")

    return _lines(*parts)
