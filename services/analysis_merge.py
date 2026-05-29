"""
Merge static file analysis with dynamic sandbox reports for UI and AI summaries.
"""

from __future__ import annotations

from typing import Any

from services.file_analysis import file_verdict
from services.sandbox.base import DynamicReport
from services.validation import sanitize_tags


def merge_dynamic_into_threat(
    threat: dict[str, Any],
    dynamic: DynamicReport,
) -> dict[str, Any]:
    """Combine static threat dict with normalized dynamic report."""
    merged = dict(threat)
    static_score = int(threat.get("risk_score") or 0)
    dynamic_score = int(dynamic.risk_score or 0)
    combined_score = max(static_score, dynamic_score)

    tags = list(dict.fromkeys(list(threat.get("tags") or []) + list(dynamic.tags)))
    findings = list(threat.get("findings") or [])

    for behavior in dynamic.behaviors[:8]:
        findings.append({
            "severity": "warning",
            "title": "Dynamic behavior",
            "detail": behavior,
            "source": "heuristic",
        })

    for ioc in dynamic.network_iocs[:6]:
        findings.append({
            "severity": "info",
            "title": "Network IOC",
            "detail": ioc,
        })

    for sig in dynamic.signatures[:5]:
        findings.append({
            "severity": "warning",
            "title": "Sandbox signature",
            "detail": sig,
        })

    meta = dict(threat.get("meta") or {})
    meta["analysis_mode"] = "static+dynamic"
    meta["sandbox_backend"] = dynamic.backend
    meta["dynamic_summary"] = dynamic.summary
    if dynamic.dropped_files:
        meta["dropped_files"] = dynamic.dropped_files[:10]

    yara_hits = int(meta.get("yara_match_count") or 0)
    in_db = bool(threat.get("in_database"))
    merged.update({
        "risk_score": combined_score,
        "tags": sanitize_tags(tags),
        "findings": findings,
        "meta": meta,
        "dynamic": dynamic.to_dict(),
        "verdict": file_verdict(
            combined_score,
            in_database=in_db,
            yara_match_count=yara_hits,
        ),
    })
    return merged
