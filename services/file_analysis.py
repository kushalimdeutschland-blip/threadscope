"""
Merge static file analysis with local hash intelligence DB.
"""

from __future__ import annotations

from typing import Any

import database
from services.lookup import verdict
from services.static_analysis import StaticAnalysisResult
from services.validation import sanitize_tags

def file_verdict(
    combined_score: int,
    *,
    in_database: bool,
    yara_match_count: int,
) -> str:
    """
    Score-based verdict with UNKNOWN when nothing in feeds or YARA matched.
    Avoids a green CLEAN on novel samples with weak static signal.
    """
    scored = verdict(combined_score)
    if scored != "CLEAN":
        return scored
    if in_database or yara_match_count > 0:
        return scored
    return "UNKNOWN"


async def build_file_threat_report(analysis: StaticAnalysisResult) -> dict[str, Any]:
    """Combine static analysis scores with local hash DB hits."""
    sha256 = analysis.hashes["sha256"]
    md5 = analysis.hashes["md5"]

    db_row = await database.get_indicator(sha256, "hash")
    if not db_row:
        db_row = await database.get_indicator(md5, "hash")

    db_score = db_row["risk_score"] if db_row else 0
    db_tags = sanitize_tags(db_row["tags"]) if db_row else []
    db_meta = db_row.get("meta") or {} if db_row else {}

    static_score = analysis.risk_score
    combined_score = max(static_score, db_score)
    if db_row and db_score >= 70:
        combined_score = max(combined_score, db_score)

    tags = list(dict.fromkeys(analysis.tags + db_tags))
    meta = {
        **analysis.meta,
        **db_meta,
        "hashes": analysis.hashes,
        "file_kind": analysis.file_kind,
        "size_bytes": analysis.size_bytes,
        "analysis_mode": "static",
    }

    findings = [
        {"severity": f.severity, "title": f.title, "detail": f.detail, "source": f.source}
        for f in analysis.findings
    ]
    if db_row and db_score >= 70:
        findings.insert(
            0,
            {
                "severity": "critical",
                "title": "Hash intelligence match",
                "detail": f"Listed in local feeds (score {db_score})",
                "source": "intel",
            },
        )

    threat: dict[str, Any] = {
        "value": analysis.filename,
        "type": "file",
        "file_kind": analysis.file_kind,
        "risk_score": combined_score,
        "tags": tags,
        "meta": meta,
        "hashes": analysis.hashes,
        "findings": findings,
        "last_updated": db_row["last_updated"] if db_row else None,
        "in_database": db_row is not None,
        "hash_db_match": sha256 if db_row and db_row["value"] == sha256 else (
            md5 if db_row and db_row["value"] == md5 else None
        ),
    }
    yara_hits = int(meta.get("yara_match_count") or 0)
    threat["verdict"] = file_verdict(
        combined_score,
        in_database=db_row is not None,
        yara_match_count=yara_hits,
    )
    return threat
