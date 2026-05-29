"""
Export malicious indicators from SQLite as blocklist CSV for lab firewalls / hosts files.
"""

from __future__ import annotations

import csv
import io
from typing import Literal

import database

IndicatorExportType = Literal["ipv4", "ipv6", "domain", "hash", "phone", "email", "all"]


async def export_blocklist_csv(
    *,
    min_score: int = 70,
    indicator_type: IndicatorExportType = "all",
    limit: int = 50_000,
) -> str:
    rows = await database.list_indicators_for_export(
        min_score=min_score,
        indicator_type=indicator_type,
        limit=limit,
    )
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["value", "type", "risk_score", "tags", "last_updated"])
    for row in rows:
        tags = row.get("tags") or []
        writer.writerow([
            row["value"],
            row["type"],
            row["risk_score"],
            ";".join(tags) if isinstance(tags, list) else tags,
            row.get("last_updated", ""),
        ])
    return buf.getvalue()
