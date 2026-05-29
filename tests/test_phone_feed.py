"""Tests for phone scam CSV feed parser."""

from __future__ import annotations

from services.feed_parser import parse_phone_scam_csv


def test_parse_phone_scam_csv() -> None:
    content = """phone,score,tags,source
+18005551234,90,scam;robocall,Homelab
(555) 987-6543,75,spam,Local
"""
    rows = parse_phone_scam_csv(content)
    assert len(rows) == 2
    assert rows[0].type == "phone"
    assert rows[0].value == "+18005551234"
    assert rows[0].risk_score == 90
    assert "scam" in rows[0].tags
