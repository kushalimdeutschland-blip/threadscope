"""Tests for email scam CSV feed parser."""

from __future__ import annotations

from services.feed_parser import parse_email_scam_csv


def test_parse_email_scam_csv() -> None:
    content = """email,score,tags,source
phish@evil.example,90,phishing;bec,HomelabExample
"""
    rows = parse_email_scam_csv(content)
    assert len(rows) == 1
    assert rows[0].type == "email"
    assert rows[0].value == "phish@evil.example"
    assert rows[0].risk_score == 90
    assert "phishing" in rows[0].tags
