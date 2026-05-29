"""Tests for plain-text report export."""

from services.report_export import (
    build_bulk_report_text,
    build_file_report_text,
    build_indicator_report_text,
)


def test_build_file_report_text():
    threat = {
        "value": "malware.exe",
        "file_kind": "exe",
        "verdict": "MALICIOUS",
        "risk_score": 85,
        "in_database": True,
        "hashes": {"sha256": "a" * 64},
        "findings": [{"severity": "critical", "title": "YARA hit", "detail": "Emotet", "source": "signature"}],
        "meta": {"yara_match_count": 1, "yara_status": "ok"},
        "tags": ["trojan"],
    }
    escalation = {
        "re_workflow_source": "static",
        "re_workflow": [{"title": "Disassemble", "detail": "Open in Ghidra"}],
        "suggested_commands": ["strings 'sample'"],
        "escalation_hints": ["Use isolated VM"],
        "copy_sample_path": "/tmp/sample",
    }
    text = build_file_report_text(threat, "AI summary here.", escalation)
    assert "malware.exe" in text
    assert "MALICIOUS" in text
    assert "SHA256" in text
    assert "YARA hit" in text
    assert "Disassemble" in text
    assert "AI summary here." in text


def test_build_indicator_report_text():
    threat = {
        "value": "1.2.3.4",
        "type": "ipv4",
        "verdict": "MALICIOUS",
        "risk_score": 90,
        "in_database": True,
        "freshness_status": "active",
        "last_seen_label": "2 days ago",
        "tags": ["botnet"],
        "meta": {},
    }
    text = build_indicator_report_text(threat, "Block this IP.", None)
    assert "1.2.3.4" in text
    assert "ipv4" in text
    assert "Block this IP." in text


def test_build_bulk_report_text():
    rows = [
        {
            "input": "8.8.8.8",
            "value": "8.8.8.8",
            "type": "ipv4",
            "verdict": "CLEAN",
            "risk_score": 0,
            "in_database": False,
            "error": None,
        },
        {
            "input": "bad",
            "value": "bad",
            "type": None,
            "verdict": None,
            "risk_score": None,
            "in_database": False,
            "error": "Invalid indicator",
        },
    ]
    text = build_bulk_report_text(rows)
    assert "Bulk IOC" in text
    assert "8.8.8.8" in text
    assert "ERROR" in text
