"""File threat report and verdict logic."""

from __future__ import annotations

from services.file_analysis import file_verdict


def test_file_verdict_unknown_when_no_signals():
    assert file_verdict(0, in_database=False, yara_match_count=0) == "UNKNOWN"


def test_file_verdict_clean_when_in_database():
    assert file_verdict(5, in_database=True, yara_match_count=0) == "CLEAN"


def test_file_verdict_clean_when_yara_matched_low_score():
    assert file_verdict(10, in_database=False, yara_match_count=1) == "CLEAN"


def test_file_verdict_malicious_from_score():
    assert file_verdict(85, in_database=False, yara_match_count=0) == "MALICIOUS"


def test_file_verdict_suspicious():
    assert file_verdict(25, in_database=False, yara_match_count=0) == "SUSPICIOUS"
