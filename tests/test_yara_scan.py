"""YARA scanning tests (uses bundled bootstrap rules)."""

from __future__ import annotations

from pathlib import Path

import pytest

from services.yara_scan import invalidate_rules_cache, scan_bytes

EICAR = (
    b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
)


@pytest.fixture(autouse=True)
def _bootstrap_rules(monkeypatch, tmp_path):
    bootstrap = Path(__file__).resolve().parents[1] / "yara_rules" / "bootstrap"
    rules_dir = tmp_path / "yara_rules"
    rules_dir.mkdir()
    for src in bootstrap.glob("*.yar"):
        (rules_dir / src.name).write_bytes(src.read_bytes())

    monkeypatch.setattr("services.yara_scan.rules_directory", lambda: rules_dir)
    invalidate_rules_cache()
    yield
    invalidate_rules_cache()


def test_yara_matches_eicar():
    pytest.importorskip("yara")

    result = scan_bytes(EICAR)
    if result.status == "unavailable":
        pytest.skip(result.message or "yara unavailable")

    assert result.status == "ok"
    assert result.match_count >= 1
    assert any(m.rule == "eicar_test_string" for m in result.matches)


def test_yara_clean_buffer():
    pytest.importorskip("yara")
    result = scan_bytes(b"hello threatscope test buffer")
    if result.status == "unavailable":
        pytest.skip(result.message or "yara unavailable")
    assert result.status == "ok"
    assert result.match_count == 0
