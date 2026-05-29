"""Tests for opt-in lab scanning helpers."""

from __future__ import annotations

import pytest

from services.lab_scan import (
    build_nmap_argv,
    resolve_scan_target,
    validate_scan_allowed,
)


def test_resolve_scan_target_ipv4() -> None:
    host, resolved = resolve_scan_target("8.8.8.8", "ipv4")
    assert host == "8.8.8.8"
    assert resolved == "8.8.8.8"


def test_build_nmap_argv_safe() -> None:
    argv = build_nmap_argv("8.8.8.8")
    assert "-sT" in argv
    assert "-A" not in argv
    assert "8.8.8.8" in argv


def test_validate_scan_blocks_private_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    from config import get_settings

    get_settings.cache_clear()
    monkeypatch.setenv("LAB_SCAN_ALLOW_PRIVATE", "0")
    with pytest.raises(ValueError, match="Private"):
        validate_scan_allowed("192.168.1.1")


def test_validate_scan_allows_public() -> None:
    validate_scan_allowed("8.8.8.8")
