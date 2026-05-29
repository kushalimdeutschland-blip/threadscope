"""THREATSCOPE_PUBLIC profile configuration tests."""

from __future__ import annotations

import pytest

from conftest import reload_config_module
from config import get_settings


@pytest.fixture(autouse=True)
def _clear_settings_cache():
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


def test_public_mode_stricter_limits(monkeypatch):
    monkeypatch.setenv("THREATSCOPE_PUBLIC", "1")
    reload_config_module()
    cfg = get_settings()
    assert cfg.effective_rate_limit == "20/minute"
    assert cfg.effective_file_upload_rate_limit == "5/hour"
    assert cfg.effective_blocklist_rate_limit == "5/hour"


def test_public_mode_disables_admin_env_and_dynamic_sandbox(monkeypatch):
    monkeypatch.setenv("THREATSCOPE_PUBLIC", "1")
    monkeypatch.setenv("THREATSCOPE_ADMIN", "1")
    monkeypatch.setenv("SANDBOX_BACKEND", "mock")
    monkeypatch.setenv("LAB_SCAN_ENABLED", "1")
    reload_config_module()
    cfg = get_settings()
    assert cfg.env_threatscope_admin is False
    assert cfg.allow_dynamic_sandbox is False
    assert cfg.effective_lab_scan_enabled is False
    assert cfg.record_lookup_history is False


def test_homelab_keeps_defaults_without_public(monkeypatch):
    monkeypatch.delenv("THREATSCOPE_PUBLIC", raising=False)
    reload_config_module()
    cfg = get_settings()
    assert cfg.effective_rate_limit == "30/minute"
    assert cfg.record_lookup_history is True
    assert cfg.allow_dynamic_sandbox is True
