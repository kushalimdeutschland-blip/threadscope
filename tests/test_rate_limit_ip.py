"""Rate limit client IP resolution behind reverse proxies."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from config import Settings, get_settings
from services.rate_limit import get_client_ip


def _request(
    *,
    client_host: str = "127.0.0.1",
    forwarded: str | None = None,
    real_ip: str | None = None,
) -> MagicMock:
    headers = {}
    if forwarded is not None:
        headers["x-forwarded-for"] = forwarded
    if real_ip is not None:
        headers["x-real-ip"] = real_ip
    req = MagicMock()
    req.headers = headers
    req.client = MagicMock()
    req.client.host = client_host
    return req


def test_direct_client_ip_when_proxy_headers_disabled():
    cfg = Settings()
    cfg.trust_proxy_headers = False
    ip = get_client_ip(_request(client_host="203.0.113.10"), cfg)
    assert ip == "203.0.113.10"


def test_x_forwarded_for_first_hop_when_trusted():
    cfg = Settings()
    cfg.trust_proxy_headers = True
    ip = get_client_ip(
        _request(client_host="127.0.0.1", forwarded="198.51.100.5, 10.0.0.1"),
        cfg,
    )
    assert ip == "198.51.100.5"


def test_x_real_ip_fallback():
    cfg = Settings()
    cfg.trust_proxy_headers = True
    ip = get_client_ip(_request(client_host="127.0.0.1", real_ip="198.51.100.9"), cfg)
    assert ip == "198.51.100.9"


def test_invalid_forwarded_falls_back_to_client():
    cfg = Settings()
    cfg.trust_proxy_headers = True
    ip = get_client_ip(
        _request(client_host="127.0.0.1", forwarded="not-an-ip"),
        cfg,
    )
    assert ip == "127.0.0.1"


def test_trust_proxy_defaults_on_in_production(monkeypatch):
    monkeypatch.setenv("ENV", "production")
    monkeypatch.delenv("TRUST_PROXY_HEADERS", raising=False)
    from conftest import reload_config_module

    reload_config_module()
    cfg = get_settings()
    assert cfg.trust_proxy_headers is True
