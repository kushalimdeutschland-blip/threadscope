"""Admin session authentication and protected routes."""

from __future__ import annotations

import asyncio
from importlib import reload

import pytest
from starlette.testclient import TestClient

import database
from config import get_settings
from services.admin_auth import (
    ADMIN_SESSION_COOKIE,
    create_admin_session_token,
    is_admin_request,
    verify_admin_password,
    verify_admin_session_token,
)
from services.csrf import CSRF_COOKIE, generate_csrf_token
from services.rate_limit import is_admin_context, reset_admin_context, set_admin_context


@pytest.fixture
def app_client(monkeypatch, tmp_path):
    db_path = tmp_path / "admin_auth_test.db"
    monkeypatch.setattr(database, "DB_PATH", db_path)
    monkeypatch.setenv("ENV", "development")
    monkeypatch.setenv("SECRET_KEY", "test-secret-key-for-admin-auth-tests!!")
    monkeypatch.setenv("ADMIN_PASSWORD", "test-admin-pass")
    monkeypatch.setenv("THREATSCOPE_PUBLIC", "1")
    monkeypatch.setenv("THREATSCOPE_ADMIN", "0")
    from conftest import reload_config_module

    reload_config_module()

    async def _setup():
        await database.close_read_pool()
        await database.init_db()

    async def _teardown():
        await database.close_read_pool()

    asyncio.run(_setup())

    import main

    reload(main)
    with TestClient(main.app) as client:
        yield client, main
    asyncio.run(_teardown())
    get_settings.cache_clear()


def _csrf_headers(client: TestClient, main_mod) -> tuple[dict[str, str], str]:
    secret = main_mod.secret_key
    token = generate_csrf_token(secret)
    client.cookies.set(CSRF_COOKIE, token)
    return {"Cookie": f"{CSRF_COOKIE}={token}"}, token


def test_verify_password_plaintext():
    cfg = get_settings()
    cfg.admin_password = "secret"
    cfg.admin_password_hash = ""
    assert verify_admin_password(cfg, "secret") is True
    assert verify_admin_password(cfg, "wrong") is False


def test_session_token_roundtrip():
    secret = "test-secret"
    token = create_admin_session_token(secret)
    assert verify_admin_session_token(secret, token) is True
    assert verify_admin_session_token(secret, "bad.token") is False


def test_intel_search_forbidden_without_session(app_client):
    client, main_mod = app_client
    _, token = _csrf_headers(client, main_mod)
    resp = client.post(
        "/api/intel-search",
        data={"q": "ransomware", "tag": "", "csrf_token": token},
    )
    assert resp.status_code == 403


def test_admin_login_grants_intel_access(app_client):
    client, main_mod = app_client
    _, token = _csrf_headers(client, main_mod)
    login = client.post(
        "/admin/login",
        data={"password": "test-admin-pass", "csrf_token": token},
        follow_redirects=False,
    )
    assert login.status_code == 303
    assert ADMIN_SESSION_COOKIE in login.cookies

    _, token2 = _csrf_headers(client, main_mod)
    resp = client.post(
        "/api/intel-search",
        data={"q": "ransomware", "tag": "", "csrf_token": token2},
    )
    assert resp.status_code != 403


def test_admin_login_rejects_bad_password(app_client):
    client, main_mod = app_client
    _, token = _csrf_headers(client, main_mod)
    resp = client.post(
        "/admin/login",
        data={"password": "wrong-password", "csrf_token": token},
    )
    assert resp.status_code == 401


def test_feed_accuracy_requires_session(app_client):
    client, _main = app_client
    resp = client.get("/api/feed-accuracy")
    assert resp.status_code == 403


def test_index_shows_intel_tab_when_logged_in(app_client):
    client, main_mod = app_client
    _, token = _csrf_headers(client, main_mod)
    client.post(
        "/admin/login",
        data={"password": "test-admin-pass", "csrf_token": token},
        follow_redirects=True,
    )
    home = client.get("/")
    assert "panel-intel" in home.text
    assert "Intel" in home.text


def test_admin_context_for_rate_limit_exemption():
    assert is_admin_context() is False
    token = set_admin_context(True)
    try:
        assert is_admin_context() is True
    finally:
        reset_admin_context(token)
    assert is_admin_context() is False


def test_admin_rate_exempt_helper():
    """Unit test for slowapi exempt_when; optional integration: burst lookups as logged-in admin."""
    import main

    assert main._admin_rate_exempt() is False
    token = set_admin_context(True)
    try:
        assert main._admin_rate_exempt() is True
    finally:
        reset_admin_context(token)


def test_is_admin_dev_bypass_when_not_public(monkeypatch):
    monkeypatch.setenv("THREATSCOPE_PUBLIC", "0")
    monkeypatch.setenv("THREATSCOPE_ADMIN", "1")
    monkeypatch.setenv("ENV", "development")
    from conftest import reload_config_module

    reload_config_module()
    cfg = get_settings()
    assert cfg.threatscope_public is False
    assert cfg.threatscope_admin is True
    assert is_admin_request(type("Req", (), {"cookies": {}})(), cfg, "k") is True
