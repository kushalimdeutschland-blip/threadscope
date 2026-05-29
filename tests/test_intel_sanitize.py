"""Intel sanitization — HTML strip, secret redaction, truncation."""

from __future__ import annotations

from services.intel.sanitize import (
    body_hash,
    prepare_intel_document,
    redact_secrets,
    sanitize_meta,
    sanitize_text,
    strip_html,
    truncate_body,
)


def test_strip_html_removes_script_and_tags():
    raw = "<html><body><script>alert(1)</script><p>Hello <b>world</b></p></body></html>"
    assert "Hello" in strip_html(raw) and "world" in strip_html(raw)
    assert "alert" not in strip_html(raw)
    assert "<" not in strip_html(raw)


def test_redact_password_and_api_key_assignments():
    text = "user=admin password=SuperSecret123 api_key=abcd1234efgh5678"
    out = redact_secrets(text)
    assert "SuperSecret123" not in out
    assert "abcd1234efgh5678" not in out
    assert "password=[REDACTED]" in out
    assert "api_key=[REDACTED]" in out


def test_redact_bearer_token():
    text = "Authorization: bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.extra"
    out = redact_secrets(text)
    assert "eyJhbGci" not in out
    assert "[REDACTED]" in out


def test_truncate_body_respects_utf8():
    long_text = "a" * 100
    out = truncate_body(long_text, 20)
    assert len(out.encode("utf-8")) <= 40
    assert len(out) < len(long_text)
    assert "truncated" in out


def test_sanitize_meta_drops_password_fields():
    meta = sanitize_meta(
        {
            "query": "test",
            "password": "never-store",
            "api_key": "secret",
            "nested": {"passwd": "x", "ok": "yes"},
        }
    )
    assert meta == {"query": "test", "nested": {"ok": "yes"}}


def test_prepare_intel_document_hashes_sanitized_body():
    title, body, meta, digest = prepare_intel_document(
        "<b>Title</b>",
        "<p>Contact evil@example.com password=hunter2</p>",
        {"feed": "test"},
        max_bytes=4096,
    )
    assert title == "Title"
    assert "hunter2" not in body
    assert "password=[REDACTED]" in body
    assert digest == body_hash(body)
    assert meta == {"feed": "test"}


def test_strip_null_bytes():
    assert "\x00" not in sanitize_text("before\x00after")
