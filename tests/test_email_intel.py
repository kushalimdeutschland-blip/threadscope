"""Tests for local email intel helpers."""

from __future__ import annotations

from services.email_intel import build_local_email_intel
from services.validation import validate_email


def test_build_local_email_intel() -> None:
    email = validate_email("test@example.com")
    intel = build_local_email_intel(email)
    assert intel["domain"] == "example.com"
    assert "has_mx" in intel
    assert intel["provider"] == "local"
