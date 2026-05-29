"""Tests for lookup input normalization and auto-detection."""

from __future__ import annotations

import pytest

from services.validation import normalize_lookup_input, resolve_indicator


class TestNormalizeLookupInput:
    def test_bare_ipv4(self) -> None:
        assert normalize_lookup_input("8.8.8.8") == "8.8.8.8"

    def test_ipv4_trailing_slash(self) -> None:
        assert normalize_lookup_input("101.132.78.77/") == "101.132.78.77"

    def test_ipv4_with_path(self) -> None:
        assert normalize_lookup_input("101.132.78.77/login") == "101.132.78.77"

    def test_full_url(self) -> None:
        assert normalize_lookup_input("http://101.132.78.77/login") == "101.132.78.77"

    def test_whitespace(self) -> None:
        assert normalize_lookup_input("  162.243.103.246  ") == "162.243.103.246"

    def test_quoted_input(self) -> None:
        assert normalize_lookup_input('"evil.com"') == "evil.com"

    def test_domain_with_path(self) -> None:
        assert normalize_lookup_input("evil.com/path") == "evil.com"

    def test_email_mailto_query(self) -> None:
        assert normalize_lookup_input("mailto:phish@evil.com?subject=x") == "phish@evil.com"

    def test_email_angle_brackets(self) -> None:
        assert normalize_lookup_input("<user@example.com>") == "user@example.com"


class TestResolveIndicatorAuto:
    def test_bare_ipv4(self) -> None:
        assert resolve_indicator("8.8.8.8", "auto") == ("ipv4", "8.8.8.8")

    def test_ipv4_trailing_slash(self) -> None:
        assert resolve_indicator("101.132.78.77/", "auto") == ("ipv4", "101.132.78.77")

    def test_full_url(self) -> None:
        assert resolve_indicator("http://101.132.78.77/login", "auto") == (
            "ipv4",
            "101.132.78.77",
        )

    def test_whitespace_ipv4(self) -> None:
        assert resolve_indicator(" 162.243.103.246 ", "auto") == ("ipv4", "162.243.103.246")

    def test_domain_with_path(self) -> None:
        assert resolve_indicator("evil.com/path", "auto") == ("domain", "evil.com")

    def test_md5_hash(self) -> None:
        h = "44d88612fea8a8f36de82e1278abb02f"
        assert resolve_indicator(h, "auto") == ("hash", h)

    def test_sha256_hash(self) -> None:
        h = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        assert resolve_indicator(h, "auto") == ("hash", h)

    def test_invalid_input_raises(self) -> None:
        with pytest.raises(ValueError):
            resolve_indicator("not-a-valid-indicator!!!", "auto")

    def test_us_phone_auto(self) -> None:
        assert resolve_indicator("+1 555-123-4567", "auto") == ("phone", "+15551234567")

    def test_phone_explicit_type(self) -> None:
        assert resolve_indicator("(555) 123-4567", "phone") == ("phone", "+15551234567")

    def test_email_auto(self) -> None:
        assert resolve_indicator("user@example.com", "auto") == (
            "email",
            "user@example.com",
        )

    def test_email_mailto(self) -> None:
        assert resolve_indicator("mailto:phish@evil.com", "auto") == (
            "email",
            "phish@evil.com",
        )

    def test_email_angle_brackets(self) -> None:
        assert resolve_indicator("<user@example.com>", "auto") == (
            "email",
            "user@example.com",
        )

    def test_email_explicit_type(self) -> None:
        assert resolve_indicator("user@example.com", "email") == ("email", "user@example.com")

    def test_domain_not_email(self) -> None:
        assert resolve_indicator("evil.com", "auto") == ("domain", "evil.com")

    def test_ipv4_not_email(self) -> None:
        assert resolve_indicator("8.8.8.8", "auto") == ("ipv4", "8.8.8.8")
