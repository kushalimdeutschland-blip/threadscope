"""
Strict input validation for threat indicators.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Literal
from urllib.parse import urlparse

import phonenumbers
from phonenumbers import NumberParseException, PhoneNumberFormat

IndicatorType = Literal["ipv4", "ipv6", "domain", "hash", "phone", "email"]
AutoIndicatorType = IndicatorType | Literal["auto"]

MAX_IPV4_LEN = 15
MAX_IPV6_LEN = 45
MAX_DOMAIN_LEN = 253
MAX_HASH_LEN = 64
MAX_PHONE_LEN = 20
MAX_EMAIL_LEN = 254
MAX_INPUT_LEN = 512
MAX_TAG_LEN = 64
MAX_TAGS = 20

_IPV4_RE = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
_HASH_RE = re.compile(r"^[a-f0-9]{32}$|^[a-f0-9]{40}$|^[a-f0-9]{64}$")
_DOMAIN_RE = re.compile(
    r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$",
    re.IGNORECASE,
)
_PHONE_CANDIDATE_RE = re.compile(r"^[\d\s().+\-]{7,20}$")
_DIGIT_HEAVY_RE = re.compile(r"^[\d\s().+\-]+$")
_EMAIL_RE = re.compile(
    r"^[a-z0-9._%+\-]+@[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$",
    re.IGNORECASE,
)

_TYPE_LABELS = {
    "ipv4": "IPv4 address",
    "ipv6": "IPv6 address",
    "domain": "domain",
    "hash": "file hash",
    "phone": "phone number",
    "email": "email address",
}


def validate_ipv4(value: str) -> str:
    if not value or len(value) > MAX_IPV4_LEN:
        raise ValueError("Invalid IPv4 address")

    candidate = value.strip()
    if not _IPV4_RE.match(candidate):
        raise ValueError("Invalid IPv4 address format")

    try:
        addr = ipaddress.IPv4Address(candidate)
    except ipaddress.AddressValueError as exc:
        raise ValueError("Invalid IPv4 address") from exc

    if str(addr) != candidate:
        raise ValueError("Invalid IPv4 address format")

    return str(addr)


def validate_ipv6(value: str) -> str:
    if not value or len(value) > MAX_IPV6_LEN:
        raise ValueError("Invalid IPv6 address")

    candidate = value.strip()
    if "%" in candidate:
        candidate = candidate.split("%", 1)[0]

    try:
        addr = ipaddress.IPv6Address(candidate)
    except ipaddress.AddressValueError as exc:
        raise ValueError("Invalid IPv6 address") from exc

    return str(addr)


def validate_domain(value: str) -> str:
    if not value or len(value) > MAX_INPUT_LEN:
        raise ValueError("Invalid domain")

    candidate = value.strip().lower()
    for prefix in ("http://", "https://", "//"):
        if candidate.startswith(prefix):
            candidate = candidate[len(prefix):]
    candidate = candidate.split("/")[0].split("?")[0].split("#")[0].rstrip(".")

    if not candidate or len(candidate) > MAX_DOMAIN_LEN:
        raise ValueError("Invalid domain")
    if candidate.endswith("."):
        candidate = candidate[:-1]
    if not _DOMAIN_RE.match(candidate):
        raise ValueError("Invalid domain format")

    return candidate


def validate_hash(value: str) -> str:
    if not value or len(value) > MAX_HASH_LEN:
        raise ValueError("Invalid hash")

    candidate = value.strip().lower()
    if not _HASH_RE.match(candidate):
        raise ValueError("Invalid hash. Use MD5 (32), SHA1 (40), or SHA256 (64) hex characters.")

    return candidate


def _strip_email_wrappers(value: str) -> str:
    """Remove mailto prefix, angle brackets, and trailing path/query fragments."""
    candidate = value.strip()
    if candidate.lower().startswith("mailto:"):
        candidate = candidate[7:].strip()
    candidate = candidate.strip("<>").strip()
    if "@" in candidate:
        candidate = candidate.split("?")[0].split("#")[0].strip()
        candidate = candidate.split("/")[0].strip()
    return candidate


def validate_email(value: str) -> str:
    if not value or len(value) > MAX_INPUT_LEN:
        raise ValueError("Invalid email address")

    candidate = _strip_email_wrappers(value).lower()

    if not candidate or len(candidate) > MAX_EMAIL_LEN:
        raise ValueError("Invalid email address")
    if "@" not in candidate:
        raise ValueError("Invalid email address")

    local, _, domain = candidate.partition("@")
    if not local or not domain or "." not in domain:
        raise ValueError("Invalid email address")
    if not _EMAIL_RE.match(candidate):
        raise ValueError("Invalid email address format")

    return candidate


def email_domain(value: str) -> str:
    """Domain part of a normalized email address."""
    return value.rsplit("@", 1)[1]


def validate_phone(value: str, *, default_region: str = "US") -> str:
    if not value or len(value) > MAX_INPUT_LEN:
        raise ValueError("Invalid phone number")

    candidate = value.strip()
    if candidate.lower().startswith("tel:"):
        candidate = candidate[4:].strip()

    if not candidate or len(candidate) > MAX_PHONE_LEN + 4:
        raise ValueError("Invalid phone number")

    region = None if candidate.startswith("+") else default_region
    try:
        parsed = phonenumbers.parse(candidate, region)
    except NumberParseException as exc:
        raise ValueError("Invalid phone number") from exc

    if not phonenumbers.is_possible_number(parsed):
        raise ValueError("Invalid phone number")

    return phonenumbers.format_number(parsed, PhoneNumberFormat.E164)


def phone_display(value_e164: str) -> str:
    """International display format for E.164 stored value."""
    try:
        parsed = phonenumbers.parse(value_e164, None)
        return phonenumbers.format_number(parsed, PhoneNumberFormat.INTERNATIONAL)
    except NumberParseException:
        return value_e164


def phone_region_code(value_e164: str) -> str | None:
    try:
        parsed = phonenumbers.parse(value_e164, None)
        return phonenumbers.region_code_for_number(parsed)
    except NumberParseException:
        return None


def hash_algorithm(value: str) -> str:
    length = len(value)
    if length == 32:
        return "md5"
    if length == 40:
        return "sha1"
    return "sha256"


def _looks_like_email(raw: str) -> bool:
    stripped = _strip_email_wrappers(raw).lower()
    if "@" not in stripped:
        return False
    if _IPV4_RE.match(stripped):
        return False
    try:
        validate_email(stripped)
        return True
    except ValueError:
        return False


def _looks_like_phone(raw: str) -> bool:
    stripped = raw.strip()
    if stripped.lower().startswith("tel:"):
        return True
    if stripped.startswith("+"):
        return True
    if _IPV4_RE.match(stripped):
        return False
    if not _DIGIT_HEAVY_RE.match(stripped):
        return False
    if "." in stripped and not any(c in stripped for c in "()-"):
        return False
    digits = sum(1 for c in stripped if c.isdigit())
    return digits >= 7 and _PHONE_CANDIDATE_RE.match(stripped) is not None


def validate_indicator(value: str, indicator_type: IndicatorType) -> str:
    validators = {
        "ipv4": validate_ipv4,
        "ipv6": validate_ipv6,
        "domain": validate_domain,
        "hash": validate_hash,
        "phone": validate_phone,
        "email": validate_email,
    }
    return validators[indicator_type](value)


def sanitize_lookup_input(value: str) -> str:
    """Normalize raw user input before type detection or validation."""
    return normalize_lookup_input(value)


def normalize_lookup_input(value: str) -> str:
    """Strip URLs, paths, quotes, and brackets to a lookup key."""
    raw = value.strip().strip('"').strip("'")
    if not raw or len(raw) > MAX_INPUT_LEN:
        raise ValueError("Invalid indicator")

    if raw.lower().startswith("tel:"):
        return raw[4:].strip()
    if raw.lower().startswith("mailto:"):
        raw = raw[7:].strip()
    raw = raw.strip("<>").strip()

    if "://" in raw or raw.startswith("//"):
        parsed = urlparse(raw if "://" in raw else f"http:{raw}")
        host = parsed.hostname
        if not host:
            raise ValueError("Invalid indicator")
        raw = host
    else:
        if "@" in raw:
            raw = _strip_email_wrappers(raw)
        else:
            raw = raw.split("/")[0].split("?")[0].split("#")[0]

    raw = raw.strip().rstrip(".")
    if raw.startswith("[") and raw.endswith("]"):
        raw = raw[1:-1]
    if "%" in raw:
        raw = raw.split("%", 1)[0]

    if not raw:
        raise ValueError("Invalid indicator")
    return raw


def detect_indicator_type(value: str) -> tuple[IndicatorType, str]:
    """
    Auto-detect indicator type from raw input.
    Order: hash → email → IPv4 → IPv6 → phone → domain.
    """
    raw = normalize_lookup_input(value)

    lowered = raw.lower()
    if _HASH_RE.match(lowered):
        return "hash", validate_hash(lowered)

    if _looks_like_email(raw):
        return "email", validate_email(raw)

    if _IPV4_RE.match(raw.strip()):
        return "ipv4", validate_ipv4(raw)

    if ":" in raw and not raw.strip().startswith("+"):
        return "ipv6", validate_ipv6(raw)

    if _looks_like_phone(raw):
        return "phone", validate_phone(raw)

    return "domain", validate_domain(raw)


def resolve_indicator(value: str, indicator_type: AutoIndicatorType) -> tuple[IndicatorType, str]:
    if indicator_type == "auto":
        return detect_indicator_type(value)
    normalized_input = normalize_lookup_input(value)
    normalized = validate_indicator(normalized_input, indicator_type)
    return indicator_type, normalized


def type_label(indicator_type: IndicatorType) -> str:
    return _TYPE_LABELS[indicator_type]


def sanitize_tags(tags: list[str]) -> list[str]:
    clean: list[str] = []
    for tag in tags[:MAX_TAGS]:
        if not isinstance(tag, str):
            continue
        t = tag.strip()
        if t and len(t) <= MAX_TAG_LEN:
            clean.append(t)
    return clean
