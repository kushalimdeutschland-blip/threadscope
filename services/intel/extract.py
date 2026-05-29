"""
Extract IOCs and tags from intel document text (never passwords or credential pairs).
"""

from __future__ import annotations

import re
from typing import Any

from services.feed_parser import FeedIndicator, _DOMAIN_IN_TEXT_RE, _IPV4_IN_TEXT_RE
from services.validation import (
    validate_domain,
    validate_email,
    validate_hash,
    validate_ipv4,
    validate_ipv6,
)

BREACH_EMAIL_SCORE = 50
INTEL_IOC_SCORE = 70

_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
_EMAIL_RE = re.compile(
    r"\b[a-z0-9._%+\-]+@[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+\.[a-z]{2,63}\b",
    re.IGNORECASE,
)
_HASH_RE = re.compile(r"\b[a-f0-9]{32}\b|\b[a-f0-9]{40}\b|\b[a-f0-9]{64}\b", re.IGNORECASE)
# email:password or user:pass — take email only, never store secret part
_CREDENTIAL_PAIR_RE = re.compile(
    r"^([a-z0-9._%+\-]+@[^\s:]+):[^\s]+$",
    re.IGNORECASE,
)
_CREDENTIAL_INLINE_RE = re.compile(
    r"\b([a-z0-9._%+\-]+@[a-z0-9.-]+\.[a-z]{2,63}):[^\s]+",
    re.IGNORECASE,
)
_YARA_CANDIDATE_RE = re.compile(
    r"\b(rule\s+\w+|strings\s*:|condition\s*:)\b|(?:\b[0-9a-fA-F]{16,}\b)",
    re.IGNORECASE,
)

_TAG_KEYWORDS: dict[str, re.Pattern[str]] = {
    "cve": re.compile(r"\bCVE-\d{4}-\d+", re.IGNORECASE),
    "rat": re.compile(r"\b(remote access trojan|RAT\b|njRAT|AsyncRAT|Quasar)\b", re.IGNORECASE),
    "leak": re.compile(r"\b(breach|leak|credential stuffing|combo list)\b", re.IGNORECASE),
    "exploit": re.compile(r"\b(exploit|RCE|zero-?day|0day)\b", re.IGNORECASE),
    "ransomware": re.compile(r"\b(ransomware|lockbit|blackcat|alphv)\b", re.IGNORECASE),
    "phishing": re.compile(r"\b(phish|credential harvest|smish)\b", re.IGNORECASE),
}


def extract_tags(text: str, extra: list[str] | None = None) -> list[str]:
    tags: list[str] = []
    for name, pattern in _TAG_KEYWORDS.items():
        if pattern.search(text):
            tags.append(name)
    if _YARA_CANDIDATE_RE.search(text):
        tags.append("yara_candidate")
    for cve in _CVE_RE.findall(text):
        tags.append(cve.upper())
    if extra:
        for t in extra:
            if t and t not in tags:
                tags.append(t)
    return tags[:20]


def _safe_email(raw: str) -> str | None:
    candidate = raw.strip().lower()
    pair = _CREDENTIAL_PAIR_RE.match(candidate)
    if pair:
        candidate = pair.group(1)
    try:
        return validate_email(candidate)
    except ValueError:
        return None


def extract_iocs(
    text: str,
    *,
    source: str,
    default_score: int = INTEL_IOC_SCORE,
    extra_tags: list[str] | None = None,
) -> list[FeedIndicator]:
    """Parse text into validated FeedIndicator rows (no passwords)."""
    seen: set[tuple[str, str]] = set()
    rows: list[FeedIndicator] = []
    base_tags = list(extra_tags or [])
    if "intel" not in base_tags:
        base_tags.append("intel")

    def _add(value: str, indicator_type: str, score: int, tags: list[str]) -> None:
        key = (value, indicator_type)
        if key in seen:
            return
        seen.add(key)
        rows.append(
            FeedIndicator(
                value=value,
                type=indicator_type,  # type: ignore[arg-type]
                risk_score=score,
                tags=tags,
                meta={"source": source},
            )
        )

    for match in _CREDENTIAL_INLINE_RE.finditer(text):
        email = _safe_email(match.group(1))
        if email:
            _add(email, "email", default_score, base_tags + ["intel-email"])

    for line in text.splitlines():
        pair = _CREDENTIAL_PAIR_RE.match(line.strip())
        if pair:
            email = _safe_email(pair.group(1))
            if email:
                _add(email, "email", default_score, base_tags + ["intel-email"])

    for raw in _EMAIL_RE.findall(text):
        email = _safe_email(raw)
        if email:
            _add(email, "email", default_score, base_tags + ["intel-email"])

    for raw in _IPV4_IN_TEXT_RE.findall(text):
        try:
            ip = validate_ipv4(raw)
            _add(ip, "ipv4", default_score, base_tags)
        except ValueError:
            pass

    email_domains = {e.split("@", 1)[1] for e, t in seen if t == "email"}

    for raw in _DOMAIN_IN_TEXT_RE.findall(text):
        try:
            domain = validate_domain(raw)
            if domain in email_domains:
                continue
            _add(domain, "domain", default_score, base_tags)
        except ValueError:
            pass

    for raw in _HASH_RE.findall(text):
        try:
            h = validate_hash(raw)
            _add(h, "hash", default_score, base_tags)
        except ValueError:
            pass

    # IPv6 (sparse in paste text)
    for match in re.finditer(r"\b([0-9a-f:]+:[0-9a-f:]+)\b", text, re.IGNORECASE):
        try:
            ip6 = validate_ipv6(match.group(1))
            _add(ip6, "ipv6", default_score, base_tags)
        except ValueError:
            pass

    return rows


def parse_leak_row(row: dict[str, Any], *, source: str) -> list[FeedIndicator]:
    """
    IOC-only leak API row — email field only; password/hash/username never stored.
    """
    email_raw = row.get("email") or row.get("username")
    if not email_raw or "@" not in str(email_raw):
        return []
    email = _safe_email(str(email_raw))
    if not email:
        return []
    meta = {
        "source": source,
        "breach": row.get("database") or row.get("name") or row.get("source"),
    }
    return [
        FeedIndicator(
            value=email,
            type="email",
            risk_score=BREACH_EMAIL_SCORE,
            tags=["breach-leak", "intel"],
            meta={k: v for k, v in meta.items() if v},
        )
    ]
