"""
Sanitize intel document text and metadata before storage, FTS indexing, and UI display.

- Strip HTML/scripts; plain text only
- Normalize whitespace; strip null bytes
- Redact obvious secrets (passwords, API keys, bearer tokens, private keys)
- Truncate body to configured max bytes
- Meta JSON never retains password/credential fields
"""

from __future__ import annotations

import hashlib
import re
from typing import Any

from bs4 import BeautifulSoup

# Assignment-style secrets
_ASSIGNMENT_RE = re.compile(
    r"(?i)\b("
    r"password|passwd|pwd|api[_-]?key|secret|token|auth|authorization|"
    r"bearer|private[_-]?key|client[_-]?secret"
    r")\s*[:=]\s*\S+"
)
_BEARER_RE = re.compile(r"(?i)\bbearer\s+[a-z0-9._\-+/=]{8,}\b")
_PRIVATE_KEY_RE = re.compile(
    r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"
)
# PEM / long base64-ish blobs after key labels
_LONG_SECRET_RE = re.compile(
    r"(?i)\b(api[_-]?key|secret|token)\s*[:=]\s*['\"]?[a-z0-9._\-+/=]{16,}",
)

_META_DROP_KEYS = frozenset(
    {
        "password",
        "passwd",
        "pwd",
        "pass",
        "hash",
        "hashed_password",
        "api_key",
        "apikey",
        "secret",
        "token",
        "access_token",
        "refresh_token",
        "authorization",
        "private_key",
        "client_secret",
    }
)
_META_DROP_PREFIXES = ("password_", "passwd_", "secret_")


def strip_null_bytes(text: str) -> str:
    return text.replace("\x00", "")


def normalize_whitespace(text: str) -> str:
    text = strip_null_bytes(text)
    lines = [re.sub(r"[ \t]+", " ", line).strip() for line in text.splitlines()]
    collapsed: list[str] = []
    prev_blank = False
    for line in lines:
        if not line:
            if not prev_blank:
                collapsed.append("")
            prev_blank = True
            continue
        collapsed.append(line)
        prev_blank = False
    return "\n".join(collapsed).strip()


def html_to_text(html: str) -> str:
    """Alias for HTML → plain text extraction."""
    return strip_html(html)


def strip_html(html: str) -> str:
    """Parse HTML to plain text; no script execution."""
    if not html or "<" not in html:
        return normalize_whitespace(html or "")
    soup = BeautifulSoup(html, "html.parser")
    for tag in soup(["script", "style", "noscript", "iframe", "object", "embed"]):
        tag.decompose()
    root = (
        soup.find("article")
        or soup.find("main")
        or soup.find(attrs={"role": "main"})
        or soup.find("body")
        or soup
    )
    text = root.get_text(separator="\n", strip=True)
    return normalize_whitespace(text)


def redact_secrets(text: str) -> str:
    if not text:
        return ""
    out = _PRIVATE_KEY_RE.sub("[REDACTED_PRIVATE_KEY]", text)
    out = _BEARER_RE.sub("bearer [REDACTED]", out)
    out = _ASSIGNMENT_RE.sub(lambda m: f"{m.group(1)}=[REDACTED]", out)
    out = _LONG_SECRET_RE.sub(lambda m: f"{m.group(1)}=[REDACTED]", out)
    return out


def truncate_body(text: str, max_bytes: int) -> str:
    if max_bytes <= 0:
        return ""
    raw = text.encode("utf-8")
    if len(raw) <= max_bytes:
        return text
    cut = raw[:max_bytes]
    while cut and (cut[-1] & 0xC0) == 0x80:
        cut = cut[:-1]
    return cut.decode("utf-8", errors="ignore") + "\n…[truncated]"


def body_hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _meta_key_sensitive(key: str) -> bool:
    lower = key.lower()
    if lower in _META_DROP_KEYS:
        return True
    return any(lower.startswith(p) for p in _META_DROP_PREFIXES)


def sanitize_meta(meta: dict[str, Any] | None) -> dict[str, Any]:
    if not meta:
        return {}
    clean: dict[str, Any] = {}
    for key, value in meta.items():
        if _meta_key_sensitive(str(key)):
            continue
        if isinstance(value, dict):
            nested = sanitize_meta(value)
            if nested:
                clean[key] = nested
            continue
        if isinstance(value, str) and _ASSIGNMENT_RE.search(value):
            clean[key] = redact_secrets(value)
        else:
            clean[key] = value
    return clean


def sanitize_text(text: str, *, max_bytes: int | None = None) -> str:
    """Full text pipeline for intel bodies and titles."""
    if not text:
        return ""
    plain = strip_html(text) if "<" in text else normalize_whitespace(text)
    plain = redact_secrets(plain)
    if max_bytes is not None:
        plain = truncate_body(plain, max_bytes)
    return plain


def prepare_intel_document(
    title: str,
    body: str,
    meta: dict[str, Any] | None = None,
    *,
    max_bytes: int,
) -> tuple[str, str, dict[str, Any], str]:
    """
    Sanitize title, body, and meta for persistence.

    Returns (title, body, meta, body_sha256) where body is sanitized and truncated.
    """
    safe_title = sanitize_text(title, max_bytes=min(max_bytes, 2048))
    safe_body = sanitize_text(body, max_bytes=max_bytes)
    safe_meta = sanitize_meta(meta)
    digest = body_hash(safe_body)
    return safe_title, safe_body, safe_meta, digest


def sanitize_for_display(text: str, *, max_len: int | None = None) -> str:
    """Defense-in-depth before UI snippets (already stored sanitized)."""
    out = sanitize_text(text, max_bytes=max_len)
    return redact_secrets(out)
