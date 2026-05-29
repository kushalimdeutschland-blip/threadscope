"""
Parse OSINT text feeds into normalized indicator records.
"""

from __future__ import annotations

import csv
import io
import ipaddress
import json
import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

from services.validation import (
    IndicatorType,
    validate_domain,
    validate_email,
    validate_hash,
    validate_ipv4,
    validate_ipv6,
    validate_phone,
)

URLHAUS_DOMAIN_SCORE = 85
URLHAUS_IP_SCORE = 85
FEODO_IP_SCORE = 92
BLOCKLIST_IP_SCORE = 75
CINSSCORE_IP_SCORE = 80
PHISHING_DOMAIN_SCORE = 88
PHISHING_IP_SCORE = 88
MALWAREBAZAAR_HASH_SCORE = 90
SPAMHAUS_DROP_SCORE = 82
FIREHOL_IP_SCORE = 78
OPENPHISH_DOMAIN_SCORE = 86
OPENPHISH_IP_SCORE = 86
THREATFOX_IP_SCORE = 88
THREATFOX_DOMAIN_SCORE = 88
THREATFOX_HASH_SCORE = 90
CISA_KEV_SCORE = 75

_IPV4_IN_TEXT_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_DOMAIN_IN_TEXT_RE = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\b",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class FeedIndicator:
    value: str
    type: IndicatorType
    risk_score: int
    tags: list[str] = field(default_factory=list)
    meta: dict[str, Any] = field(default_factory=dict)


@dataclass
class IngestStats:
    inserted: int = 0
    updated: int = 0
    skipped: int = 0
    parsed: int = 0
    pruned: int = 0


def _hostname_from_url(line: str) -> str | None:
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    parsed = urlparse(line if "://" in line else f"http://{line}")
    host = parsed.hostname
    if not host:
        return None
    return host.strip().lower()


def _classify_host(
    host: str,
    *,
    source: str,
    domain_score: int,
    ip_score: int,
    tags: list[str],
) -> FeedIndicator | None:
    """Classify hostname as ipv4, ipv6, or domain."""
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]

    if ":" in host:
        try:
            value = validate_ipv6(host)
            return FeedIndicator(
                value=value,
                type="ipv6",
                risk_score=ip_score,
                tags=tags,
                meta={"source": source},
            )
        except ValueError:
            pass

    try:
        value = validate_ipv4(host)
        return FeedIndicator(
            value=value,
            type="ipv4",
            risk_score=ip_score,
            tags=tags,
            meta={"source": source},
        )
    except ValueError:
        pass

    try:
        value = validate_domain(host)
        return FeedIndicator(
            value=value,
            type="domain",
            risk_score=domain_score,
            tags=tags,
            meta={"source": source},
        )
    except ValueError:
        return None


def parse_urlhaus_text(content: str) -> list[FeedIndicator]:
    """Extract ipv4, ipv6, and domain indicators from URLhaus plain-text URL list."""
    results: list[FeedIndicator] = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        host = _hostname_from_url(line)
        if not host:
            continue
        indicator = _classify_host(
            host,
            source="URLhaus",
            domain_score=URLHAUS_DOMAIN_SCORE,
            ip_score=URLHAUS_IP_SCORE,
            tags=["URLhaus", "Malware Distribution"],
        )
        if indicator:
            results.append(indicator)
    return results


def _is_public_ip(value: str) -> bool:
    try:
        addr = ipaddress.ip_address(value)
    except ValueError:
        return False
    return addr.is_global


def parse_ip_blocklist_text(
    content: str,
    *,
    source: str,
    score: int,
    tags: list[str],
    require_global: bool = False,
) -> list[FeedIndicator]:
    """Extract IPv4/IPv6 addresses from plain-text IP blocklists."""
    results: list[FeedIndicator] = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if ";" in line:
            line = line.split(";", 1)[0].strip()

        candidate = line.split("/", 1)[0].strip()
        if ":" in candidate:
            try:
                value = validate_ipv6(candidate)
            except ValueError:
                continue
            results.append(
                FeedIndicator(
                    value=value,
                    type="ipv6",
                    risk_score=score,
                    tags=tags,
                    meta={"source": source},
                )
            )
            continue

        try:
            value = validate_ipv4(candidate)
        except ValueError:
            continue
        if require_global and not _is_public_ip(value):
            continue
        results.append(
            FeedIndicator(
                value=value,
                type="ipv4",
                risk_score=score,
                tags=tags,
                meta={"source": source},
            )
        )
    return results


def parse_blocklist_text(content: str) -> list[FeedIndicator]:
    """Extract IPs from Blocklist.de all.txt."""
    return parse_ip_blocklist_text(
        content,
        source="Blocklist.de",
        score=BLOCKLIST_IP_SCORE,
        tags=["Blocklist.de", "Brute Force"],
    )


def parse_cinsscore_text(content: str) -> list[FeedIndicator]:
    """Extract IPs from CINSscore ci-badguys list."""
    return parse_ip_blocklist_text(
        content,
        source="CINSscore",
        score=CINSSCORE_IP_SCORE,
        tags=["CINSscore", "Threat Intel"],
    )


def parse_feodo_text(content: str) -> list[FeedIndicator]:
    """Extract IPv4 C2 addresses from Feodo Tracker blocklist."""
    return parse_ip_blocklist_text(
        content,
        source="Feodo Tracker",
        score=FEODO_IP_SCORE,
        tags=["Feodo Tracker", "C2", "Botnet"],
    )


def parse_phishing_urls_text(content: str) -> list[FeedIndicator]:
    """Extract domains and IPs from Phishing.Database active URL list."""
    results: list[FeedIndicator] = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        host = _hostname_from_url(line)
        if not host:
            continue
        indicator = _classify_host(
            host,
            source="Phishing.Database",
            domain_score=PHISHING_DOMAIN_SCORE,
            ip_score=PHISHING_IP_SCORE,
            tags=["Phishing.Database", "Phishing"],
        )
        if indicator:
            results.append(indicator)
    return results


def parse_spamhaus_drop_text(content: str) -> list[FeedIndicator]:
    """Extract IPs from Spamhaus DROP list (semicolon comments, CIDR rows)."""
    return parse_ip_blocklist_text(
        content,
        source="Spamhaus DROP",
        score=SPAMHAUS_DROP_SCORE,
        tags=["Spamhaus DROP", "Drop List"],
        require_global=True,
    )


def parse_firehol_level1_text(content: str) -> list[FeedIndicator]:
    """Extract public IPs from FireHOL level1 netset."""
    return parse_ip_blocklist_text(
        content,
        source="FireHOL Level1",
        score=FIREHOL_IP_SCORE,
        tags=["FireHOL", "Aggregated Blocklist"],
        require_global=True,
    )


def parse_openphish_text(content: str) -> list[FeedIndicator]:
    """Extract domains and IPs from OpenPhish URL feed."""
    results: list[FeedIndicator] = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        host = _hostname_from_url(line)
        if not host:
            continue
        indicator = _classify_host(
            host,
            source="OpenPhish",
            domain_score=OPENPHISH_DOMAIN_SCORE,
            ip_score=OPENPHISH_IP_SCORE,
            tags=["OpenPhish", "Phishing"],
        )
        if indicator:
            results.append(indicator)
    return results


def parse_malwarebazaar_csv(content: str) -> list[FeedIndicator]:
    """Extract file hashes from MalwareBazaar recent samples CSV."""
    results: list[FeedIndicator] = []
    reader = csv.reader(
        (line for line in content.splitlines() if line.strip() and not line.strip().startswith("#")),
    )
    for row in reader:
        if len(row) < 4:
            continue
        for idx in (1, 2, 3):
            raw = row[idx].strip().strip('"').lower()
            if not raw or raw == "n/a":
                continue
            try:
                value = validate_hash(raw)
            except ValueError:
                continue
            results.append(
                FeedIndicator(
                    value=value,
                    type="hash",
                    risk_score=MALWAREBAZAAR_HASH_SCORE,
                    tags=["MalwareBazaar", "Malware Sample"],
                    meta={"source": "MalwareBazaar"},
                )
            )
    return results


def parse_cisa_kev_json(content: str) -> list[FeedIndicator]:
    """Extract IPs/domains mentioned in CISA KEV vulnerability notes."""
    try:
        payload = json.loads(content)
    except json.JSONDecodeError:
        return []

    results: list[FeedIndicator] = []
    seen: set[tuple[str, str]] = set()
    for entry in payload.get("vulnerabilities") or []:
        cve_id = entry.get("cveID") or "CVE"
        text = " ".join(
            str(entry.get(key) or "")
            for key in ("notes", "shortDescription", "vulnerabilityName")
        )
        for match in _IPV4_IN_TEXT_RE.findall(text):
            try:
                value = validate_ipv4(match)
            except ValueError:
                continue
            if not _is_public_ip(value):
                continue
            key = (value, "ipv4")
            if key in seen:
                continue
            seen.add(key)
            results.append(
                FeedIndicator(
                    value=value,
                    type="ipv4",
                    risk_score=CISA_KEV_SCORE,
                    tags=["CISA KEV", cve_id],
                    meta={"source": "CISA KEV", "cve": cve_id},
                )
            )
        for match in _DOMAIN_IN_TEXT_RE.findall(text):
            try:
                value = validate_domain(match)
            except ValueError:
                continue
            key = (value, "domain")
            if key in seen:
                continue
            seen.add(key)
            results.append(
                FeedIndicator(
                    value=value,
                    type="domain",
                    risk_score=CISA_KEV_SCORE,
                    tags=["CISA KEV", cve_id],
                    meta={"source": "CISA KEV", "cve": cve_id},
                )
            )
    return results


def parse_threatfox_csv(content: str) -> list[FeedIndicator]:
    """Extract IOCs from ThreatFox CSV export."""
    results: list[FeedIndicator] = []
    reader = csv.DictReader(io.StringIO(content))
    if not reader.fieldnames:
        return results

    def _field(*names: str) -> str | None:
        for name in names:
            if name in reader.fieldnames:
                return name
        lowered = {n.lower(): n for n in reader.fieldnames}
        for name in names:
            hit = lowered.get(name.lower())
            if hit:
                return hit
        return None

    ioc_col = _field("ioc", "ioc_value", "value")
    type_col = _field("ioc_type", "type", "ioc_type_desc")
    if not ioc_col:
        return results

    for row in reader:
        raw_ioc = (row.get(ioc_col) or "").strip().strip('"')
        if not raw_ioc:
            continue
        raw_type = (row.get(type_col) or "").strip().lower() if type_col else ""

        if raw_type in ("ip", "ip:port", "ipv4", "ipv4-addr") or _IPV4_IN_TEXT_RE.fullmatch(raw_ioc):
            host = raw_ioc.split(":", 1)[0].strip()
            indicator = _classify_host(
                host,
                source="ThreatFox",
                domain_score=THREATFOX_DOMAIN_SCORE,
                ip_score=THREATFOX_IP_SCORE,
                tags=["ThreatFox"],
            )
            if indicator and indicator.type in ("ipv4", "ipv6"):
                results.append(indicator)
            continue

        if raw_type in ("domain", "hostname", "domain:port"):
            host = raw_ioc.split(":", 1)[0].strip()
            indicator = _classify_host(
                host,
                source="ThreatFox",
                domain_score=THREATFOX_DOMAIN_SCORE,
                ip_score=THREATFOX_IP_SCORE,
                tags=["ThreatFox"],
            )
            if indicator and indicator.type == "domain":
                results.append(indicator)
            continue

        if raw_type in ("md5", "md5_hash", "sha1", "sha1_hash", "sha256", "sha256_hash", "hash"):
            try:
                value = validate_hash(raw_ioc.lower())
            except ValueError:
                continue
            results.append(
                FeedIndicator(
                    value=value,
                    type="hash",
                    risk_score=THREATFOX_HASH_SCORE,
                    tags=["ThreatFox"],
                    meta={"source": "ThreatFox"},
                )
            )

    return results


PHONE_SCAM_SCORE = 85
EMAIL_SCAM_SCORE = 85


def parse_email_scam_csv(content: str) -> list[FeedIndicator]:
    """
    Parse homelab email scam CSV: email,score,tags,source
    Header row optional. Tags semicolon-separated.
    """
    results: list[FeedIndicator] = []
    reader = csv.reader(io.StringIO(content))
    for row in reader:
        if not row or row[0].strip().startswith("#"):
            continue
        email_raw = row[0].strip()
        if email_raw.lower() in ("email", "address", "mailbox"):
            continue
        try:
            value = validate_email(email_raw)
        except ValueError:
            continue
        score = EMAIL_SCAM_SCORE
        if len(row) > 1 and row[1].strip().isdigit():
            score = min(100, max(0, int(row[1].strip())))
        tags: list[str] = ["email-scam"]
        if len(row) > 2 and row[2].strip():
            tags.extend(t.strip() for t in row[2].split(";") if t.strip())
        source = row[3].strip() if len(row) > 3 and row[3].strip() else "EmailScamList"
        results.append(
            FeedIndicator(
                value=value,
                type="email",
                risk_score=score,
                tags=tags,
                meta={"source": source, "category": "email-scam"},
            )
        )
    return results


def parse_phone_scam_csv(content: str) -> list[FeedIndicator]:
    """
    Parse homelab phone scam CSV: phone,score,tags,source
    Header row optional. Tags semicolon-separated.
    """
    results: list[FeedIndicator] = []
    reader = csv.reader(io.StringIO(content))
    for row in reader:
        if not row or row[0].strip().startswith("#"):
            continue
        phone_raw = row[0].strip()
        if phone_raw.lower() in ("phone", "number", "e164"):
            continue
        try:
            value = validate_phone(phone_raw)
        except ValueError:
            continue
        score = PHONE_SCAM_SCORE
        if len(row) > 1 and row[1].strip().isdigit():
            score = min(100, max(0, int(row[1].strip())))
        tags: list[str] = ["phone-scam"]
        if len(row) > 2 and row[2].strip():
            tags.extend(t.strip() for t in row[2].split(";") if t.strip())
        source = row[3].strip() if len(row) > 3 and row[3].strip() else "PhoneScamList"
        results.append(
            FeedIndicator(
                value=value,
                type="phone",
                risk_score=score,
                tags=tags,
                meta={"source": source, "category": "phone-scam"},
            )
        )
    return results


def deduplicate_indicators(rows: list[FeedIndicator]) -> list[FeedIndicator]:
    """
    Deduplicate by (value, type). On conflict keep highest risk_score
    and merge tags/meta sources.
    """
    merged: dict[tuple[str, IndicatorType], FeedIndicator] = {}
    for row in rows:
        key = (row.value, row.type)
        if key not in merged:
            merged[key] = row
            continue
        existing = merged[key]
        tags = list(dict.fromkeys(existing.tags + row.tags))
        sources = list(
            dict.fromkeys(
                [existing.meta.get("source", "")]
                + ([row.meta.get("source", "")] if row.meta.get("source") else [])
            )
        )
        sources = [s for s in sources if s]
        meta = {**existing.meta, **row.meta, "sources": sources}
        merged[key] = FeedIndicator(
            value=row.value,
            type=row.type,
            risk_score=max(existing.risk_score, row.risk_score),
            tags=tags,
            meta=meta,
        )
    return list(merged.values())
