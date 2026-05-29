"""
Passive indicator enrichment — local GeoIP, DNS resolution, actor hints from feeds.
No active probing of targets.
"""

from __future__ import annotations

import ipaddress
import socket
from pathlib import Path
from typing import Any

from config import get_settings
from services.validation import IndicatorType, email_domain

settings = get_settings()

_country_reader = None
_asn_reader = None


def _load_readers() -> tuple[Any | None, Any | None]:
    global _country_reader, _asn_reader
    if _country_reader is not None or _asn_reader is not None:
        return _country_reader, _asn_reader

    if not settings.enrichment_enabled:
        return None, None

    try:
        import geoip2.database
    except ImportError:
        return None, None

    country_path = Path(settings.geolite2_country_path)
    asn_path = Path(settings.geolite2_asn_path)

    if country_path.is_file():
        try:
            _country_reader = geoip2.database.Reader(str(country_path))
        except OSError:
            _country_reader = None

    if asn_path.is_file():
        try:
            _asn_reader = geoip2.database.Reader(str(asn_path))
        except OSError:
            _asn_reader = None

    return _country_reader, _asn_reader


def _geoip_for_ip(ip_str: str) -> dict[str, Any]:
    country_reader, asn_reader = _load_readers()
    out: dict[str, Any] = {"ip": ip_str}

    if country_reader is not None:
        try:
            rec = country_reader.country(ip_str)
            out["country_code"] = rec.country.iso_code
            out["country_name"] = rec.country.name
        except Exception:
            pass

    if asn_reader is not None:
        try:
            rec = asn_reader.asn(ip_str)
            out["asn"] = rec.autonomous_system_number
            out["asn_org"] = rec.autonomous_system_organization
        except Exception:
            pass

    return out


def _resolve_domain_ips(domain: str) -> list[str]:
    ips: list[str] = []
    try:
        for family, _, _, _, sockaddr in socket.getaddrinfo(domain, None):
            if family == socket.AF_INET:
                ips.append(sockaddr[0])
            elif family == socket.AF_INET6:
                ips.append(sockaddr[0])
    except (socket.gaierror, OSError):
        return []
    seen: set[str] = set()
    unique: list[str] = []
    for ip in ips:
        if ip not in seen:
            seen.add(ip)
            unique.append(ip)
    return unique[:8]


def _actor_hints(tags: list[str], meta: dict[str, Any]) -> list[str]:
    hints: list[str] = []
    family = meta.get("malware_family") or meta.get("threat_type")
    if isinstance(family, str) and family.strip():
        hints.append(family.strip())

    apt_keywords = ("apt", "lazarus", "fin", "sandworm", "emotet", "cobalt", "ransom")
    for tag in tags:
        if not isinstance(tag, str):
            continue
        t = tag.strip()
        if not t:
            continue
        lower = t.lower()
        if any(k in lower for k in apt_keywords) or t.isupper():
            if t not in hints:
                hints.append(t)
    return hints[:10]


async def enrich_indicator(
    value: str,
    indicator_type: IndicatorType,
    *,
    tags: list[str] | None = None,
    meta: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build passive enrichment block for threat.meta.enrichment."""
    tags = tags or []
    meta = meta or {}
    enrichment: dict[str, Any] = {}

    actor_hints = _actor_hints(tags, meta)
    if actor_hints:
        enrichment["actor_hints"] = actor_hints

    if indicator_type in ("ipv4", "ipv6"):
        try:
            ipaddress.ip_address(value)
        except ValueError:
            return enrichment
        geo = _geoip_for_ip(value)
        if len(geo) > 1:
            enrichment["geoip"] = geo

    elif indicator_type == "domain":
        ips = _resolve_domain_ips(value)
        if ips:
            enrichment["resolved_ips"] = ips
            enrichment["geoip"] = [_geoip_for_ip(ip) for ip in ips[:4]]

    elif indicator_type == "email":
        domain = email_domain(value)
        enrichment["email_domain"] = domain
        ips = _resolve_domain_ips(domain)
        if ips:
            enrichment["resolved_ips"] = ips
            enrichment["geoip"] = [_geoip_for_ip(ip) for ip in ips[:4]]

    return enrichment
