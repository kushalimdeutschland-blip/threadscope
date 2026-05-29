"""
VirusTotal Service
------------------
Free tier: 500 requests/day, 4 requests/minute
Docs: https://docs.virustotal.com/reference/overview
Get key: https://www.virustotal.com/gui/join-us

Covers: IP reputation, domain reputation, file hash analysis
"""

import os
import httpx

VT_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
BASE   = "https://www.virustotal.com/api/v3"
HEADERS = {"x-apikey": VT_KEY}


# ─── IP ───────────────────────────────────────────────────────────────────────

async def check_virustotal_ip(client: httpx.AsyncClient, ip: str) -> dict:
    if not VT_KEY:
        return {}
    try:
        resp = await client.get(f"{BASE}/ip_addresses/{ip}", headers=HEADERS)
        resp.raise_for_status()
        attrs = resp.json().get("data", {}).get("attributes", {})

        stats      = attrs.get("last_analysis_stats", {})
        malicious  = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        total      = sum(stats.values())

        score = _detection_score(malicious, suspicious, total)
        tags  = _extract_tags(attrs)

        return {
            "score":      score,
            "detections": malicious + suspicious,
            "total_engines": total,
            "last_seen":  attrs.get("last_modification_date"),
            "tags":       tags,
            "country":    attrs.get("country"),
            "asn":        f"AS{attrs.get('asn', '')} {attrs.get('as_owner', '')}".strip(),
        }
    except httpx.HTTPStatusError:
        return {}


# ─── Domain ───────────────────────────────────────────────────────────────────

async def check_virustotal_domain(client: httpx.AsyncClient, domain: str) -> dict:
    if not VT_KEY:
        return {}
    try:
        resp = await client.get(f"{BASE}/domains/{domain}", headers=HEADERS)
        resp.raise_for_status()
        attrs = resp.json().get("data", {}).get("attributes", {})

        stats      = attrs.get("last_analysis_stats", {})
        malicious  = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        total      = sum(stats.values())

        score = _detection_score(malicious, suspicious, total)

        # Registrar and creation date from WHOIS
        whois = attrs.get("whois", "")
        registrar = _extract_whois_field(whois, "Registrar:")
        created   = _extract_whois_field(whois, "Creation Date:")

        # VT categories (e.g., "phishing", "malware")
        categories = list(attrs.get("categories", {}).values())

        return {
            "score":       score,
            "detections":  malicious + suspicious,
            "total_engines": total,
            "last_seen":   attrs.get("last_modification_date"),
            "registrar":   registrar,
            "created":     created[:10] if created else None,
            "categories":  categories,
            "tags":        _extract_tags(attrs) + (["Phishing"] if "phishing" in str(categories).lower() else []),
        }
    except httpx.HTTPStatusError:
        return {}


# ─── Hash ─────────────────────────────────────────────────────────────────────

async def check_virustotal_hash(client: httpx.AsyncClient, file_hash: str) -> dict:
    if not VT_KEY:
        return {}
    try:
        resp = await client.get(f"{BASE}/files/{file_hash}", headers=HEADERS)
        resp.raise_for_status()
        attrs = resp.json().get("data", {}).get("attributes", {})

        stats      = attrs.get("last_analysis_stats", {})
        malicious  = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        total      = sum(stats.values())

        score    = _detection_score(malicious, suspicious, total)
        families = list(attrs.get("popular_threat_classification", {})
                         .get("popular_threat_name", [{}])[0].get("value", ""))

        size_bytes = attrs.get("size", 0)
        size_str   = f"{size_bytes / 1024 / 1024:.2f} MB" if size_bytes > 1024*1024 else f"{size_bytes / 1024:.1f} KB"

        return {
            "score":         score,
            "detections":    malicious + suspicious,
            "total_engines": total,
            "filetype":      attrs.get("type_description"),
            "file_size":     size_str if size_bytes else None,
            "last_seen":     attrs.get("last_submission_date"),
            "tags":          attrs.get("tags", [])[:5],
            "malware_family": "".join(families) if families else None,
        }
    except httpx.HTTPStatusError:
        return {}


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _detection_score(malicious: int, suspicious: int, total: int) -> int:
    """Convert raw detection counts to a 0-100 risk score."""
    if total == 0:
        return 0
    weighted = (malicious * 1.0 + suspicious * 0.5) / total
    return min(100, int(weighted * 150))  # scale so even 50% = 75 score


def _extract_tags(attrs: dict) -> list[str]:
    tags = []
    if attrs.get("tags"):
        tags.extend(attrs["tags"][:5])
    threat_names = attrs.get("popular_threat_classification", {}).get("popular_threat_name", [])
    for t in threat_names[:2]:
        v = t.get("value")
        if v:
            tags.append(v.title())
    return list(set(tags))


def _extract_whois_field(whois: str, field: str) -> str | None:
    for line in whois.splitlines():
        if line.strip().startswith(field):
            return line.split(":", 1)[-1].strip()
    return None
