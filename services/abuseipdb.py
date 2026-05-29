"""
AbuseIPDB Service
-----------------
Free tier: 1,000 checks/day
Docs: https://docs.abuseipdb.com/#check-endpoint
Get key: https://www.abuseipdb.com/register

Returns: abuse confidence score (0–100), report count, country, ISP, tags
"""

import os
import httpx

ABUSEIPDB_KEY = os.getenv("ABUSEIPDB_API_KEY", "")
BASE_URL = "https://api.abuseipdb.com/api/v2/check"

# Maps AbuseIPDB category IDs to human-readable tags
CATEGORY_MAP = {
    3:  "Fraud Orders",       9:  "Open Proxy",        10: "Web Spam",
    11: "Email Spam",         14: "Port Scan",          15: "Hacking",
    16: "SQL Injection",      17: "Spoofing",           18: "Brute Force",
    19: "Bad Web Bot",        20: "Exploited Host",     21: "Web App Attack",
    22: "SSH Abuse",          23: "IoT Targeted",
}


async def check_abuseipdb(client: httpx.AsyncClient, ip: str) -> dict:
    if not ABUSEIPDB_KEY:
        return _mock_fallback(ip)

    try:
        resp = await client.get(
            BASE_URL,
            headers={"Key": ABUSEIPDB_KEY, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": True},
        )
        resp.raise_for_status()
        data = resp.json().get("data", {})

        # Gather unique tags from recent reports
        category_ids = set()
        for report in data.get("reports", [])[:50]:
            category_ids.update(report.get("categories", []))
        tags = [CATEGORY_MAP.get(c, f"Cat-{c}") for c in category_ids if c in CATEGORY_MAP]

        # Add ISP-derived tag for known bad ASNs
        isp = data.get("isp", "")
        if any(k in isp.lower() for k in ["tor", "vpn", "proxy", "anonymous"]):
            tags.append("Anonymizer")

        return {
            "score":    data.get("abuseConfidenceScore", 0),
            "reports":  data.get("totalReports", 0),
            "country":  data.get("countryCode"),
            "asn":      f"AS{data.get('asnId', '')} {isp}".strip(),
            "last_seen": data.get("lastReportedAt"),
            "tags":     tags,
        }

    except httpx.HTTPStatusError as e:
        if e.response.status_code == 429:
            return {"error": "AbuseIPDB rate limit hit"}
        raise


def _mock_fallback(ip: str) -> dict:
    """
    Returns empty dict when no API key is configured.
    The caller will skip this source gracefully.
    """
    return {}
