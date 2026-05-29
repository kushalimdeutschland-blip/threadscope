#!/usr/bin/env python3
"""Populate the local indicators database with sample data for all indicator types."""

import asyncio
from datetime import datetime, timezone

from database import DB_PATH, init_db, upsert_indicator

MALICIOUS_IPV4 = [
    ("185.220.101.45", 97, ["Tor Exit Node", "Brute Force", "SSH Abuse"]),
    ("45.155.205.233", 92, ["C2", "Emotet", "Malware Distribution"]),
    ("103.253.145.192", 88, ["Scanner", "Exploit Attempt"]),
    ("194.26.192.35", 85, ["Phishing", "Credential Harvesting"]),
    ("89.248.165.53", 82, ["Open Proxy", "Spam"]),
]

CLEAN_IPV4 = [
    ("8.8.8.8", 0, []),
    ("1.1.1.1", 0, []),
    ("208.67.222.222", 2, ["Public DNS"]),
]

MALICIOUS_IPV6 = [
    ("2001:db8:dead:beef::1", 90, ["Scanner", "Brute Force"]),
    ("2a00:1450:4001:812::200e", 75, ["Suspicious Traffic"]),
]

CLEAN_IPV6 = [
    ("2001:4860:4860::8888", 0, ["Public DNS"]),
    ("2606:4700:4700::1111", 0, []),
]

MALICIOUS_DOMAINS = [
    ("malware-c2.ru", 95, ["C2", "Malware"], {"category": "command-and-control"}),
    ("phish-login.xyz", 88, ["Phishing", "Credential Theft"], {"category": "phishing"}),
    ("bad-payload.biz", 82, ["Malware Distribution"], {"category": "dropper"}),
    ("spam-tracker.top", 70, ["Spam", "Tracking"], {}),
]

CLEAN_DOMAINS = [
    ("google.com", 0, [], {}),
    ("cloudflare.com", 2, ["CDN"], {"category": "infrastructure"}),
]

MALICIOUS_HASHES = [
    (
        "44d88612fea8a8f36de82e1278abb02f",
        98,
        ["EICAR", "Test Malware"],
        {"hash_type": "md5", "malware_family": "EICAR-Test-File", "filetype": "text/plain"},
    ),
    (
        "3395856c81b195f0b4119a511a3b99614992eb6",
        94,
        ["TrickBot"],
        {"hash_type": "sha1", "malware_family": "TrickBot", "filetype": "application/x-dosexec"},
    ),
    (
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        91,
        ["Suspicious"],
        {"hash_type": "sha256", "malware_family": "Unknown", "filetype": "application/octet-stream"},
    ),
]


async def main() -> None:
    await init_db()
    now = datetime.now(timezone.utc).isoformat()

    for ip, score, tags in MALICIOUS_IPV4 + CLEAN_IPV4:
        await upsert_indicator(ip, "ipv4", score, tags, last_updated=now)

    for ip, score, tags in MALICIOUS_IPV6 + CLEAN_IPV6:
        await upsert_indicator(ip, "ipv6", score, tags, last_updated=now)

    for domain, score, tags, meta in MALICIOUS_DOMAINS + CLEAN_DOMAINS:
        await upsert_indicator(domain, "domain", score, tags, meta=meta, last_updated=now)

    for h, score, tags, meta in MALICIOUS_HASHES:
        await upsert_indicator(h, "hash", score, tags, meta=meta, last_updated=now)

    total = (
        len(MALICIOUS_IPV4) + len(CLEAN_IPV4)
        + len(MALICIOUS_IPV6) + len(CLEAN_IPV6)
        + len(MALICIOUS_DOMAINS) + len(CLEAN_DOMAINS)
        + len(MALICIOUS_HASHES)
    )
    print(f"Seeded {total} indicators into {DB_PATH}")


if __name__ == "__main__":
    asyncio.run(main())
