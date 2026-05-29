"""
URLhaus Service
---------------
Completely free, no API key required.
Docs: https://urlhaus-api.abuse.ch/

Returns: malware URL count, threat type, tags for a given domain or hash.
"""

import httpx

BASE_URL = "https://urlhaus-api.abuse.ch/v1/"


async def check_urlhaus_domain(client: httpx.AsyncClient, domain: str) -> dict:
    try:
        resp = await client.post(
            f"{BASE_URL}host/",
            data={"host": domain},
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        resp.raise_for_status()
        body = resp.json()

        if body.get("query_status") == "no_results":
            return {}

        urls      = body.get("urls", [])
        active    = sum(1 for u in urls if u.get("url_status") == "online")
        url_count = len(urls)

        # Gather threat tags from URL entries
        tags = list({u.get("threat") for u in urls if u.get("threat")})

        # Score: if there are active malicious URLs, it's serious
        score = 0
        if url_count > 0:
            score = 90 if active > 0 else 60

        return {
            "score":     score,
            "reports":   url_count,
            "last_seen": urls[0].get("date_added") if urls else None,
            "tags":      tags[:4],
        }

    except (httpx.RequestError, KeyError):
        return {}


async def check_urlhaus_hash(client: httpx.AsyncClient, file_hash: str) -> dict:
    try:
        # Detect hash type by length
        if len(file_hash) == 32:
            payload = {"md5_hash": file_hash}
        elif len(file_hash) == 64:
            payload = {"sha256_hash": file_hash}
        else:
            return {}

        resp = await client.post(
            f"{BASE_URL}payload/",
            data=payload,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        resp.raise_for_status()
        body = resp.json()

        if body.get("query_status") == "no_results":
            return {}

        urls = body.get("urls", [])

        return {
            "score":   85 if urls else 0,
            "reports": len(urls),
            "tags":    list({u.get("threat") for u in urls if u.get("threat")})[:4],
        }

    except (httpx.RequestError, KeyError):
        return {}
