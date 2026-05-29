"""
Shodan Service
--------------
Free tier: 1 API credit/query (free account gets limited credits)
Get key: https://account.shodan.io/
Docs: https://developer.shodan.io/api

Returns: open ports, services, known CVEs, country, ISP.
Note: Shodan free tier doesn't support full API — use sparingly.
Consider caching aggressively (TTL: 24h) to preserve credits.
"""

import os
import httpx

SHODAN_KEY = os.getenv("SHODAN_API_KEY", "")
BASE_URL   = "https://api.shodan.io/shodan/host"


async def check_shodan(client: httpx.AsyncClient, ip: str) -> dict:
    if not SHODAN_KEY:
        return {}

    try:
        resp = await client.get(
            f"{BASE_URL}/{ip}",
            params={"key": SHODAN_KEY},
        )

        if resp.status_code == 404:
            return {}           # IP not indexed by Shodan
        resp.raise_for_status()

        data = resp.json()

        open_ports = sorted(data.get("ports", []))
        vulns      = list(data.get("vulns", {}).keys())   # e.g. ["CVE-2021-44228"]

        # Build service tags from banner data
        service_tags = []
        for item in data.get("data", [])[:10]:
            product = item.get("product")
            if product:
                service_tags.append(product)
        service_tags = list(set(service_tags))[:5]

        # Tag known dangerous ports
        danger_ports = {21: "FTP", 23: "Telnet", 445: "SMB", 3389: "RDP", 5900: "VNC"}
        port_tags = [danger_ports[p] for p in open_ports if p in danger_ports]

        tags = list(set(service_tags + port_tags))
        if vulns:
            tags.append(f"{len(vulns)} CVE(s)")

        return {
            "open_ports": open_ports[:20],
            "vulns":      vulns[:10],
            "country":    data.get("country_name"),
            "asn":        data.get("asn"),
            "org":        data.get("org"),
            "tags":       tags,
        }

    except httpx.HTTPStatusError:
        return {}
    except httpx.RequestError:
        return {}
