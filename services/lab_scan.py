"""
Opt-in homelab active scanning — safe nmap/ping subprocess helpers.
Runs only from scripts/scan_worker.py, never from the web process.
"""

from __future__ import annotations

import ipaddress
import re
import shlex
import socket
import subprocess
import xml.etree.ElementTree as ET
from typing import Any

from config import get_settings
from services.validation import IndicatorType

settings = get_settings()

_NMAP_PORT_RE = re.compile(r"^(\d+)/(\w+)$")


def resolve_scan_target(value: str, indicator_type: IndicatorType) -> tuple[str, str | None]:
    """
    Return (scan_host, resolved_ip) for nmap.
    For domains, resolves first A/AAAA record.
    """
    if indicator_type in ("ipv4", "ipv6"):
        return value, value

    if indicator_type == "domain":
        try:
            infos = socket.getaddrinfo(value, None, type=socket.SOCK_STREAM)
        except (socket.gaierror, OSError) as exc:
            raise ValueError(f"Could not resolve domain: {value}") from exc
        for family, _, _, _, sockaddr in infos:
            ip = sockaddr[0]
            if family == socket.AF_INET:
                return ip, ip
        for family, _, _, _, sockaddr in infos:
            ip = sockaddr[0]
            if family == socket.AF_INET6:
                return ip, ip
        raise ValueError(f"Could not resolve domain: {value}")

    raise ValueError(f"Lab scan not supported for type: {indicator_type}")


def validate_scan_allowed(host: str) -> None:
    """Raise ValueError if target is blocked by lab scan policy."""
    try:
        addr = ipaddress.ip_address(host)
    except ValueError as exc:
        raise ValueError(f"Invalid scan target: {host}") from exc

    if not settings.lab_scan_allow_private:
        if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_multicast:
            raise ValueError(
                "Private/reserved IPs are blocked. Set LAB_SCAN_ALLOW_PRIVATE=1 for homelab targets."
            )

    deny_raw = settings.lab_scan_deny_cidrs.strip()
    if deny_raw:
        for part in deny_raw.split(","):
            part = part.strip()
            if not part:
                continue
            try:
                net = ipaddress.ip_network(part, strict=False)
            except ValueError:
                continue
            if addr in net:
                raise ValueError(f"Target {host} is in denied range {part}")


def build_nmap_argv(host: str) -> list[str]:
    """Safe homelab nmap profile — TCP connect, top 50 ports, no scripts."""
    return [
        settings.nmap_path,
        "-Pn",
        "-sT",
        "-sV",
        "--top-ports",
        "50",
        "--open",
        "-oX",
        "-",
        host,
    ]


def build_ping_argv(host: str) -> list[str]:
    return [settings.ping_path, "-c", "1", "-W", "2", host]


def run_ping(host: str, timeout: float = 5.0) -> dict[str, Any]:
    argv = build_ping_argv(host)
    try:
        proc = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"host_up": False, "error": str(exc)}

    host_up = proc.returncode == 0
    rtt_ms: float | None = None
    if host_up:
        for line in proc.stdout.splitlines():
            if "time=" in line:
                try:
                    part = line.split("time=")[1].split()[0]
                    rtt_ms = float(part.replace("ms", ""))
                except (IndexError, ValueError):
                    pass
                break

    return {"host_up": host_up, "rtt_ms": rtt_ms}


def run_nmap(host: str, timeout: float | None = None) -> dict[str, Any]:
    timeout = timeout or settings.lab_scan_job_timeout
    argv = build_nmap_argv(host)
    try:
        proc = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"error": str(exc), "open_ports": []}

    if proc.returncode not in (0, 1):
        err = (proc.stderr or proc.stdout or "nmap failed").strip()[:500]
        return {"error": err, "open_ports": []}

    return _parse_nmap_xml(proc.stdout)


def _parse_nmap_xml(xml_text: str) -> dict[str, Any]:
    open_ports: list[dict[str, Any]] = []
    host_up = False

    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return {"host_up": False, "open_ports": [], "error": "Failed to parse nmap output"}

    for host in root.findall("host"):
        status = host.find("status")
        if status is not None and status.get("state") == "up":
            host_up = True
        for port_el in host.findall(".//port"):
            state = port_el.find("state")
            if state is None or state.get("state") != "open":
                continue
            port_id = port_el.get("portid", "")
            proto = port_el.get("protocol", "tcp")
            service_el = port_el.find("service")
            service_name = service_el.get("name", "") if service_el is not None else ""
            product = service_el.get("product", "") if service_el is not None else ""
            version = service_el.get("version", "") if service_el is not None else ""
            open_ports.append({
                "port": int(port_id) if port_id.isdigit() else port_id,
                "protocol": proto,
                "service": service_name,
                "product": product,
                "version": version,
            })

    open_ports.sort(key=lambda p: int(p["port"]) if isinstance(p["port"], int) else 0)
    return {
        "host_up": host_up,
        "open_ports": open_ports,
        "port_count": len(open_ports),
        "command": " ".join(shlex.quote(a) for a in build_nmap_argv("TARGET")),
    }


def run_lab_scan(host: str) -> dict[str, Any]:
    """Execute ping + nmap and return merged report."""
    ping = run_ping(host)
    nmap = run_nmap(host)
    return {
        "target": host,
        "ping": ping,
        "nmap": nmap,
        "host_up": ping.get("host_up") or nmap.get("host_up", False),
        "open_ports": nmap.get("open_ports", []),
    }
