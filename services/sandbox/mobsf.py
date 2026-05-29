"""
MobSF REST client for APK dynamic/static sandbox scans.
Requires MobSF Docker profile (127.0.0.1:8001).
"""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path
from typing import Any

import httpx

from services.sandbox.base import DynamicReport, JobPollStatus, SandboxAdapter, merge_network_iocs

logger = logging.getLogger("threatscope.sandbox.mobsf")

_PENDING: dict[str, dict[str, Any]] = {}


class MobSFSandboxAdapter(SandboxAdapter):
    name = "mobsf"

    def __init__(self, base_url: str, api_key: str = "", timeout: float = 600.0) -> None:
        self._base = base_url.rstrip("/")
        self._api_key = api_key.strip()
        self._timeout = timeout

    def _headers(self) -> dict[str, str]:
        headers: dict[str, str] = {}
        if self._api_key:
            headers["Authorization"] = self._api_key
        return headers

    async def submit(self, sample_path: Path, filename: str, file_kind: str) -> str:
        if file_kind != "apk":
            raise ValueError("MobSF adapter only supports APK samples")

        async with httpx.AsyncClient(timeout=self._timeout, headers=self._headers()) as client:
            with sample_path.open("rb") as fh:
                resp = await client.post(
                    f"{self._base}/api/v1/upload",
                    files={"file": (filename, fh, "application/vnd.android.package-archive")},
                )
            resp.raise_for_status()
            body = resp.json()
            scan_hash = body.get("hash") or body.get("sha256")
            if not scan_hash:
                raise RuntimeError(f"MobSF upload missing hash: {body}")

            scan_resp = await client.post(
                f"{self._base}/api/v1/scan",
                data={"hash": scan_hash, "re_scan": "0"},
            )
            scan_resp.raise_for_status()

        job_id = f"mobsf-{scan_hash}"
        _PENDING[job_id] = {"hash": scan_hash, "submitted": True}
        return job_id

    async def poll(self, external_job_id: str) -> tuple[JobPollStatus, DynamicReport | None]:
        meta = _PENDING.get(external_job_id)
        if meta is None:
            scan_hash = external_job_id.removeprefix("mobsf-")
        else:
            scan_hash = meta["hash"]

        async with httpx.AsyncClient(timeout=60.0, headers=self._headers()) as client:
            resp = await client.get(
                f"{self._base}/api/v1/report_json",
                params={"hash": scan_hash},
            )
            if resp.status_code == 404:
                return "pending", None
            resp.raise_for_status()
            report = resp.json()

        if not _scan_complete(report):
            await asyncio.sleep(2)
            return "pending", None

        normalized = _normalize_report(report, scan_hash)
        _PENDING.pop(external_job_id, None)
        return "completed", normalized

    async def health_check(self) -> bool:
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.get(f"{self._base}/")
                return resp.status_code < 500
        except httpx.HTTPError:
            return False


def _scan_complete(report: dict[str, Any]) -> bool:
    if report.get("scan_type") or report.get("app_name"):
        return True
    return bool(report.get("virus_total") or report.get("permissions"))


def _normalize_report(report: dict[str, Any], scan_hash: str) -> DynamicReport:
    behaviors: list[str] = []
    tags: list[str] = []
    signatures: list[str] = []
    network: list[str] = []

    score = int(report.get("average_cvss") or 0)
    if score < 1:
        score = int(report.get("security_score") or 0)
    risk = min(100, max(score, 40 if report.get("virus_total") else 20))

    vt = report.get("virus_total") or {}
    if isinstance(vt, dict) and vt.get("detections"):
        tags.append("MobSF Detections")
        behaviors.append(f"VirusTotal detections: {vt.get('detections')}")

    perms = report.get("permissions") or {}
    if isinstance(perms, dict):
        dangerous = [k for k, v in perms.items() if v == "dangerous"]
        if dangerous:
            behaviors.append(f"Dangerous permissions: {', '.join(dangerous[:5])}")
            tags.append("Dangerous Permissions")

    urls = report.get("urls") or []
    if isinstance(urls, list):
        for u in urls[:20]:
            if isinstance(u, str):
                network.append(u)
            elif isinstance(u, dict) and u.get("urls"):
                network.append(str(u["urls"]))

    domains = report.get("domains") or {}
    if isinstance(domains, dict):
        network.extend(list(domains.keys())[:20])

    malware = report.get("malware_permissions") or []
    if malware:
        signatures.append("Suspicious permission combinations")
        tags.append("Suspicious Permissions")

    tracker = report.get("trackers") or {}
    if isinstance(tracker, dict) and tracker.get("detected_trackers"):
        behaviors.append(f"Trackers detected: {tracker.get('detected_trackers')}")
        tags.append("Trackers")

    return DynamicReport(
        backend="mobsf",
        status="completed",
        behaviors=behaviors[:15],
        network_iocs=merge_network_iocs(network),
        signatures=signatures,
        risk_score=risk,
        tags=list(dict.fromkeys(tags + ["MobSF"])),
        summary=f"MobSF scan complete for {report.get('app_name', scan_hash[:12])}.",
        raw={"hash": scan_hash, "package": report.get("package_name")},
    )
