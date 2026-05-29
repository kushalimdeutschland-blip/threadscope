"""
CAPEv2 REST client for Windows PE dynamic analysis.
Requires CAPE Docker profile with KVM (127.0.0.1:8002).
"""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path
from typing import Any

import httpx

from services.sandbox.base import DynamicReport, JobPollStatus, SandboxAdapter, merge_network_iocs

logger = logging.getLogger("threatscope.sandbox.cape")

_CAPE_STATUS_PENDING = frozenset({"pending", "running", "processing", "recovered"})


class CapeSandboxAdapter(SandboxAdapter):
    name = "cape"

    def __init__(self, base_url: str, api_token: str = "", timeout: float = 600.0) -> None:
        self._base = base_url.rstrip("/")
        self._token = api_token.strip()
        self._timeout = timeout

    def _headers(self) -> dict[str, str]:
        if self._token:
            return {"Authorization": f"Token {self._token}"}
        return {}

    async def submit(self, sample_path: Path, filename: str, file_kind: str) -> str:
        if file_kind != "exe":
            raise ValueError("CAPE adapter only supports PE (.exe) samples")

        async with httpx.AsyncClient(timeout=self._timeout, headers=self._headers()) as client:
            with sample_path.open("rb") as fh:
                resp = await client.post(
                    f"{self._base}/apiv2/tasks/create/file/",
                    files={"file": (filename, fh, "application/octet-stream")},
                )
            resp.raise_for_status()
            body = resp.json()
            task_id = str(body.get("task_id") or body.get("data", {}).get("task_ids", [None])[0])
            if not task_id or task_id == "None":
                raise RuntimeError(f"CAPE submit missing task_id: {body}")
        return f"cape-{task_id}"

    async def poll(self, external_job_id: str) -> tuple[JobPollStatus, DynamicReport | None]:
        task_id = external_job_id.removeprefix("cape-")

        async with httpx.AsyncClient(timeout=60.0, headers=self._headers()) as client:
            status_resp = await client.get(f"{self._base}/apiv2/tasks/status/{task_id}/")
            status_resp.raise_for_status()
            status_body = status_resp.json()
            status = (status_body.get("status") or status_body.get("data") or "").lower()

            if status in _CAPE_STATUS_PENDING:
                await asyncio.sleep(3)
                return "pending", None

            if status in ("failed", "failed_analysis", "failed_processing"):
                return "failed", DynamicReport(
                    backend=self.name,
                    status="failed",
                    error=status_body.get("error") or f"CAPE task failed: {status}",
                )

            report_resp = await client.get(f"{self._base}/apiv2/tasks/get/report/{task_id}/json/")
            if report_resp.status_code == 404:
                await asyncio.sleep(3)
                return "pending", None
            report_resp.raise_for_status()
            report = report_resp.json()

        return "completed", _normalize_cape_report(report, task_id)

    async def health_check(self) -> bool:
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.get(f"{self._base}/")
                return resp.status_code < 500
        except httpx.HTTPError:
            return False


def _normalize_cape_report(report: dict[str, Any], task_id: str) -> DynamicReport:
    behaviors: list[str] = []
    network: list[str] = []
    dropped: list[str] = []
    signatures: list[str] = []
    tags: list[str] = ["CAPE"]

    info = report.get("info") or {}
    score = int(info.get("score") or 0)
    if score <= 10:
        risk = score * 10
    else:
        risk = min(100, score)

    for sig in (report.get("signatures") or [])[:15]:
        if isinstance(sig, dict):
            name = sig.get("name") or sig.get("description")
            if name:
                signatures.append(str(name))
                sev = sig.get("severity", 0)
                if sev and int(sev) >= 2:
                    behaviors.append(str(name))
        elif isinstance(sig, str):
            signatures.append(sig)

    network_block = report.get("network") or {}
    if isinstance(network_block, dict):
        for host in network_block.get("hosts", [])[:20]:
            network.append(str(host))
        for domain in network_block.get("domains", [])[:20]:
            if isinstance(domain, dict):
                network.append(str(domain.get("domain", domain)))
            else:
                network.append(str(domain))

    for dropped_entry in (report.get("dropped") or [])[:10]:
        if isinstance(dropped_entry, dict) and dropped_entry.get("name"):
            dropped.append(str(dropped_entry["name"]))

    if behaviors:
        tags.append("Suspicious Behavior")
    if network:
        tags.append("Network Activity")

    return DynamicReport(
        backend="cape",
        status="completed",
        behaviors=behaviors[:15],
        network_iocs=merge_network_iocs(network),
        dropped_files=dropped,
        signatures=signatures[:15],
        risk_score=min(100, max(risk, 30 if signatures else 10)),
        tags=list(dict.fromkeys(tags)),
        summary=f"CAPE task {task_id} completed with {len(signatures)} signature(s).",
        raw={"task_id": task_id},
    )
