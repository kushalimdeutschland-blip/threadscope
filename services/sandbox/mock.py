"""
Mock sandbox for local development — no Docker or VMs required.
"""

from __future__ import annotations

import asyncio
import time
from pathlib import Path

from services.sandbox.base import DynamicReport, JobPollStatus, SandboxAdapter

_MOCK_JOBS: dict[str, dict] = {}


class MockSandboxAdapter(SandboxAdapter):
    name = "mock"

    def __init__(self, delay_seconds: float = 6.0) -> None:
        self._delay = delay_seconds

    async def submit(self, sample_path: Path, filename: str, file_kind: str) -> str:
        job_id = f"mock-{int(time.time() * 1000)}-{sample_path.stat().st_size}"
        _MOCK_JOBS[job_id] = {
            "submitted_at": time.monotonic(),
            "filename": filename,
            "file_kind": file_kind,
            "ready": False,
        }
        return job_id

    async def poll(self, external_job_id: str) -> tuple[JobPollStatus, DynamicReport | None]:
        entry = _MOCK_JOBS.get(external_job_id)
        if entry is None:
            return "failed", DynamicReport(
                backend=self.name,
                status="failed",
                error="Unknown mock job id",
            )

        elapsed = time.monotonic() - entry["submitted_at"]
        if elapsed < self._delay:
            await asyncio.sleep(min(1.0, self._delay - elapsed))
            if time.monotonic() - entry["submitted_at"] < self._delay:
                return "pending", None

        file_kind = entry["file_kind"]
        if file_kind == "apk":
            report = DynamicReport(
                backend=self.name,
                status="completed",
                behaviors=[
                    "Mock: attempted HTTP connection to suspicious host",
                    "Mock: read device identifiers",
                ],
                network_iocs=["10.0.0.1", "evil-mock.example.com"],
                signatures=["Mock.Android.Spyware.Generic"],
                risk_score=72,
                tags=["Mock Sandbox", "Suspicious Network"],
                summary="Mock dynamic analysis (APK): simulated C2 beacon and data exfiltration behaviors.",
                raw={"mode": "mock", "file_kind": file_kind},
            )
        else:
            report = DynamicReport(
                backend=self.name,
                status="completed",
                behaviors=[
                    "Mock: created remote thread in explorer.exe",
                    "Mock: wrote file to %TEMP%",
                    "Mock: registry Run key modification",
                ],
                network_iocs=["198.51.100.50", "mock-c2.example.net"],
                dropped_files=["mock_payload.dll"],
                signatures=["Mock.Win32.Trojan.Generic"],
                risk_score=78,
                tags=["Mock Sandbox", "Process Injection"],
                summary="Mock dynamic analysis (EXE): simulated process injection and persistence.",
                raw={"mode": "mock", "file_kind": file_kind},
            )

        del _MOCK_JOBS[external_job_id]
        return "completed", report
