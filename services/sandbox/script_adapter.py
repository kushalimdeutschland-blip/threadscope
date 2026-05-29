"""
Example sandbox adapter — run your own analysis script out-of-process.

Configure:
  SANDBOX_BACKEND=script
  SANDBOX_SCRIPT=/path/to/your_analyzer.py

Your script must accept CLI args and print a JSON report on stdout:

  python your_analyzer.py --sample /path/to/file --kind apk --filename name.apk

Stdout JSON shape (fields optional except status):
  {
    "status": "completed",
    "risk_score": 75,
    "behaviors": ["..."],
    "network_iocs": ["1.2.3.4"],
    "signatures": ["..."],
    "tags": ["Custom"],
    "summary": "One-line summary"
  }

On failure: {"status": "failed", "error": "reason"}
"""

from __future__ import annotations

import asyncio
import json
import os
import time
import uuid
from pathlib import Path

from services.sandbox.base import DynamicReport, SandboxAdapter

_PENDING: dict[str, dict] = {}


class ScriptSandboxAdapter(SandboxAdapter):
    name = "script"

    def __init__(
        self,
        script_path: str,
        timeout: float = 300.0,
        delay_seconds: float = 0.0,
    ) -> None:
        self.script_path = Path(script_path)
        self.timeout = timeout
        self.delay_seconds = delay_seconds
        if not self.script_path.is_file():
            raise ValueError(f"SANDBOX_SCRIPT not found: {self.script_path}")

    async def submit(self, sample_path: Path, filename: str, file_kind: str) -> str:
        job_id = str(uuid.uuid4())
        _PENDING[job_id] = {
            "sample_path": str(sample_path),
            "filename": filename,
            "file_kind": file_kind,
            "ready_at": time.monotonic() + self.delay_seconds,
        }
        return job_id

    async def poll(self, external_job_id: str) -> tuple[str, DynamicReport | None]:
        entry = _PENDING.get(external_job_id)
        if entry is None:
            return "failed", DynamicReport(
                backend=self.name,
                status="failed",
                error="Unknown script job id",
            )

        if time.monotonic() < entry["ready_at"]:
            return "pending", None

        try:
            report = await asyncio.to_thread(self._run_script, entry)
            _PENDING.pop(external_job_id, None)
            if report.status == "failed":
                return "failed", report
            return "completed", report
        except Exception as exc:
            _PENDING.pop(external_job_id, None)
            return "failed", DynamicReport(
                backend=self.name,
                status="failed",
                error=str(exc)[:500],
            )

    def _run_script(self, entry: dict) -> DynamicReport:
        import subprocess

        cmd = [
            os.environ.get("SANDBOX_SCRIPT_PYTHON", "python3"),
            str(self.script_path),
            "--sample",
            entry["sample_path"],
            "--kind",
            entry["file_kind"],
            "--filename",
            entry["filename"],
        ]
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=self.timeout,
            check=False,
        )
        if proc.returncode != 0:
            err = proc.stderr.strip() or proc.stdout.strip() or f"exit {proc.returncode}"
            return DynamicReport(backend=self.name, status="failed", error=err[:500])

        try:
            data = json.loads(proc.stdout)
        except json.JSONDecodeError as exc:
            return DynamicReport(
                backend=self.name,
                status="failed",
                error=f"Invalid JSON from script: {exc}",
            )

        if data.get("status") == "failed":
            return DynamicReport(
                backend=self.name,
                status="failed",
                error=str(data.get("error") or "script reported failure"),
            )

        return DynamicReport(
            backend=self.name,
            status="completed",
            behaviors=list(data.get("behaviors") or []),
            network_iocs=list(data.get("network_iocs") or []),
            dropped_files=list(data.get("dropped_files") or []),
            signatures=list(data.get("signatures") or []),
            risk_score=int(data.get("risk_score") or 0),
            tags=list(data.get("tags") or []),
            summary=str(data.get("summary") or ""),
            raw=data,
        )
