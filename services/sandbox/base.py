"""
Sandbox adapter interface and normalized dynamic analysis reports.
Samples are analyzed out-of-process; never executed inside FastAPI.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Literal

JobPollStatus = Literal["pending", "completed", "failed"]


@dataclass
class DynamicReport:
    """Normalized dynamic analysis result for UI and Ollama summaries."""

    backend: str
    status: Literal["completed", "failed"] = "completed"
    behaviors: list[str] = field(default_factory=list)
    network_iocs: list[str] = field(default_factory=list)
    dropped_files: list[str] = field(default_factory=list)
    signatures: list[str] = field(default_factory=list)
    risk_score: int = 0
    tags: list[str] = field(default_factory=list)
    summary: str = ""
    raw: dict[str, Any] = field(default_factory=dict)
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> DynamicReport:
        return cls(
            backend=str(data.get("backend", "unknown")),
            status=data.get("status", "completed"),
            behaviors=list(data.get("behaviors") or []),
            network_iocs=list(data.get("network_iocs") or []),
            dropped_files=list(data.get("dropped_files") or []),
            signatures=list(data.get("signatures") or []),
            risk_score=int(data.get("risk_score") or 0),
            tags=list(data.get("tags") or []),
            summary=str(data.get("summary") or ""),
            raw=dict(data.get("raw") or {}),
            error=data.get("error"),
        )


class SandboxAdapter(ABC):
    """Submit samples to an isolated sandbox and poll for results."""

    name: str

    @abstractmethod
    async def submit(self, sample_path: Path, filename: str, file_kind: str) -> str:
        """Upload sample; return external sandbox task/scan id."""

    @abstractmethod
    async def poll(self, external_job_id: str) -> tuple[JobPollStatus, DynamicReport | None]:
        """Return (pending|completed|failed, report when finished)."""


def merge_network_iocs(*sources: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for items in sources:
        for item in items:
            key = item.strip().lower()
            if key and key not in seen:
                seen.add(key)
                out.append(item.strip())
    return out[:50]
