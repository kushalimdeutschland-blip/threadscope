"""Tests for sandbox adapters and report normalization."""

from __future__ import annotations

import asyncio
import tempfile
from pathlib import Path

import pytest

from services.analysis_merge import merge_dynamic_into_threat
from services.sandbox.base import DynamicReport
from services.sandbox.mock import MockSandboxAdapter


async def _run_mock_sandbox() -> None:
    adapter = MockSandboxAdapter(delay_seconds=0.2)
    with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as tmp:
        tmp.write(b"MZ" + b"\x00" * 64)
        path = Path(tmp.name)

    try:
        ext_id = await adapter.submit(path, "sample.exe", "exe")
        status = "pending"
        report = None
        for _ in range(20):
            status, report = await adapter.poll(ext_id)
            if status != "pending":
                break
            await asyncio.sleep(0.1)
        assert status == "completed"
        assert report is not None
        assert report.backend == "mock"
        assert report.risk_score > 0
        assert report.behaviors
    finally:
        path.unlink(missing_ok=True)


def test_mock_sandbox_completes():
    asyncio.run(_run_mock_sandbox())


def test_dynamic_report_roundtrip():
    report = DynamicReport(
        backend="mock",
        behaviors=["test"],
        network_iocs=["1.2.3.4"],
        risk_score=50,
    )
    restored = DynamicReport.from_dict(report.to_dict())
    assert restored.behaviors == ["test"]
    assert restored.network_iocs == ["1.2.3.4"]


def test_merge_dynamic_into_threat():
    static = {
        "value": "a.exe",
        "type": "file",
        "risk_score": 30,
        "tags": ["Static"],
        "findings": [],
        "meta": {"analysis_mode": "static"},
    }
    dynamic = DynamicReport(
        backend="mock",
        behaviors=["Network beacon"],
        risk_score=80,
        tags=["Dynamic"],
    )
    merged = merge_dynamic_into_threat(static, dynamic)
    assert merged["risk_score"] == 80
    assert "Dynamic" in merged["tags"]
    assert merged["meta"]["analysis_mode"] == "static+dynamic"
    assert any(f["title"] == "Dynamic behavior" for f in merged["findings"])
