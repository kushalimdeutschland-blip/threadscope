"""
Resolve sandbox backend and construct adapters.
"""

from __future__ import annotations

from urllib.parse import urlparse

import httpx

from config import Settings, get_settings
from services.sandbox.base import SandboxAdapter
from services.sandbox.cape import CapeSandboxAdapter
from services.sandbox.mock import MockSandboxAdapter
from services.sandbox.mobsf import MobSFSandboxAdapter

_ALLOWED_SANDBOX_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})


def assert_local_sandbox_url(url: str, name: str) -> str:
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError(f"{name} URL must use http or https")
    host = (parsed.hostname or "").lower()
    if host not in _ALLOWED_SANDBOX_HOSTS:
        raise ValueError(f"{name} URL must point to localhost only")
    return url.rstrip("/")


async def sandbox_reachable(base_url: str, path: str = "/") -> bool:
    try:
        async with httpx.AsyncClient(timeout=3.0) as client:
            resp = await client.get(f"{base_url.rstrip('/')}{path}")
            return resp.status_code < 500
    except (httpx.HTTPError, ValueError):
        return False


def get_adapter(backend: str, settings: Settings | None = None) -> SandboxAdapter:
    settings = settings or get_settings()
    if backend == "mock":
        return MockSandboxAdapter(delay_seconds=settings.sandbox_mock_delay)
    if backend == "mobsf":
        return MobSFSandboxAdapter(
            base_url=assert_local_sandbox_url(settings.mobsf_url, "MobSF"),
            api_key=settings.mobsf_api_key,
            timeout=settings.sandbox_job_timeout,
        )
    if backend == "cape":
        return CapeSandboxAdapter(
            base_url=assert_local_sandbox_url(settings.cape_url, "CAPE"),
            api_token=settings.cape_api_token,
            timeout=settings.sandbox_job_timeout,
        )
    if backend == "script":
        if not settings.sandbox_script:
            raise ValueError("SANDBOX_SCRIPT must be set when SANDBOX_BACKEND=script")
        from services.sandbox.script_adapter import ScriptSandboxAdapter

        return ScriptSandboxAdapter(
            script_path=settings.sandbox_script,
            timeout=settings.sandbox_job_timeout,
        )
    raise ValueError(f"Unknown sandbox backend: {backend}")


async def resolve_backend(ext: str, settings: Settings | None = None) -> str:
    """Pick sandbox backend for file extension (.exe / .apk)."""
    settings = settings or get_settings()
    mode = settings.sandbox_backend.lower()

    if mode == "off":
        raise ValueError("Dynamic sandbox analysis is disabled (SANDBOX_BACKEND=off)")

    if mode in ("mock", "mobsf", "cape", "script"):
        if mode == "mobsf" and ext != ".apk":
            raise ValueError("MobSF backend supports .apk only; use mock or cape for .exe")
        if mode == "cape" and ext != ".exe":
            raise ValueError("CAPE backend supports .exe only; use mock or mobsf for .apk")
        return mode

    # auto — homelab path: MobSF for APK; mock for EXE (CAPE requires KVM lab)
    if ext == ".apk":
        mobsf_url = assert_local_sandbox_url(settings.mobsf_url, "MobSF")
        if await sandbox_reachable(mobsf_url, "/"):
            return "mobsf"
        return "mock"

    if ext == ".exe":
        return "mock"

    raise ValueError(f"Unsupported extension for dynamic analysis: {ext}")
