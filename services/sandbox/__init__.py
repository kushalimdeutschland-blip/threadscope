"""Isolated sandbox adapters for optional dynamic file analysis."""

from services.sandbox.base import DynamicReport, SandboxAdapter
from services.sandbox.registry import get_adapter, resolve_backend

__all__ = ["DynamicReport", "SandboxAdapter", "get_adapter", "resolve_backend"]
