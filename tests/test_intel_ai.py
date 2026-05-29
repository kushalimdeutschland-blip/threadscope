"""Intel AI: ingest summaries, lookup context, query expansion."""

from __future__ import annotations

import asyncio
import json
from unittest.mock import AsyncMock, patch

import pytest

import database
from config import get_settings
from services.intel import ai as intel_ai
from services.intel.context import attach_intel_context
from services.intel.search import search_intel_with_ai
from services.lookup import lookup_indicator


@pytest.fixture
def temp_db(monkeypatch, tmp_path):
    db_path = tmp_path / "intel_ai_test.db"
    monkeypatch.setattr(database, "DB_PATH", db_path)

    async def _setup():
        await database.close_read_pool()
        await database.init_db()

    async def _teardown():
        await database.close_read_pool()

    asyncio.run(_setup())
    yield db_path
    asyncio.run(_teardown())


@pytest.fixture
def intel_ai_on(monkeypatch):
    settings = get_settings()
    monkeypatch.setattr(settings, "intel_ai_enabled", True)
    monkeypatch.setattr(settings, "intel_ai_ingest_summary", True)
    monkeypatch.setattr(settings, "intel_ai_lookup_context", True)
    monkeypatch.setattr(settings, "intel_ai_query_expand", True)
    yield settings


@pytest.fixture
def intel_ai_off(monkeypatch):
    settings = get_settings()
    monkeypatch.setattr(settings, "intel_ai_enabled", False)
    yield settings


def test_generate_intel_doc_summary_merges_meta(intel_ai_on):
    async def _run():
        with patch(
            "services.intel.ai._call_ollama",
            new_callable=AsyncMock,
            return_value="Campaign uses AsyncRAT against finance targets.",
        ):
            summary = await intel_ai.generate_intel_doc_summary(
                "RAT alert",
                "Body mentions AsyncRAT loader.",
                ["rat"],
            )
        assert summary == "Campaign uses AsyncRAT against finance targets."

    asyncio.run(_run())


def test_generate_intel_doc_summary_skipped_when_disabled(intel_ai_off):
    async def _run():
        with patch(
            "services.intel.ai._call_ollama",
            new_callable=AsyncMock,
            return_value="should not call",
        ) as mock_llm:
            summary = await intel_ai.generate_intel_doc_summary("t", "body", [])
        assert summary is None
        mock_llm.assert_not_called()

    asyncio.run(_run())


def test_search_intel_items_for_ioc(temp_db):
    async def _run():
        await database.upsert_intel_item(
            source="RSS-Test",
            source_id="email-1",
            title="Phish using evil@example.com",
            body="Analysts tracked evil@example.com in a credential phishing wave.",
            tags=["phishing"],
            ioc_count=1,
        )
        hits = await database.search_intel_items_for_ioc(
            "evil@example.com",
            indicator_type="email",
            limit=3,
        )
        assert len(hits) >= 1
        assert hits[0]["title"]
        assert "evil@example.com" in hits[0]["snippet"] or hits[0].get("snippet")

    asyncio.run(_run())


def test_attach_intel_context_when_enabled(temp_db, intel_ai_on):
    async def _run():
        await database.upsert_intel_item(
            source="RSS-Test",
            source_id="dom-1",
            title="C2 on bad.example.com",
            body="Traffic observed to bad.example.com from infected hosts.",
            tags=["c2"],
        )
        threat = {
            "value": "bad.example.com",
            "type": "domain",
            "meta": {},
        }
        await attach_intel_context(threat)
        ctx = threat["meta"].get("intel_context")
        assert ctx
        assert len(ctx) >= 1
        assert ctx[0]["title"]

    asyncio.run(_run())


def test_attach_intel_context_skipped_when_disabled(temp_db, intel_ai_off):
    async def _run():
        await database.upsert_intel_item(
            source="RSS-Test",
            source_id="dom-2",
            title="C2 on other.example.com",
            body="other.example.com mentioned here.",
        )
        threat = {"value": "other.example.com", "type": "domain", "meta": {}}
        await attach_intel_context(threat)
        assert "intel_context" not in threat["meta"]

    asyncio.run(_run())


def test_lookup_attaches_intel_context(temp_db, intel_ai_on):
    async def _run():
        await database.upsert_intel_item(
            source="RSS-Test",
            source_id="lookup-1",
            title="Phish domain alert",
            body="Credential theft tied to phish.example.com in recent wave.",
            tags=["phishing"],
        )
        threat = await lookup_indicator("phish.example.com", "domain")
        assert threat["meta"].get("intel_context")

    asyncio.run(_run())


def test_expand_intel_query_parses_json(intel_ai_on):
    async def _run():
        payload = json.dumps(
            {"fts_tokens": ["asyncrat", "remote", "access", "trojan"], "tags": ["rat"]}
        )
        with patch(
            "services.intel.ai._call_ollama",
            new_callable=AsyncMock,
            return_value=payload,
        ):
            expanded = await intel_ai.expand_intel_query("async rat")
        assert expanded
        assert "asyncrat" in expanded["fts_tokens"]

    asyncio.run(_run())


def test_search_intel_with_ai_uses_expanded_fts(temp_db, intel_ai_on):
    async def _run():
        await database.upsert_intel_item(
            source="RSS-Test",
            source_id="rat-1",
            title="AsyncRAT wave",
            body="Researchers document AsyncRAT remote access trojan activity.",
            tags=["rat"],
        )
        payload = json.dumps(
            {"fts_tokens": ["AsyncRAT", "trojan"], "tags": ["rat"]}
        )
        with patch(
            "services.intel.ai._call_ollama",
            new_callable=AsyncMock,
            return_value=payload,
        ):
            results, meta = await search_intel_with_ai("async rat", limit=10)
        assert meta
        assert meta["expanded"]
        assert len(results) >= 1

    asyncio.run(_run())


def test_search_intel_with_ai_invalid_json_fallback(temp_db, intel_ai_on):
    async def _run():
        await database.upsert_intel_item(
            source="RSS-Test",
            source_id="rat-2",
            title="AsyncRAT again",
            body="More AsyncRAT coverage in sector reports.",
            tags=["rat"],
        )
        with patch(
            "services.intel.ai._call_ollama",
            new_callable=AsyncMock,
            return_value="not valid json {{{",
        ):
            results, meta = await search_intel_with_ai("AsyncRAT", limit=10)
        assert meta is None
        assert len(results) >= 1

    asyncio.run(_run())
