"""FTS5 intel document search tests."""

from __future__ import annotations

import asyncio

import pytest

import database


@pytest.fixture
def temp_db(monkeypatch, tmp_path):
    db_path = tmp_path / "intel_fts_test.db"
    monkeypatch.setattr(database, "DB_PATH", db_path)

    async def _setup():
        await database.close_read_pool()
        await database.init_db()

    async def _teardown():
        await database.close_read_pool()

    asyncio.run(_setup())
    yield db_path
    asyncio.run(_teardown())


def test_fts_search_returns_ranked_match(temp_db):
    async def _run():
        await database.upsert_intel_item(
            source="RSS-Test",
            source_id="item-1",
            title="New RAT campaign uses AsyncRAT",
            body="Researchers found a remote access trojan targeting finance sector.",
            tags=["rat", "news"],
            ioc_count=0,
        )
        await database.upsert_intel_item(
            source="RSS-Test",
            source_id="item-2",
            title="Patch Tuesday",
            body="Routine Windows updates with no major incidents.",
            tags=["news"],
            ioc_count=0,
        )
        hits = await database.search_intel_items("AsyncRAT", limit=10)
        assert len(hits) >= 1
        assert hits[0]["source_id"] == "item-1"
        assert "RAT" in hits[0]["title"] or "trojan" in hits[0]["body"].lower()

    asyncio.run(_run())


def test_upsert_skips_unchanged_body(temp_db):
    async def _run():
        status1, _ = await database.upsert_intel_item(
            source="IntelX",
            source_id="x-1",
            title="Same",
            body="unchanged body text",
            tags=["paste"],
        )
        assert status1 == "inserted"
        status2, _ = await database.upsert_intel_item(
            source="IntelX",
            source_id="x-1",
            title="Same",
            body="unchanged body text",
            tags=["paste"],
        )
        assert status2 == "skipped"

    asyncio.run(_run())
