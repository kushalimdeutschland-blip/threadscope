"""Analyst feedback and feed_accuracy recompute tests (temp SQLite)."""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone

import pytest

import database


@pytest.fixture
def temp_db(monkeypatch, tmp_path):
    db_path = tmp_path / "feedback_test.db"
    monkeypatch.setattr(database, "DB_PATH", db_path)

    async def _setup():
        await database.close_read_pool()
        await database.init_db()

    async def _teardown():
        await database.close_read_pool()

    asyncio.run(_setup())
    yield db_path
    asyncio.run(_teardown())


async def _insert_source(value: str, indicator_type: str, source: str) -> None:
    now = datetime.now(timezone.utc).isoformat()
    db = await database._new_write_connection()
    try:
        await db.execute(
            """
            INSERT INTO indicator_sources (value, type, source, last_seen)
            VALUES (?, ?, ?, ?)
            """,
            (value, indicator_type, source, now),
        )
        await db.commit()
    finally:
        await db.close()


def test_recompute_feed_accuracy_join_counts_tp_fp(temp_db):
    async def _run():
        await database.upsert_indicator("1.2.3.4", "ipv4", 80, ["test"])
        await database.upsert_indicator("5.6.7.8", "ipv4", 50, ["test"])
        await _insert_source("1.2.3.4", "ipv4", "FeedA")
        await _insert_source("5.6.7.8", "ipv4", "FeedA")

        await database.insert_feedback(
            "1.2.3.4", "ipv4", "MALICIOUS", "MALICIOUS"
        )
        await database.insert_feedback(
            "5.6.7.8", "ipv4", "MALICIOUS", "CLEAN"
        )
        await database.recompute_feed_accuracy("FeedA")

        row = await database.get_feed_accuracy("FeedA")
        assert row is not None
        assert row["true_positive"] == 1
        assert row["false_positive"] == 1

    asyncio.run(_run())


def test_recompute_ignores_feedback_without_matching_source(temp_db):
    async def _run():
        await database.upsert_indicator("9.9.9.9", "ipv4", 70, ["orphan"])
        await database.insert_feedback(
            "9.9.9.9", "ipv4", "SUSPICIOUS", "CLEAN"
        )
        await database.recompute_feed_accuracy("MissingFeed")

        row = await database.get_feed_accuracy("MissingFeed")
        assert row is not None
        assert row["true_positive"] == 0
        assert row["false_positive"] == 0

    asyncio.run(_run())


def test_get_feedback_for_indicator_ordered(temp_db):
    async def _run():
        await database.upsert_indicator("evil.test", "domain", 90, ["bad"])
        await database.insert_feedback("evil.test", "domain", "MALICIOUS", "CLEAN")
        await database.insert_feedback("evil.test", "domain", "MALICIOUS", "MALICIOUS")

        rows = await database.get_feedback_for_indicator("evil.test", "domain")
        assert len(rows) == 2
        assert rows[0]["created_at"] >= rows[1]["created_at"]

    asyncio.run(_run())
