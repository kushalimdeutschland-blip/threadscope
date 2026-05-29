"""Feed credibility coefficient tests."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, patch

from services.feed_credibility import (
    COEFFICIENT_FLOOR,
    MIN_SAMPLES,
    apply_credibility,
    get_feed_credibility,
)


def test_get_feed_credibility_below_threshold():
    with patch(
        "services.feed_credibility.database.get_feed_accuracy",
        new=AsyncMock(return_value={"true_positive": 5, "false_positive": 3}),
    ):
        assert asyncio.run(get_feed_credibility("URLhaus")) == 1.0


def test_get_feed_credibility_applies_floor():
    with patch(
        "services.feed_credibility.database.get_feed_accuracy",
        new=AsyncMock(return_value={"true_positive": 4, "false_positive": 16}),
    ):
        coeff = asyncio.run(get_feed_credibility("URLhaus"))
        assert coeff == COEFFICIENT_FLOOR


def test_get_feed_credibility_no_row():
    with patch(
        "services.feed_credibility.database.get_feed_accuracy",
        new=AsyncMock(return_value=None),
    ):
        assert asyncio.run(get_feed_credibility("missing")) == 1.0


def test_get_feed_credibility_exact_ratio():
    total = MIN_SAMPLES
    tp = 15
    fp = total - tp
    with patch(
        "services.feed_credibility.database.get_feed_accuracy",
        new=AsyncMock(return_value={"true_positive": tp, "false_positive": fp}),
    ):
        coeff = asyncio.run(get_feed_credibility("Feodo"))
        assert coeff == tp / total


def test_apply_credibility_empty_sources():
    score, adjusted = asyncio.run(apply_credibility(80, []))
    assert score == 80
    assert adjusted is False


def test_apply_credibility_averages_sources():
    async def _mock(source: str) -> float:
        return {"A": 1.0, "B": 0.5}[source]

    with patch("services.feed_credibility.get_feed_credibility", side_effect=_mock):
        score, adjusted = asyncio.run(
            apply_credibility(
                100,
                [{"source": "A", "last_seen": "x"}, {"source": "B", "last_seen": "y"}],
            )
        )
    assert score == 75
    assert adjusted is True
