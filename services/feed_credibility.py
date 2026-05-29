"""
Feed credibility weighting.

Rules:
- Minimum 20 feedback samples before a feed's coefficient shifts from 1.0.
- Coefficient = true_positive / (true_positive + false_positive), floored at 0.5.
- Return value is always in [0.5, 1.0].
"""

from __future__ import annotations

import database

MIN_SAMPLES = 20
COEFFICIENT_FLOOR = 0.5


async def get_feed_credibility(source: str) -> float:
    row = await database.get_feed_accuracy(source)
    if not row:
        return 1.0
    total = row["true_positive"] + row["false_positive"]
    if total < MIN_SAMPLES:
        return 1.0
    ratio = row["true_positive"] / total
    return min(1.0, max(COEFFICIENT_FLOOR, ratio))


async def apply_credibility(base_score: int, sources: list[dict]) -> tuple[int, bool]:
    """
    Average credibility coefficients across sources, multiply base_score, round.
    Returns (adjusted_score, was_adjusted).
    """
    if not sources:
        return base_score, False
    coeffs = [await get_feed_credibility(s["source"]) for s in sources]
    avg = sum(coeffs) / len(coeffs)
    adjusted = round(base_score * avg)
    was_adjusted = any(c < 1.0 for c in coeffs)
    return adjusted, was_adjusted
