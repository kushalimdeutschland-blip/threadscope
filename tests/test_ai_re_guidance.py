"""Tests for AI-generated file RE workflow parsing."""

from services.ai_analyst import _parse_re_guidance_json


def test_parse_re_guidance_json_array():
    raw = '[{"title": "YARA review", "detail": "Inspect Emotet rule matches."}]'
    steps = _parse_re_guidance_json(raw)
    assert steps is not None
    assert steps[0]["title"] == "YARA review"


def test_parse_re_guidance_json_codeblock():
    raw = """```json
[{"title": "Step one", "detail": "Do this first."}]
```"""
    steps = _parse_re_guidance_json(raw)
    assert steps is not None
    assert len(steps) == 1


def test_parse_re_guidance_json_invalid():
    assert _parse_re_guidance_json("not json") is None
    assert _parse_re_guidance_json('{"title": "x"}') is None
