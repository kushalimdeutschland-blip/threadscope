"""Content-addressed sample storage."""

from pathlib import Path

from services import sample_store


def test_store_sample_dedup(tmp_path, monkeypatch):
    monkeypatch.setattr(sample_store, "SAMPLES_ROOT", tmp_path / "samples")
    data = b"MZtest sample content"
    h1, p1 = sample_store.store_sample(data)
    h2, p2 = sample_store.store_sample(data)
    assert h1 == h2
    assert p1 == p2
    assert p1.is_file()
    assert sample_store.read_sample(h1) == data
