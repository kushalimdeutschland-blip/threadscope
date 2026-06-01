"""sample_repos zip-in-RAM walker (synthetic archives only)."""

from __future__ import annotations

import io
import zipfile

import pytest

from services.sample_repos import (
    ZipSafetyError,
    hash_single_blob,
    iter_zip_members,
)


def _make_zip(entries: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in entries.items():
            zf.writestr(name, data)
    return buf.getvalue()


def test_iter_zip_members_hashes_files():
    data = _make_zip(
        {
            "samples/a.bin": b"hello-malware-fixture",
            "samples/b.bin": b"second-fixture",
        }
    )
    records = iter_zip_members(data)
    assert len(records) == 2
    by_name = {r.inner_filename: r for r in records}
    rec = by_name["samples/a.bin"]
    assert len(rec.sha256) == 64
    assert len(rec.md5) == 32
    assert len(rec.sha1) == 40
    assert rec.sha256 != rec.md5


def test_hash_single_blob():
    rec = hash_single_blob(b"plain-file", inner_filename="plain.bin")
    assert rec.inner_filename == "plain.bin"
    assert rec.sha256 == hash_single_blob(b"plain-file", inner_filename="x").sha256


def test_rejects_path_traversal():
    data = _make_zip({"../evil.bin": b"x"})
    with pytest.raises(ZipSafetyError, match="traversal"):
        iter_zip_members(data)


def test_rejects_too_many_members():
    entries = {f"f{i}.bin": b"x" for i in range(5)}
    data = _make_zip(entries)
    with pytest.raises(ZipSafetyError, match="too many"):
        iter_zip_members(data, max_members=3)


def test_skips_directories():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("dir/", "")
        zf.writestr("dir/file.bin", b"content")
    records = iter_zip_members(buf.getvalue())
    assert len(records) == 1
    assert records[0].inner_filename == "dir/file.bin"
