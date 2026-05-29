"""Static PE/APK analysis unit tests."""

from __future__ import annotations

import io
import zipfile

import pytest

from services.static_analysis import (
    analyze_apk,
    analyze_bytes,
    analyze_pe,
    compute_hashes,
)


def test_compute_hashes_deterministic():
    data = b"threatscope-test-payload"
    h = compute_hashes(data)
    assert len(h["md5"]) == 32
    assert len(h["sha1"]) == 40
    assert len(h["sha256"]) == 64


def test_analyze_bytes_rejects_unknown_extension():
    with pytest.raises(ValueError, match="Unsupported"):
        analyze_bytes(b"data", "file.bin", ".bin")


def test_analyze_pe_invalid_mz():
    result = analyze_pe(b"MZ" + b"\x00" * 128, "bad.exe")
    assert result.file_kind == "exe"
    assert result.risk_score >= 70
    assert any(f.title == "Invalid PE" for f in result.findings)


def _minimal_apk_bytes() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(
            "AndroidManifest.xml",
            b'<?xml version="1.0"?><manifest package="com.test.app"></manifest>',
        )
        zf.writestr("classes.dex", b"dex\n035\x00" + b"\x00" * 32)
    return buf.getvalue()


def test_analyze_apk_minimal_zip():
    data = _minimal_apk_bytes()
    result = analyze_apk(data, "test.apk")
    assert result.file_kind == "apk"
    assert result.hashes["sha256"]
    assert result.meta.get("file_count", 0) >= 2


def test_analyze_zip_lists_members():
    from services.static_documents import analyze_zip

    data = _minimal_apk_bytes()
    result = analyze_zip(data, "wrap.zip")
    assert result.file_kind == "zip"
    assert result.meta.get("archive_listing")


def test_analyze_pdf_flags():
    from services.static_documents import analyze_pdf

    data = b"%PDF-1.4\n/JavaScript (alert)\n"
    result = analyze_pdf(data, "doc.pdf")
    assert any(f.title == "Suspicious PDF features" for f in result.findings)


def test_analyze_apk_via_analyze_bytes_includes_yara_meta(monkeypatch, tmp_path):
    from services import yara_scan as ys

    bootstrap = (
        __import__("pathlib").Path(__file__).resolve().parents[1] / "yara_rules" / "bootstrap"
    )
    rules_dir = tmp_path / "yara"
    rules_dir.mkdir()
    for src in bootstrap.glob("*.yar"):
        (rules_dir / src.name).write_bytes(src.read_bytes())
    monkeypatch.setattr(ys, "rules_directory", lambda: rules_dir)
    ys.invalidate_rules_cache()

    pytest.importorskip("yara")
    data = _minimal_apk_bytes()
    result = analyze_bytes(data, "test.apk", ".apk")
    assert "yara_status" in result.meta
