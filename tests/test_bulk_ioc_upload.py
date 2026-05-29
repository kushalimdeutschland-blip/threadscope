"""Bulk IOC file import tests."""

from __future__ import annotations

import pytest

from services.bulk_lookup import MAX_BULK_IOCS, parse_bulk_ioc_text
from services.bulk_ioc_upload import (
    MAX_BULK_IOC_FILE_BYTES,
    parse_bulk_ioc_file,
)
from services.file_upload import FileUploadError


def test_parse_bulk_ioc_text_mixed_separators():
    raw = "8.8.8.8, evil.test;\n# whole-line comment\n10.0.0.1\n"
    tokens = parse_bulk_ioc_text(raw)
    assert tokens == ["8.8.8.8", "evil.test", "10.0.0.1"]


def test_parse_txt_file_mixed_iocs():
    data = b"8.8.8.8\n# skip\nmalware.test\n"
    tokens = parse_bulk_ioc_file(data, "iocs.txt")
    assert tokens == ["8.8.8.8", "malware.test"]


def test_parse_csv_with_header():
    data = b"value,notes\n8.8.8.8,legit\nmalware.test,bad\n"
    tokens = parse_bulk_ioc_file(data, "iocs.csv")
    assert tokens == ["8.8.8.8", "malware.test"]


def test_parse_csv_without_header():
    data = b"8.8.8.8\nmalware.test\n"
    tokens = parse_bulk_ioc_file(data, "list.csv")
    assert tokens == ["8.8.8.8", "malware.test"]


def test_parse_csv_ioc_column_name():
    data = b"ioc,source\n1.2.3.4,feed\n"
    tokens = parse_bulk_ioc_file(data, "feed.csv")
    assert tokens == ["1.2.3.4"]


def test_rejects_exe_extension():
    with pytest.raises(FileUploadError, match="Supported bulk IOC"):
        parse_bulk_ioc_file(b"8.8.8.8\n", "malware.exe")


def test_rejects_oversize():
    data = b"x" * (MAX_BULK_IOC_FILE_BYTES + 1)
    with pytest.raises(FileUploadError, match="maximum size"):
        parse_bulk_ioc_file(data, "big.txt")


def test_rejects_path_traversal_filename():
    with pytest.raises(FileUploadError, match="Supported bulk IOC"):
        parse_bulk_ioc_file(b"8.8.8.8\n", "../../etc/passwd.exe")


def test_rejects_empty_file():
    with pytest.raises(FileUploadError, match="Empty"):
        parse_bulk_ioc_file(b"", "empty.txt")


def test_rejects_binary_utf8():
    data = bytes(range(256))
    with pytest.raises(FileUploadError, match="UTF-8"):
        parse_bulk_ioc_file(data, "binary.txt")


def test_max_50_cap():
    lines = "\n".join(f"10.0.0.{i}" for i in range(60))
    tokens = parse_bulk_ioc_file(lines.encode(), "many.txt")
    assert len(tokens) == MAX_BULK_IOCS
