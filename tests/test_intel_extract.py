"""Intel IOC extraction — no password passthrough."""

from __future__ import annotations

import json
from pathlib import Path

from services.intel.extract import extract_iocs, parse_leak_row

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "intel"


def test_extract_iocs_finds_cve_ip_domain_hash_email():
    text = (FIXTURES / "paste_sample.txt").read_text(encoding="utf-8")
    rows = extract_iocs(text, source="TestPaste")
    types = {r.type for r in rows}
    values = {r.value for r in rows}
    assert "ipv4" in types
    assert "192.0.2.44" in values
    assert "domain" in types
    assert "hash" in types
    assert "email" in types
    assert "victim@example.com" in values
    assert not any("SuperSecretPassword" in r.value for r in rows)
    assert not any("password" in json.dumps(r.meta).lower() for r in rows)


def test_credential_pair_extracts_email_only():
    rows = extract_iocs("stolen@victim.com:P@ssw0rd!", source="Paste")
    assert len(rows) == 1
    assert rows[0].type == "email"
    assert rows[0].value == "stolen@victim.com"


def test_parse_leak_row_ioc_only():
    row = json.loads((FIXTURES / "leak_row_redacted.json").read_text(encoding="utf-8"))
    rows = parse_leak_row(row, source="DeHashed")
    assert len(rows) == 1
    assert rows[0].type == "email"
    assert rows[0].value == "analyst.redacted@example.com"
    assert "password" not in rows[0].meta
    blob = json.dumps(row).lower()
    assert "redacted-not-stored" in blob
    assert rows[0].risk_score == 50
