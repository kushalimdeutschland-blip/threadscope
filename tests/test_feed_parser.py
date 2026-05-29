"""Feed parser unit tests (fixture snippets, no network)."""

from services.feed_parser import (
    deduplicate_indicators,
    parse_cisa_kev_json,
    parse_firehol_level1_text,
    parse_malwarebazaar_csv,
    parse_openphish_text,
    parse_spamhaus_drop_text,
    parse_threatfox_csv,
)


def test_spamhaus_drop_parses_cidr():
    content = "; comment\n1.2.3.4/24 ; SBL123\n"
    rows = parse_spamhaus_drop_text(content)
    assert len(rows) == 1
    assert rows[0].value == "1.2.3.4"
    assert rows[0].type == "ipv4"
    assert rows[0].risk_score >= 70


def test_firehol_skips_non_global():
    content = "127.0.0.1/8\n8.8.8.8/32\n"
    rows = parse_firehol_level1_text(content)
    assert len(rows) == 1
    assert rows[0].value == "8.8.8.8"


def test_malwarebazaar_csv_hashes():
    sha256 = "a" * 64
    md5 = "b" * 32
    sha1 = "c" * 40
    content = f'# header\n"2026-01-01 00:00:00", "{sha256}", "{md5}", "{sha1}", "src"\n'
    rows = parse_malwarebazaar_csv(content)
    values = {r.value for r in rows}
    assert sha256 in values
    assert md5 in values
    assert sha1 in values


def test_openphish_extracts_domain():
    content = "https://evil.example/phish\n"
    rows = parse_openphish_text(content)
    assert any(r.value == "evil.example" and r.type == "domain" for r in rows)


def test_cisa_kev_extracts_ip_from_notes():
    content = """{
      "vulnerabilities": [{
        "cveID": "CVE-2024-0001",
        "notes": "See http://1.2.3.4/path for details",
        "shortDescription": "",
        "vulnerabilityName": ""
      }]
    }"""
    rows = parse_cisa_kev_json(content)
    assert any(r.value == "1.2.3.4" for r in rows)


def test_threatfox_csv_ip_and_hash():
    content = "ioc,ioc_type\n1.2.3.4,ip\n" + "a" * 64 + ",sha256_hash\n"
    rows = parse_threatfox_csv(content)
    types = {(r.type, r.value) for r in rows}
    assert ("ipv4", "1.2.3.4") in types
    assert ("hash", "a" * 64) in types


def test_deduplicate_keeps_max_score():
    from services.feed_parser import FeedIndicator

    rows = [
        FeedIndicator("1.2.3.4", "ipv4", 70, ["a"], {"source": "A"}),
        FeedIndicator("1.2.3.4", "ipv4", 90, ["b"], {"source": "B"}),
    ]
    merged = deduplicate_indicators(rows)
    assert len(merged) == 1
    assert merged[0].risk_score == 90
