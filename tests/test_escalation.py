"""Escalation panel context builders."""

from services.escalation import file_escalation_context, indicator_escalation_context


def test_file_escalation_unknown_exe():
    ctx = file_escalation_context(
        {
            "verdict": "UNKNOWN",
            "value": "test.exe",
            "file_kind": "exe",
            "hashes": {"sha256": "a" * 64},
        },
        sample_path="/tmp/sample",
    )
    assert ctx["copy_sha256"]
    assert ctx["suggested_commands"]
    assert ctx["re_workflow"]
    assert len(ctx["re_workflow"]) >= 3
    cmds = " ".join(ctx["suggested_commands"])
    assert "Ghidra" in cmds
    assert "floss" in cmds
    assert "capa" in cmds


def test_file_escalation_apk():
    ctx = file_escalation_context(
        {
            "verdict": "SUSPICIOUS",
            "value": "evil.apk",
            "file_kind": "apk",
            "hashes": {"sha256": "b" * 64},
        },
        sample_path="/tmp/evil.apk",
    )
    assert ctx["re_workflow"]
    assert any("jadx" in s["detail"].lower() or "apktool" in s["detail"].lower() for s in ctx["re_workflow"])
    cmds = " ".join(ctx["suggested_commands"])
    assert "jadx" in cmds
    assert "apktool" in cmds
    assert any("MobSF" in h for h in ctx["escalation_hints"])


def test_indicator_escalation_malicious_ipv4():
    ctx = indicator_escalation_context(
        {"verdict": "MALICIOUS", "value": "1.2.3.4", "type": "ipv4"},
    )
    assert ctx["copy_value"] == "1.2.3.4"
    assert any("nmap" in c for c in ctx["suggested_commands"])


def test_file_escalation_clean_skipped():
    ctx = file_escalation_context(
        {"verdict": "CLEAN", "hashes": {}},
    )
    assert ctx == {}
