"""
YARA signature scanning for uploaded files (parse-only, rules on disk).
"""

from __future__ import annotations

import logging
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from config import get_settings

logger = logging.getLogger("threatscope.yara")

_yara = None
_yara_import_error: str | None = None
_rules_lock = threading.Lock()
_compiled_rules = None
_compiled_rule_count: int = 0
_rules_dir_mtime: float | None = None

# Bundled minimal rules for dev/tests when data/yara_rules is empty
_BOOTSTRAP_RULES = Path(__file__).resolve().parents[1] / "yara_rules" / "bootstrap"


@dataclass
class YaraMatch:
    rule: str
    namespace: str
    tags: list[str] = field(default_factory=list)
    meta: dict[str, Any] = field(default_factory=dict)


@dataclass
class YaraScanResult:
    status: str  # ok | skipped | unavailable
    matches: list[YaraMatch] = field(default_factory=list)
    rules_loaded: int = 0
    message: str | None = None

    @property
    def match_count(self) -> int:
        return len(self.matches)


def _import_yara():
    global _yara, _yara_import_error
    if _yara is not None or _yara_import_error is not None:
        return _yara
    try:
        import yara as yara_mod

        _yara = yara_mod
        return _yara
    except ImportError as exc:
        _yara_import_error = str(exc)
        return None


def rules_directory() -> Path:
    settings = get_settings()
    return Path(settings.yara_rules_dir)


def _collect_rule_files(root: Path) -> list[Path]:
    if not root.is_dir():
        return []
    files: list[Path] = []
    for pattern in ("*.yar", "*.yara"):
        files.extend(root.rglob(pattern))
    return sorted({p.resolve() for p in files if p.is_file()})


def _effective_rules_roots() -> list[Path]:
    roots: list[Path] = []
    primary = rules_directory()
    if primary.is_dir() and _collect_rule_files(primary):
        roots.append(primary)
    elif _BOOTSTRAP_RULES.is_dir():
        roots.append(_BOOTSTRAP_RULES)
    return roots


def _rules_dir_signature(roots: list[Path]) -> float:
    latest = 0.0
    for root in roots:
        for path in _collect_rule_files(root):
            try:
                latest = max(latest, path.stat().st_mtime)
            except OSError:
                continue
        try:
            latest = max(latest, root.stat().st_mtime)
        except OSError:
            pass
    return latest


def _compile_rules() -> tuple[Any | None, int, str | None]:
    yara = _import_yara()
    if yara is None:
        return None, 0, _yara_import_error or "yara-python not installed"

    roots = _effective_rules_roots()
    if not roots:
        return None, 0, "no .yar rules found (run ingest_yara_rules.py or add rules to data/yara_rules/)"

    candidates: dict[str, str] = {}
    for root in roots:
        for path in _collect_rule_files(root):
            key = path.stem
            if key in candidates:
                key = f"{key}_{len(candidates)}"
            candidates[key] = str(path)

    if not candidates:
        return None, 0, "no .yar rules found"

    # Community bundles often include a few rules incompatible with current libyara.
    rules_map: dict[str, str] = {}
    skipped = 0
    for key, path in candidates.items():
        try:
            yara.compile(filepath=path)
            rules_map[key] = path
        except yara.Error as exc:
            skipped += 1
            logger.debug("Skipping broken YARA rule %s: %s", path, exc)

    if skipped:
        logger.info("YARA: loaded %s rules, skipped %s broken files", len(rules_map), skipped)

    if not rules_map:
        return None, 0, "no valid .yar rules (all files failed to compile)"

    try:
        compiled = yara.compile(filepaths=rules_map)
        return compiled, len(rules_map), None
    except yara.Error as exc:
        logger.warning("YARA compile failed: %s", exc)
        return None, 0, str(exc)


def _get_compiled_rules() -> tuple[Any | None, int, str | None]:
    global _compiled_rules, _compiled_rule_count, _rules_dir_mtime

    roots = _effective_rules_roots()
    signature = _rules_dir_signature(roots)

    with _rules_lock:
        if _compiled_rules is not None and _rules_dir_mtime == signature:
            return _compiled_rules, _compiled_rule_count, None

        compiled, count, err = _compile_rules()
        _compiled_rules = compiled
        _compiled_rule_count = count
        _rules_dir_mtime = signature
        return compiled, count, err


def invalidate_rules_cache() -> None:
    """Call after ingesting new rules."""
    global _compiled_rules, _compiled_rule_count, _rules_dir_mtime
    with _rules_lock:
        _compiled_rules = None
        _compiled_rule_count = 0
        _rules_dir_mtime = None


def scan_bytes(data: bytes) -> YaraScanResult:
    """Scan file bytes against compiled YARA rules."""
    compiled, rule_count, err = _get_compiled_rules()
    if compiled is None:
        status = "unavailable" if _import_yara() is None else "skipped"
        return YaraScanResult(status=status, message=err, rules_loaded=0)

    try:
        matches = compiled.match(data=data)
    except Exception as exc:
        logger.exception("YARA match failed")
        return YaraScanResult(status="skipped", message=str(exc), rules_loaded=rule_count)

    parsed: list[YaraMatch] = []
    for match in matches:
        tags = list(match.tags) if match.tags else []
        meta = dict(match.meta) if match.meta else {}
        parsed.append(
            YaraMatch(
                rule=match.rule,
                namespace=match.namespace,
                tags=tags,
                meta=meta,
            )
        )

    return YaraScanResult(status="ok", matches=parsed, rules_loaded=rule_count)


def apply_yara_to_result(result: Any, data: bytes) -> None:
    """Append YARA findings to a StaticAnalysisResult (mutates in place)."""
    from services.static_analysis import StaticFinding

    scan = scan_bytes(data)
    result.meta["yara_status"] = scan.status
    result.meta["yara_rules_loaded"] = scan.rules_loaded

    if scan.status != "ok":
        if scan.message:
            result.meta["yara_message"] = scan.message
        return

    if not scan.matches:
        return

    result.meta["yara_match_count"] = scan.match_count
    result.meta["yara_matches"] = [
        {
            "rule": m.rule,
            "namespace": m.namespace,
            "tags": m.tags,
        }
        for m in scan.matches[:20]
    ]

    rule_names = [m.rule for m in scan.matches[:8]]
    result.findings.append(
        StaticFinding(
            "critical",
            "YARA signature match",
            "Matched rules: " + ", ".join(rule_names),
            source="signature",
        )
    )
    if "YARA Match" not in result.tags:
        result.tags.append("YARA Match")

    from services.static_analysis import _score_from_findings

    result.risk_score = max(result.risk_score, _score_from_findings(result.findings))
