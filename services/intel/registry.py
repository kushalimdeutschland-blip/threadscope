"""Load intel collector config and build enabled collector instances."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from config import get_settings
from services.intel.base import IntelCollector
from services.intel.collectors.leak_api import DehashedCollector
from services.intel.collectors.paste_intelx import IntelXCollector, PastebinCollector
from services.intel.collectors.rss_security import RssSecurityCollector
from services.intel.collectors.web_scrape import WebScrapeCollector

INTEL_FEEDS_PATH = Path(__file__).resolve().parents[2] / "data" / "intel_feeds.yaml"


def load_intel_config(path: Path | None = None) -> dict[str, Any]:
    cfg_path = path or INTEL_FEEDS_PATH
    if not cfg_path.is_file():
        return {
            "rss": {"feeds": []},
            "web": {"targets": []},
            "paste": {},
            "intelx": {},
            "leak": {},
        }
    with cfg_path.open(encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}
    return data


def get_enabled_collectors(config: dict[str, Any] | None = None) -> dict[str, IntelCollector]:
    """Return collectors keyed by CLI name (rss, web, paste, intelx, leak)."""
    cfg = config if config is not None else load_intel_config()
    settings = get_settings()
    collectors: dict[str, IntelCollector] = {}

    rss_cfg = cfg.get("rss") or {}
    if rss_cfg.get("enabled", True):
        feeds = [f for f in (rss_cfg.get("feeds") or []) if f.get("enabled", True)]
        if feeds:
            collectors["rss"] = RssSecurityCollector(feeds)

    web_cfg = cfg.get("web") or {}
    if web_cfg.get("enabled", False):
        targets = [t for t in (web_cfg.get("targets") or []) if t.get("enabled", True)]
        if targets:
            web_cfg = {**web_cfg, "targets": targets}
            if "delay_seconds" not in web_cfg:
                web_cfg["delay_seconds"] = settings.intel_scrape_delay_seconds
            collectors["web"] = WebScrapeCollector(web_cfg)

    paste_cfg = cfg.get("paste") or {}
    if paste_cfg.get("enabled") and settings.pastebin_api_key:
        collectors["paste"] = PastebinCollector(paste_cfg)

    intelx_cfg = cfg.get("intelx") or {}
    if intelx_cfg.get("enabled") and settings.intelx_api_key:
        collectors["intelx"] = IntelXCollector(intelx_cfg)

    leak_cfg = cfg.get("leak") or {}
    dehashed = leak_cfg.get("dehashed") or {}
    if dehashed.get("enabled") and settings.dehashed_api_key:
        collectors["leak"] = DehashedCollector(dehashed)

    return collectors
