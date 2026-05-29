"""Pytest configuration — ensure project root is on sys.path."""

from __future__ import annotations

import importlib
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def reload_config_module():
    """Re-read os.environ into config.Settings (class attrs are set at import)."""
    import config

    importlib.reload(config)
    config.get_settings.cache_clear()
    return config
