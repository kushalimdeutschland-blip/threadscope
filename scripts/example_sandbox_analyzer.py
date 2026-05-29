#!/usr/bin/env python3
"""
Example dynamic analyzer for SANDBOX_BACKEND=script.

Usage:
  SANDBOX_BACKEND=script
  SANDBOX_SCRIPT=scripts/example_sandbox_analyzer.py
  python scripts/sandbox_worker.py
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--sample", required=True)
    parser.add_argument("--kind", required=True)
    parser.add_argument("--filename", required=True)
    args = parser.parse_args()

    path = Path(args.sample)
    if not path.is_file():
        print(json.dumps({"status": "failed", "error": "sample not found"}))
        return 1

    size = path.stat().st_size
    # Replace this stub with your real detonation / API call.
    report = {
        "status": "completed",
        "risk_score": 15,
        "behaviors": [f"Stub analyzed {args.filename} ({size} bytes, kind={args.kind})"],
        "network_iocs": [],
        "signatures": [],
        "tags": ["Example Script"],
        "summary": "Example script backend — replace with real analysis logic.",
    }
    print(json.dumps(report))
    return 0


if __name__ == "__main__":
    sys.exit(main())
