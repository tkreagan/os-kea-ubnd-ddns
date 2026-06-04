# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Thomas Reagan
"""
Top-level conftest: JSON run-log writer for integration tests.

Writes tests/results/run_YYYYMMDD_HHMMSS.json after every test run.
Unit tests are included in the report but have no box/injected metadata.
"""

from __future__ import annotations

import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path

import pytest

RESULTS_DIR = Path(__file__).parent / "results"

_run_log: dict = {}


def pytest_configure(config):
    _run_log.clear()
    _run_log["run_at"] = datetime.now(timezone.utc).isoformat()
    _run_log["box"] = os.environ.get("OPNSENSE_HOST", "local")
    _run_log["tests"] = []
    _run_log["summary"] = {"total": 0, "passed": 0, "failed": 0, "skipped": 0}


def pytest_runtest_logreport(report):
    if report.when != "call":
        return
    entry = {
        "id": report.nodeid,
        "status": "pass" if report.passed else ("skip" if report.skipped else "fail"),
        "duration_ms": int(report.duration * 1000),
        "injected": getattr(report, "_injected", None),
        "observed": getattr(report, "_observed", None),
        "cleaned": getattr(report, "_cleaned", None),
        "error": None,
    }
    if report.failed and report.longrepr:
        entry["error"] = str(report.longrepr)[-2000:]
    _run_log["tests"].append(entry)
    summary = _run_log["summary"]
    summary["total"] += 1
    if report.passed:
        summary["passed"] += 1
    elif report.skipped:
        summary["skipped"] += 1
    else:
        summary["failed"] += 1


def pytest_sessionfinish(session, exitstatus):
    RESULTS_DIR.mkdir(exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    out = RESULTS_DIR / f"run_{ts}.json"
    out.write_text(json.dumps(_run_log, indent=2))

    s = _run_log["summary"]
    print(f"\n── Test run log: {out}")
    print(f"   {s['total']} total  {s['passed']} passed  "
          f"{s['failed']} failed  {s['skipped']} skipped")
