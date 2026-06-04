# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Thomas Reagan
"""
Integration tests — cron job creation and execution.

Verifies that enabling auto-clean in plugin settings causes the correct
cron entry to appear in the managed crontab, and that the cron command
runs the clean script successfully.
"""

from __future__ import annotations

import time

import pytest

pytestmark = [pytest.mark.integration, pytest.mark.slow]

CRON_CMD = "/usr/local/sbin/configctl -d keaunbound clean"


def _read_crontab(ssh) -> str:
    return ssh("crontab -l -u root 2>/dev/null || true", check=False)


def _rebuild_cron(ssh):
    """Ask OPNsense to regenerate the crontab from model."""
    ssh("/usr/local/sbin/configctl cron restart", check=False)
    time.sleep(2)


def test_cron_entry_present_when_auto_clean_enabled(ssh, api, deploy, test_log):
    """After enabling auto_clean in settings, a cron entry must appear."""
    # Get current settings
    current = api.api_get("general/get")
    original = current.get("general", {})

    # Enable auto_clean with h6 interval
    api.api_post("general/set", {
        "general": {
            "enabled": "1",
            "enable_auto_clean": "1",
            "auto_clean_interval": "h6",
        }
    })
    _rebuild_cron(ssh)

    crontab = _read_crontab(ssh)
    test_log("observed", {"crontab_snippet": crontab[-500:]})
    assert CRON_CMD in crontab, f"Cron entry not found after enabling auto_clean"

    # Check schedule hours
    for line in crontab.splitlines():
        if CRON_CMD in line:
            parts = line.split()
            # Format: minute hour ...
            hour_field = parts[1] if len(parts) > 1 else ""
            assert "6" in hour_field or "0,6" in hour_field or "12" in hour_field, \
                f"Unexpected hour field for h6 interval: {hour_field!r}"
            break

    test_log("cleaned", False)  # settings restored below


def test_cron_entry_absent_when_auto_clean_disabled(ssh, api, test_log):
    """Disabling auto_clean must remove the cron entry."""
    api.api_post("general/set", {
        "general": {"enable_auto_clean": "0"}
    })
    _rebuild_cron(ssh)

    crontab = _read_crontab(ssh)
    test_log("observed", {"has_cron_entry": CRON_CMD in crontab})
    assert CRON_CMD not in crontab, "Cron entry still present after disabling auto_clean"


@pytest.mark.parametrize("interval,expected_hours", [
    ("h6",  "0,6,12,18"),
    ("h12", "0,12"),
    ("h24", "0"),
])
def test_cron_schedule_matches_interval(ssh, api, interval, expected_hours, test_log):
    api.api_post("general/set", {
        "general": {"enabled": "1", "enable_auto_clean": "1",
                    "auto_clean_interval": interval}
    })
    _rebuild_cron(ssh)

    crontab = _read_crontab(ssh)
    for line in crontab.splitlines():
        if CRON_CMD in line:
            hour_field = line.split()[1] if len(line.split()) > 1 else ""
            test_log("observed", {"interval": interval, "hour_field": hour_field})
            assert hour_field == expected_hours, \
                f"Interval {interval}: expected hours {expected_hours!r}, got {hour_field!r}"
            return
    pytest.fail(f"No cron entry found for interval {interval}")


def test_cron_command_runs_clean_successfully(ssh, test_log):
    """The cron command itself should execute without error."""
    out = ssh(CRON_CMD)
    test_log("observed", {"output": out[:300]})
    assert "Traceback" not in out
    assert "Exception" not in out
