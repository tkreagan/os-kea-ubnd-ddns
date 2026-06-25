#!/usr/local/bin/python3
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Thomas Reagan
"""
run-sync.py — Config-reading entry point for kea-sync.py.

Called by the configd sync_full action and cron jobs.
Reads policy settings from config.xml once, then exec's kea-sync.py
with the appropriate flags so kea-sync.py itself is config-free.

Any flags in sys.argv[1:] (e.g. --static-only, --clean-stale, --dry-run)
are passed straight through to kea-sync.py.
"""
import subprocess
import sys
import xml.etree.ElementTree as ET

CONFIG_XML = "/conf/config.xml"
KEA_SYNC   = "/usr/local/opnsense/scripts/keaubnd/kea-sync.py"


def _read_config():
    try:
        node = ET.parse(CONFIG_XML).getroot().find("OPNsense/KeaUbnd/general")
    except Exception:
        node = None

    def g(key, default=""):
        if node is None:
            return default
        child = node.find(key)
        return child.text.strip() if child is not None and child.text else default

    return g


def main():
    g = _read_config()

    cmd = [sys.executable, KEA_SYNC] + sys.argv[1:]

    cmd.append("--collision-policy=" + (g("collision_policy") or "last_wins"))

    if g("magic_names") == "1":
        cmd.append("--magic-names")
    if g("magic_laa_tag") == "1":
        cmd.append("--laa-tag")
    if g("synthesize_ptr", "1") != "1":
        cmd.append("--no-synthesize-ptr")

    sys.exit(subprocess.call(cmd))


if __name__ == "__main__":
    main()
