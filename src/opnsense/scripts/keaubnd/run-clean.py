#!/usr/local/bin/python3
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Thomas Reagan
"""
run-clean.py — Config-reading entry point for local-data-clean.py.

Called by the configd clean action and cron. Reads policy settings from
config.xml once, then exec's local-data-clean.py with the appropriate flags.

Any flags in sys.argv[1:] (e.g. --hostname, --dry-run, --purge-ip) are
passed straight through to local-data-clean.py.
"""
import subprocess
import sys
import xml.etree.ElementTree as ET

CONFIG_XML  = "/conf/config.xml"
CLEAN_SCRIPT = "/usr/local/opnsense/scripts/keaubnd/local-data-clean.py"


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

    cmd = [sys.executable, CLEAN_SCRIPT] + sys.argv[1:]

    if g("synthesize_ptr", "1") != "1":
        cmd.append("--no-synthesize-ptr")

    sys.exit(subprocess.call(cmd))


if __name__ == "__main__":
    main()
