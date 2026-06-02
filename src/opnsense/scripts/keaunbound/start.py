#!/usr/local/bin/python3
"""
start.py -- Start kea-unbound-ddns.py via daemon(8) with settings from
the OPNsense model (config.xml //OPNsense/KeaUnbound).

Called by configd action [start] in actions_keaunbound.conf.
Reads port, TSIG key/secret/algorithm from config.xml and constructs
the appropriate daemon(8) + kea-unbound-ddns.py command.
"""

import os
import subprocess
import sys
import xml.etree.ElementTree as ET

CONFIG_XML     = "/conf/config.xml"
DAEMON         = "/usr/sbin/daemon"
SCRIPT         = "/usr/local/sbin/kea-unbound-ddns.py"
PIDFILE        = "/var/run/kea-unbound-ddns.pid"

def get_config():
    """Read KeaUnbound settings from config.xml. Returns dict with defaults."""
    cfg = {
        "enabled":                    "0",
        "port":                       "53535",
        "tsig_key_name":              "",
        "tsig_key_secret":            "",
        "tsig_algorithm":             "HMAC-SHA256",
        "reload_unbound_on_kea_sync": "0",
    }
    try:
        tree = ET.parse(CONFIG_XML)
        root = tree.getroot()
        node = root.find("KeaUnbound/general")
        if node is not None:
            for key in cfg:
                child = node.find(key)
                if child is not None and child.text:
                    cfg[key] = child.text.strip()
    except Exception as e:
        print(f"ERROR: cannot read {CONFIG_XML}: {e}", file=sys.stderr)
        sys.exit(1)
    return cfg

def main():
    cfg = get_config()

    if cfg["enabled"] != "1":
        print("kea-unbound-ddns is disabled — not starting.", file=sys.stderr)
        sys.exit(0)

    # Build kea-unbound-ddns.py argument list
    script_args = [SCRIPT, "--port", cfg["port"]]

    if cfg["tsig_key_name"] and cfg["tsig_key_secret"]:
        script_args += [
            "--tsig-key",       f"{cfg['tsig_key_name']}:{cfg['tsig_key_secret']}",
            "--tsig-algorithm", cfg["tsig_algorithm"],
        ]

    # Launch via daemon(8): -f forks to background, -p writes pidfile,
    # -r restarts on crash (with 5s backoff via -R 5)
    cmd = [DAEMON, "-f", "-p", PIDFILE, "-r", "-R", "5"] + script_args

    try:
        subprocess.run(cmd, check=True)
        print("kea-unbound-ddns started.", file=sys.stderr)
    except subprocess.CalledProcessError as e:
        print(f"ERROR: failed to start kea-unbound-ddns: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
