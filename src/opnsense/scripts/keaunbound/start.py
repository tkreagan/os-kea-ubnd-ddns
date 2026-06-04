#!/usr/local/bin/python3
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Thomas Reagan
"""
start.py -- Start kea-unbound-ddns.py via daemon(8) with settings from
the OPNsense model (config.xml //OPNsense/KeaUnbound).

Called by configd action [start] in actions_keaunbound.conf.
Reads port, TSIG key/secret/algorithm from config.xml and constructs
the appropriate daemon(8) + kea-unbound-ddns.py command.
"""

import os
import socket
import subprocess
import sys
import xml.etree.ElementTree as ET

sys.path.insert(0, "/usr/local/opnsense/scripts/keaunbound")
from lib.keaunbound_sync import setup_logging  # noqa: E402

CONFIG_XML         = "/conf/config.xml"
DAEMON             = "/usr/sbin/daemon"
SCRIPT             = "/usr/local/sbin/kea-unbound-ddns.py"
# Child (listener) PID — used by the service status check (keaunbound_services).
PIDFILE            = "/var/run/kea-unbound-ddns.pid"
# daemon(8) supervisor PID — the process that holds the -r respawn loop. Stop and
# restart must signal THIS (not the child): killing only the child lets the
# supervisor immediately respawn it, and each start would add another supervisor,
# so two would fight over the port and crash-loop on "Address already in use".
SUPERVISOR_PIDFILE = "/var/run/kea-unbound-ddns.supervisor.pid"

# Log to syslog (the keaunbound log) and, because this runs under the configd
# [start] action, also to stderr (verbose=True) so failures surface in the
# action output too.
logger = setup_logging(verbose=True)

def _port_in_use(port: int) -> bool:
    """Return True if UDP port is already bound on 127.0.0.1."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.bind(("127.0.0.1", port))
        return False
    except OSError:
        return True
    finally:
        s.close()


def _pid_alive(pidfile):
    """Return the PID from pidfile if that process is alive, else None.
    Returns True for a live PID we lack permission to signal (still 'alive')."""
    try:
        with open(pidfile) as pf:
            pid = int(pf.read().strip())
        os.kill(pid, 0)  # signal 0: existence check only
        return pid
    except (FileNotFoundError, ValueError, ProcessLookupError):
        return None
    except OSError:
        return True  # exists but EPERM — treat as alive

def get_config():
    """Read KeaUnbound settings from config.xml. Returns dict with defaults."""
    cfg = {
        "enabled":                    "0",
        "port":                       "53535",
        "enable_tsig":                "0",
        "tsig_key_name":              "",
        "tsig_key_secret":            "",
        "tsig_algorithm":             "HMAC-SHA256",
        "aggressive_cleanup":         "0",
    }
    try:
        tree = ET.parse(CONFIG_XML)
        root = tree.getroot()
        node = root.find("OPNsense/KeaUnbound/general")
        if node is not None:
            for key in cfg:
                child = node.find(key)
                if child is not None and child.text:
                    cfg[key] = child.text.strip()
    except Exception as e:
        logger.error("cannot read %s: %s", CONFIG_XML, e)
        sys.exit(1)
    return cfg

def main():
    cfg = get_config()

    if cfg["enabled"] != "1":
        logger.info("kea-unbound-ddns is disabled — not starting.")
        sys.exit(0)

    # Idempotent start: refuse to launch a second supervisor.
    # Two-layer check:
    #   1. Supervisor pidfile — catches the normal case where stop ran cleanly.
    #   2. Port availability — catches the pathological case where an orphaned
    #      process is still holding the port after a failed stop (e.g. pidfile
    #      was deleted but the process didn't die). Without this, start.py would
    #      launch a new daemon(8) supervisor that immediately crash-loops on
    #      "Address already in use", spamming the log every 5 seconds.
    existing = _pid_alive(SUPERVISOR_PIDFILE)
    if existing:
        logger.info("kea-unbound-ddns already running (supervisor pid %s) — not starting another.",
                    existing)
        sys.exit(0)

    port = int(cfg["port"])
    if _port_in_use(port):
        logger.error(
            "Port %d is already in use — an old instance may still be running. "
            "Run 'configctl keaunbound stop' to clear it before starting.", port)
        sys.exit(1)

    # Remove stale pidfiles before handing off to daemon(8): a leftover pidfile
    # whose PID is no longer running makes daemon(8) refuse to start ("process
    # already running") on some FreeBSD versions, causing "Execute error" from
    # configd. We've already established the supervisor isn't alive above, so any
    # surviving pidfile here is stale.
    for pf in (SUPERVISOR_PIDFILE, PIDFILE):
        if os.path.exists(pf) and _pid_alive(pf) is None:
            try:
                os.unlink(pf)
            except OSError:
                pass

    # Build kea-unbound-ddns.py argument list
    script_args = [SCRIPT, "--port", cfg["port"]]

    # TSIG is gated solely on the enable_tsig switch. When enabled, the key name
    # and secret are mandatory — fail closed (refuse to start) rather than
    # silently listen unauthenticated. (The model also blocks saving this state,
    # so this is a backstop.)
    if cfg["enable_tsig"] == "1":
        if not cfg["tsig_key_name"] or not cfg["tsig_key_secret"]:
            logger.error("TSIG is enabled but key name/secret is missing — "
                         "refusing to start. Set the TSIG key or disable TSIG.")
            sys.exit(1)
        script_args += [
            "--tsig-key",       f"{cfg['tsig_key_name']}:{cfg['tsig_key_secret']}",
            "--tsig-algorithm", cfg["tsig_algorithm"],
        ]

    if cfg["aggressive_cleanup"] == "1":
        script_args.append("--aggressive-cleanup")

    # Launch via daemon(8): -f forks to background, -p writes the child PID,
    # -P writes the supervisor PID (so stop/restart can signal the supervisor),
    # -r restarts the child on crash (with 5s backoff via -R 5).
    cmd = [DAEMON, "-f", "-p", PIDFILE, "-P", SUPERVISOR_PIDFILE,
           "-r", "-R", "5"] + script_args

    try:
        subprocess.run(cmd, check=True)
        logger.info("kea-unbound-ddns started (port %s).", cfg["port"])
    except subprocess.CalledProcessError as e:
        logger.error("failed to start kea-unbound-ddns: %s", e)
        sys.exit(1)

if __name__ == "__main__":
    main()
