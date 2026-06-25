#!/usr/local/bin/python3
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Thomas Reagan
"""
start.py -- Start kea-ubnd-ddns.py via daemon(8) with settings from
the OPNsense model (config.xml //OPNsense/KeaUbnd).

Called by configd action [start] in actions_keaubnd.conf.
Reads from config.xml and constructs the appropriate daemon(8) +
kea-ubnd-ddns.py command.
"""

import json
import os
import re
import socket
import subprocess
import sys
import xml.etree.ElementTree as ET
from typing import Optional

sys.path.insert(0, "/usr/local/opnsense/scripts/keaubnd")
from lib.keaubnd_sync import setup_logging  # noqa: E402
from lib.preconditions import check_preconditions, write_status  # noqa: E402

CONFIG_XML = "/conf/config.xml"
RUNTIME_CONFIG_PATH = "/var/run/keaubnd/keaubnd.json"
DAEMON = "/usr/sbin/daemon"
SCRIPT = "/usr/local/sbin/kea-ubnd-ddns.py"
LOGWATCH_SCRIPT = "/usr/local/sbin/kea-ubnd-logwatch.py"
# Child (listener) PID — used by the service status check (keaubnd_services).
PIDFILE = "/var/run/kea-ubnd-ddns.pid"
# daemon(8) supervisor PID — the process that holds the -r respawn loop. Stop and
# restart must signal THIS (not the child): killing only the child lets the
# supervisor immediately respawn it, and each start would add another supervisor,
# so two would fight over the port and crash-loop on "Address already in use".
SUPERVISOR_PIDFILE = "/var/run/kea-ubnd-ddns.supervisor.pid"
# Logwatch daemon pidfiles (same pattern)
LOGWATCH_PIDFILE = "/var/run/kea-ubnd-logwatch.pid"
LOGWATCH_SUPERVISOR_PIDFILE = "/var/run/kea-ubnd-logwatch.supervisor.pid"

# Log to syslog (the keaubnd log) and, because this runs under the configd
# [start] action, also to stderr (verbose=True) so failures surface in the
# action output too.
logger = setup_logging(verbose=True)


# ── Kea conf socket resolution (used by _write_runtime_config) ───────────────

# Kea conf files and their top-level JSON keys, per service.
_KEA_CONF_FILES = {
    "dhcp4": "/usr/local/etc/kea/kea-dhcp4.conf",
    "dhcp6": "/usr/local/etc/kea/kea-dhcp6.conf",
    "d2": "/usr/local/etc/kea/kea-dhcp-ddns.conf",
}
_KEA_ROOT_KEYS = {"dhcp4": "Dhcp4", "dhcp6": "Dhcp6", "d2": "DhcpDdns"}
_KEA_PID_FILES = {
    "dhcp4": "/var/run/kea/kea-dhcp4.kea-dhcp4.pid",
    "dhcp6": "/var/run/kea/kea-dhcp6.kea-dhcp6.pid",
    "d2": "/var/run/kea/kea-dhcp-ddns.kea-dhcp-ddns.pid",
}
# OPNsense provisions these socket paths even when the conf file omits them.
_KEA_DEFAULT_SOCKETS = {
    "dhcp4": "/var/run/kea/kea4-ctrl-socket",
    "dhcp6": "/var/run/kea/kea6-ctrl-socket",
}


def _select_kea_socket(sockets: list) -> Optional[str]:
    """Pick the best socket from a list of Kea control-socket dicts.
    Returns a unix path or http(s):// URL string, preferring http(s) over unix."""
    unix_path = None
    for sock in sockets:
        stype = (sock.get("socket-type") or "").lower()
        if stype in ("http", "https"):
            host = sock.get("socket-address") or "127.0.0.1"
            try:
                port = int(sock.get("socket-port") or 0)
            except (TypeError, ValueError):
                port = 0
            if port:
                return f"{stype}://{host}:{port}"
        elif stype == "unix" and unix_path is None:
            unix_path = sock.get("socket-name")
    return unix_path


def _resolve_kea_socket(service: str, is_manual: bool) -> Optional[str]:
    """Parse the Kea conf file for `service` and return its control socket as
    a unix path or http(s):// URL. Falls back to the OPNsense default when the
    service is OPNsense-managed and the conf omits a control-socket stanza."""
    conf_path = _KEA_CONF_FILES.get(service)
    root_key = _KEA_ROOT_KEYS.get(service)
    if not conf_path or not root_key:
        return None

    if os.path.exists(conf_path):
        try:
            with open(conf_path) as f:
                conf = json.load(f)
            root = conf.get(root_key, {})
            if isinstance(root.get("control-sockets"), list):
                sockets = root["control-sockets"]
            elif isinstance(root.get("control-socket"), dict):
                sockets = [root["control-socket"]]
            else:
                sockets = []
            result = _select_kea_socket(sockets)
            if result:
                return result
        except (OSError, ValueError):
            pass

    if is_manual:
        return None  # admin owns the conf; don't guess a socket path
    return _KEA_DEFAULT_SOCKETS.get(service)


def _detect_unbound_reload_command() -> str:
    """Return 'fast-reload' if the installed Unbound binary is >= 1.22, else 'reload'."""
    try:
        r = subprocess.run(
            ["/usr/local/sbin/unbound", "-V"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        m = re.search(r"Version\s+(\d+)\.(\d+)", r.stdout or r.stderr)
        if m and (int(m.group(1)), int(m.group(2))) >= (1, 22):
            return "fast-reload"
    except Exception:
        pass
    return "reload"


def _write_runtime_config(xml_root, cfg: dict | None = None) -> None:
    """Build and write /var/run/keaubnd/keaubnd.json from the already-parsed
    config.xml root element. Called before check_preconditions() so preconditions
    can use the runtime config if needed. cfg is the dict returned by get_config()
    and is used to embed runtime-tunable settings (e.g. fast-reload threshold)."""
    if cfg is None:
        cfg = {}
    # System domain: last-resort FQDN suffix when Kea has no ddns-qualifying-suffix
    node = xml_root.find("system/domain")
    system_domain = (node.text or "").strip() if node is not None else ""

    kea: dict = {}
    for service in ("dhcp4", "dhcp6", "d2"):
        entry: dict = {"pid": _KEA_PID_FILES[service]}
        if service in ("dhcp4", "dhcp6"):
            en_node = xml_root.find(f"OPNsense/Kea/{service}/general/enabled")
            enabled = en_node is None or (en_node.text or "").strip() not in (
                "0",
                "false",
                "no",
            )
            if not enabled:
                entry["socket"] = None
            else:
                man_node = xml_root.find(
                    f"OPNsense/Kea/{service}/general/manual_config"
                )
                is_manual = man_node is not None and (man_node.text or "").strip() in (
                    "1",
                    "true",
                    "yes",
                )
                entry["socket"] = _resolve_kea_socket(service, is_manual)
        else:
            entry["conf"] = _KEA_CONF_FILES["d2"]
        kea[service] = entry

    runtime = {
        "fallback-system-domain": system_domain,
        "unbound": {
            "control": "/usr/local/sbin/unbound-control",
            "conf": "/var/unbound/unbound.conf",
            "host-entries": "/var/unbound/host_entries.conf",
            "pid": "/var/run/unbound.pid",
        },
        "kea": kea,
        "logwatch": {
            "kea-log-dir": "/var/log/kea",
            "kea-log-prefix": "kea",
            "listener-log-dir": "/var/log/keaubnd",
            "listener-prefix": "keaubnd",
            "clean-script": "/usr/local/opnsense/scripts/keaubnd/local-data-clean.py",
            "sync-script": "/usr/local/opnsense/scripts/keaubnd/run-sync.py",
        },
        "fast-reload": {
            "enabled": cfg.get("enable_fast_reload", "1") == "1",
            "threshold": (
                int(cfg.get("fast_reload_threshold", "5000") or "5000")
                if cfg.get("enable_fast_reload", "1") == "1"
                else 0
            ),
            "reload_command": "reload",  # TODO: restore _detect_unbound_reload_command() when upstream fast-reload memory leak is fixed
        },
        "clean_stale_records": cfg.get("clean_stale_records") == "1",
        "write_magic_ptrs": cfg.get("write_magic_ptrs") == "1",
    }

    os.makedirs(os.path.dirname(RUNTIME_CONFIG_PATH), mode=0o700, exist_ok=True)
    tmp = RUNTIME_CONFIG_PATH + ".tmp"
    with open(tmp, "w") as f:
        json.dump(runtime, f, indent=2)
        f.write("\n")
    os.replace(tmp, RUNTIME_CONFIG_PATH)
    logger.info("wrote runtime config: %s", RUNTIME_CONFIG_PATH)


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
    """Read KeaUbnd settings from config.xml. Returns (cfg dict, xml_root)."""
    cfg: dict[str, str] = {
        "enabled": "0",
        "port": "53535",
        "synthesize_ptr": "1",
        "collision_policy": "last_wins",
        "magic_names": "0",
        "magic_laa_tag": "0",
        "clean_stale_records": "",  # required; set by migration M1_0_1 on upgrade
        "write_magic_ptrs": "0",
        "max_full_sync_attempts": "",
        "readiness_watchdog_minutes": "",
        "enable_logwatch": "0",
        "logwatch_on_release": "1",
        "logwatch_on_servfail": "1",
        "logwatch_on_missed_remove": "1",
        "enable_fast_reload": "1",
        "fast_reload_threshold": "5000",
    }
    try:
        tree = ET.parse(CONFIG_XML)
        root = tree.getroot()
        node = root.find("OPNsense/KeaUbnd/general")
        if node is not None:
            for key in cfg:
                child = node.find(key)
                if child is not None and child.text:
                    cfg[key] = child.text.strip()
    except Exception as e:
        logger.error("cannot read %s: %s", CONFIG_XML, e)
        sys.exit(1)

    # TODO: read enable_tsig/tsig_key_name/tsig_key_secret/tsig_algorithm from the
    # model when TSIG is implemented. Hardcoded off for now — TSIG fields are absent
    # from General.xml and the listener binds only to 127.0.0.1, so unsigned updates
    # are safe for all single-host deployments.
    cfg["enable_tsig"] = "0"
    cfg["tsig_key_name"] = ""
    cfg["tsig_key_secret"] = ""
    cfg["tsig_algorithm"] = "HMAC-SHA256"

    return cfg, root


def main():
    cfg, xml_root = get_config()

    if cfg["enabled"] != "1":
        logger.info("kea-ubnd-ddns is disabled — not starting.")
        sys.exit(0)

    if not cfg["clean_stale_records"]:
        logger.error(
            "clean_stale_records missing from config.xml — "
            "migration M1_0_1 may not have run. Try: "
            "/usr/local/opnsense/mvc/script/run_migrations.php OPNsense/KeaUbnd"
        )
        sys.exit(1)

    # Write /var/run/keaubnd/keaubnd.json before check_preconditions() so the
    # libs (kea_transport, keaubnd_sync, pid_watch) can read resolved paths from
    # it rather than touching config.xml or Kea's own conf files at runtime.
    try:
        _write_runtime_config(xml_root, cfg)
    except Exception as e:
        logger.error("failed to write runtime config: %s", e)
        sys.exit(1)

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
        logger.info(
            "kea-ubnd-ddns already running (supervisor pid %s) — not starting another.",
            existing,
        )
        sys.exit(0)

    port = int(cfg["port"])
    if _port_in_use(port):
        logger.error(
            "Port %d is already in use — an old instance may still be running. "
            "Run 'configctl keaubnd stop' to clear it before starting.",
            port,
        )
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

    # Preconditions: don't launch a daemon that would crash-loop or sit idle.
    # On refusal, record the reason in the status file (the UI banner reads it)
    # and exit 0 — not an error, just "not ready". The plugin's reconfigure on a
    # settings change re-runs start.py, so this self-corrects when DDNS is wired.
    ok, reason = check_preconditions(port)
    if not ok:
        logger.warning("not starting — %s", reason)
        write_status("refused", reason)
        sys.exit(0)

    # Build kea-ubnd-ddns.py argument list
    script_args = [SCRIPT, "--port", cfg["port"]]

    # TSIG is included but has not been developed.  As a result, it is absent from
    # General.xml and will not be enabled.  The rest of the TSIG code is only
    # present for potential future use.
    #
    # TSIG is gated solely on the enable_tsig switch. When enabled, the key name
    # and secret are mandatory — fail closed (refuse to start) rather than
    # silently listen unauthenticated. (The model also blocks saving this state,
    # so this is a backstop.)
    if cfg["enable_tsig"] == "1":
        if not cfg["tsig_key_name"] or not cfg["tsig_key_secret"]:
            logger.error(
                "TSIG is enabled but key name/secret is missing — "
                "refusing to start. Set the TSIG key or disable TSIG."
            )
            sys.exit(1)
        script_args += [
            "--tsig-key",
            f"{cfg['tsig_key_name']}:{cfg['tsig_key_secret']}",
            "--tsig-algorithm",
            cfg["tsig_algorithm"],
        ]

    if cfg["synthesize_ptr"] != "1":
        script_args.append("--no-synthesize-ptr")

    script_args += ["--collision-policy", cfg["collision_policy"]]

    if cfg["magic_names"] == "1":
        script_args.append("--magic-names")
    if cfg["magic_laa_tag"] == "1":
        script_args.append("--laa-tag")
    if (
        cfg["magic_names"] == "1"
        and cfg["write_magic_ptrs"] == "1"
        and cfg["synthesize_ptr"] == "1"
    ):
        script_args.append("--write-magic-ptrs")
    # clean_stale_records is no longer passed as a CLI arg; the daemon reads it
    # from keaubnd.json (written above in _write_runtime_config).
    if cfg["max_full_sync_attempts"]:
        script_args += ["--max-full-sync-attempts", cfg["max_full_sync_attempts"]]
    if cfg["readiness_watchdog_minutes"]:
        script_args += [
            "--readiness-watchdog-minutes",
            cfg["readiness_watchdog_minutes"],
        ]
    # fast-reload threshold is no longer passed as a CLI arg; the daemon reads it
    # from keaubnd.json (written above in _write_runtime_config). This ensures
    # the threshold is honoured even when the daemon is invoked outside start.py.

    # Launch via daemon(8): -f forks to background, -p writes the child PID,
    # -P writes the supervisor PID (so stop/restart can signal the supervisor),
    # -r restarts the child on crash (with 5s backoff via -R 5).
    cmd = [
        DAEMON,
        "-f",
        "-p",
        PIDFILE,
        "-P",
        SUPERVISOR_PIDFILE,
        "-r",
        "-R",
        "5",
    ] + script_args

    try:
        subprocess.run(cmd, check=True)
        logger.info("kea-ubnd-ddns started (port %s).", cfg["port"])
    except subprocess.CalledProcessError as e:
        logger.error("failed to start kea-ubnd-ddns: %s", e)
        sys.exit(1)

    # Start the log-watch daemon if enabled.
    if cfg["enable_logwatch"] == "1":
        _start_logwatch(cfg)


def _start_logwatch(cfg: dict) -> None:
    """Launch kea-ubnd-logwatch.py under its own daemon(8) supervisor."""
    existing = _pid_alive(LOGWATCH_SUPERVISOR_PIDFILE)
    if existing:
        logger.info("kea-ubnd-logwatch already running (supervisor pid %s).", existing)
        return

    for pf in (LOGWATCH_SUPERVISOR_PIDFILE, LOGWATCH_PIDFILE):
        if os.path.exists(pf) and _pid_alive(pf) is None:
            try:
                os.unlink(pf)
            except OSError:
                pass

    script_args = [sys.executable, LOGWATCH_SCRIPT, "--config", RUNTIME_CONFIG_PATH]
    if cfg.get("logwatch_on_release") != "1":
        script_args.append("--no-on-release")
    if cfg.get("logwatch_on_servfail") != "1":
        script_args.append("--no-on-servfail")
    if cfg.get("logwatch_on_missed_remove") != "1":
        script_args.append("--no-on-missed-remove")

    cmd = [
        DAEMON,
        "-f",
        "-p",
        LOGWATCH_PIDFILE,
        "-P",
        LOGWATCH_SUPERVISOR_PIDFILE,
        "-r",
        "-R",
        "5",
    ] + script_args
    try:
        subprocess.run(cmd, check=True)
        logger.info("kea-ubnd-logwatch started.")
    except subprocess.CalledProcessError as e:
        logger.warning("failed to start kea-ubnd-logwatch: %s", e)


if __name__ == "__main__":
    main()
