#!/usr/local/bin/python3
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Thomas Reagan
"""
preconditions.py -- startup gates for the resident daemon.

start.py calls check_preconditions() before launching the daemon; if it returns
a refusal, start.py writes the reason to the status file and does NOT start, so
the UI can explain why instead of crash-looping daemon(8).

The DDNS-enabled resolution is INHERITANCE-AWARE (spike V6). Kea's
`ddns-send-updates` can be set globally and inherited by subnets, or left absent
to take Kea's default of true (when the global `dhcp-ddns.enable-updates` master
is on). ConfigCheckController's per-subnet `isset(... ) && === true` check is too
strict for a startup gate -- it would false-refuse a valid global-DDNS config --
so it stays a Config-Check advisory while the gate uses the resolution here.

The pure resolvers take parsed dicts / explicit paths so they unit-test on macOS
with fixture configs; check_preconditions() wires them to the real files.
"""
from __future__ import annotations

import json
import os
import xml.etree.ElementTree as _ET
from typing import Dict, List, Optional, Tuple

import time

# Conf file paths for each Kea service (same as the constants start.py uses).
# preconditions.py reads these directly for DDNS-wiring checks; it is a startup
# gate and runs AFTER start.py has written keaubnd.json, so reading Kea's own
# conf files here is acceptable and expected.
_CONF_FILES = {
    "dhcp4": "/usr/local/etc/kea/kea-dhcp4.conf",
    "dhcp6": "/usr/local/etc/kea/kea-dhcp6.conf",
    "d2":    "/usr/local/etc/kea/kea-dhcp-ddns.conf",
}

_CONFIG_XML = "/conf/config.xml"

_ENABLED_XPATHS = {
    "dhcp4": "OPNsense/Kea/dhcp4/general/enabled",
    "dhcp6": "OPNsense/Kea/dhcp6/general/enabled",
}

_MANUAL_XPATHS = {
    "dhcp4": "OPNsense/Kea/dhcp4/general/manual_config",
    "dhcp6": "OPNsense/Kea/dhcp6/general/manual_config",
}


def _is_service_enabled(service: str) -> bool:
    xpath = _ENABLED_XPATHS.get(service)
    if not xpath:
        return True
    try:
        node = _ET.parse(_CONFIG_XML).getroot().find(xpath)
    except (OSError, _ET.ParseError):
        return True
    if node is None:
        return True
    return (node.text or "").strip() in ("1", "true", "yes")


def _is_manual_config(service: str) -> bool:
    xpath = _MANUAL_XPATHS.get(service)
    if not xpath:
        return False
    try:
        node = _ET.parse(_CONFIG_XML).getroot().find(xpath)
    except (OSError, _ET.ParseError):
        return False
    return node is not None and (node.text or "").strip() in ("1", "true", "yes")


UNBOUND_CONTROL = "/usr/local/sbin/unbound-control"

# One status file, written by start.py (refusal) and the daemon (running/blocked/
# stopped/alert). The UI's StatusController reads it for the banner. Format is a
# single tab-separated line: "<state>\t<detail>\t<epoch>".
STATUS_FILE = "/var/run/keaubnd/daemon-status"


def write_status(state: str, detail: str = "") -> None:
    """Write the one-line status file. Best-effort; never raises."""
    try:
        os.makedirs(os.path.dirname(STATUS_FILE), exist_ok=True)
        with open(STATUS_FILE, "w") as f:
            f.write(f"{state}\t{detail}\t{int(time.time())}\n")
    except OSError:
        pass


# ── pure resolvers (take parsed config dicts) ────────────────────────────────

def ddns_master_enabled(dhcp_config: Dict) -> bool:
    """The global master switch: Dhcp4/6.dhcp-ddns.enable-updates. Absent ⇒ False
    (Kea defaults enable-updates to false; OPNsense writes it explicitly true when
    DDNS is on)."""
    return bool(dhcp_config.get("dhcp-ddns", {}).get("enable-updates") is True)


def _iter_all_subnets(dhcp_config: Dict, subnet_key: str):
    """Yield every subnet dict, including those nested in shared-networks."""
    yield from dhcp_config.get(subnet_key, [])
    for shared in dhcp_config.get("shared-networks", []):
        yield from shared.get(subnet_key, [])


def any_subnet_ddns_enabled(dhcp_config: Dict, subnet_key: str) -> bool:
    """True if at least one subnet has DDNS effectively enabled, resolving
    inheritance: a subnet's effective ddns-send-updates is its own value if set,
    else the global ddns-send-updates if set, else Kea's default (true). So a
    subnet is only "off" when explicitly set false at the subnet level, or when a
    global false is not overridden. (The caller has already confirmed the master
    enable-updates is on.)"""
    global_send = dhcp_config.get("ddns-send-updates")  # True / False / None
    found_any = False
    for subnet in _iter_all_subnets(dhcp_config, subnet_key):
        found_any = True
        sub = subnet.get("ddns-send-updates")
        effective = sub if sub is not None else (
            global_send if global_send is not None else True)
        if effective:
            return True
    # No subnets at all but master on + global send true ⇒ nothing to send to yet,
    # but DDNS is configured; treat "no subnets" as not-an-error only if global is
    # explicitly true (rare). Otherwise require at least one enabled subnet.
    if not found_any and global_send is True:
        return True
    return False


def d2_forward_targets_port(d2_config: Dict, port: int,
                            host: str = "127.0.0.1") -> bool:
    """True if d2's forward-ddns has at least one ddns-domain whose dns-servers
    include host:port -- i.e. d2 is wired to forward DNS UPDATEs to our listener."""
    domains = d2_config.get("forward-ddns", {}).get("ddns-domains", [])
    for d in domains:
        for srv in d.get("dns-servers", []):
            if srv.get("ip-address") == host and int(srv.get("port", 53)) == port:
                return True
    return False


# ── file loading ─────────────────────────────────────────────────────────────

def _load_kea_conf(service: str) -> Optional[Dict]:
    """Parse a kea conf file, returning the inner Dhcp4/Dhcp6/DhcpDdns dict, or
    None if absent/unparseable."""
    path = _CONF_FILES.get(service)
    root = {"dhcp4": "Dhcp4", "dhcp6": "Dhcp6", "d2": "DhcpDdns"}.get(service)
    if not path or not root or not os.path.exists(path):
        return None
    try:
        with open(path) as f:
            return json.load(f).get(root, {})
    except (OSError, ValueError):
        return None


# ── the gate ──────────────────────────────────────────────────────────────────

def check_preconditions(port: int) -> Tuple[bool, str]:
    """Return (ok, reason). ok=True ⇒ launch the daemon. ok=False ⇒ start.py
    writes `reason` to the status file and refuses to start.

    Gates (in order):
      1. unbound-control present + executable (hard).
      2. d2 forwards to our port (hard, unless d2 is in manual-config mode -> a
         Config-Check advisory only, since the admin owns that file).
      3. at least one enabled+wired DHCP service with the DDNS master on and
         >=1 subnet effectively DDNS-enabled (inheritance-aware, V6).
    """
    if not (os.path.isfile(UNBOUND_CONTROL) and os.access(UNBOUND_CONTROL, os.X_OK)):
        return False, "unbound-control not found or not executable"

    # d2 wiring: does kea-dhcp-ddns forward to us?
    d2_manual = _is_manual_config("d2") if "d2" in _manual_supported() else False
    d2_conf = _load_kea_conf("d2")
    if d2_conf is None:
        if not d2_manual:
            return False, "kea-dhcp-ddns.conf not found — is DDNS enabled in Kea?"
    elif not d2_forward_targets_port(d2_conf, port) and not d2_manual:
        return False, (f"kea-dhcp-ddns does not forward to 127.0.0.1:{port} — "
                       "check the DDNS forward zone")

    # DHCP wiring: at least one enabled service with DDNS effectively on.
    wired = []
    for service, subnet_key in (("dhcp4", "subnet4"), ("dhcp6", "subnet6")):
        if not _is_service_enabled(service):
            continue
        cfg = _load_kea_conf(service)
        if cfg is None:
            continue
        if ddns_master_enabled(cfg) and any_subnet_ddns_enabled(cfg, subnet_key):
            wired.append(service)

    if not wired:
        return False, ("no enabled DHCP subnet has DDNS turned on — enable "
                       "'Send DDNS updates' on at least one subnet")

    return True, "ready: " + ",".join(wired)


def _manual_supported() -> List[str]:
    """d2 has no manual_config xpath in OPNsense today; guard so a future one is
    honored without assuming it exists now."""
    return list(_MANUAL_XPATHS.keys())
