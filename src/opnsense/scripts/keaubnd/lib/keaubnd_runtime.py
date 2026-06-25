#!/usr/local/bin/python3
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Thomas Reagan
"""
keaubnd_runtime.py -- Read the runtime config written by start.py.

start.py resolves all OPNsense-specific paths (Kea sockets, pid files, Unbound
paths) once at daemon launch and writes /var/run/keaubnd/keaubnd.json. Every lib
module reads from this file rather than touching config.xml or Kea's own conf
files directly, keeping the libs portable to non-OPNsense deployments.

On non-OPNsense, write /var/run/keaubnd/keaubnd.json manually (or via your own
startup script) with the socket paths and file locations for your system.

Schema (all fields optional; each get_* function supplies a sensible default):
{
  "fallback-system-domain": "",            # last-resort DDNS hostname suffix
  "unbound": {
    "control":      "/usr/local/sbin/unbound-control",
    "conf":         "/var/unbound/unbound.conf",
    "host-entries": "/var/unbound/host_entries.conf",
    "pid":          "/var/run/unbound.pid"
  },
  "kea": {
    "dhcp4": {
      "socket": "/var/run/kea/kea4-ctrl-socket",  # path or http(s):// URL; null=disabled
      "pid":   "/var/run/kea/kea-dhcp4.kea-dhcp4.pid"
    },
    "dhcp6": { "socket": null, "pid": "..." },
    "d2":    { "pid": "...", "conf": "/usr/local/etc/kea/kea-dhcp-ddns.conf" }
  },
  "logwatch": {
    "kea-log-dir":      "/var/log/kea",
    "kea-log-prefix":   "kea",
    "listener-log-dir": "/var/log/keaubnd",
    "listener-prefix":  "keaubnd",
    "clean-script":     "/usr/local/opnsense/scripts/keaubnd/local-data-clean.py",
    "sync-script":      "/usr/local/opnsense/scripts/keaubnd/kea-sync.py"
  },
  "fast-reload": {
    "enabled":        true,
    "threshold":      5000,
    "reload_command": "reload"   # "fast-reload" disabled due to memory leak; see CLAUDE.md TODO
  },
  "clean_stale_records": true
}
"""

import json
import os
from typing import Optional, cast

RUNTIME_CONFIG_PATH = "/var/run/keaubnd/keaubnd.json"

_config_path: str = RUNTIME_CONFIG_PATH
_cache: Optional[dict] = None


def init(path: str) -> None:
    """Override the runtime config path and clear the cache.

    Call once at process startup before any other function — e.g. when
    --config is passed on the command line."""
    global _config_path, _cache
    _config_path = path
    _cache = None


def load() -> dict:
    """Read and cache keaubnd.json. Raises RuntimeError if absent or unreadable."""
    global _cache
    if _cache is not None:
        return _cache
    if not os.path.exists(_config_path):
        raise RuntimeError(
            f"{_config_path} not found — start the daemon first "
            f"('configctl keaubnd start' on OPNsense, or create the file manually)."
        )
    try:
        with open(_config_path) as f:
            data = cast(dict, json.load(f))
    except (OSError, json.JSONDecodeError) as e:
        raise RuntimeError(f"Cannot read {_config_path}: {e}") from e
    _cache = data
    return data


def get_fallback_system_domain() -> str:
    """OPNsense system domain used as last-resort FQDN suffix. Empty = don't qualify."""
    try:
        return load().get("fallback-system-domain", "") or ""
    except RuntimeError:
        return ""


def get_kea_socket(service: str) -> Optional[str]:
    """Control socket path or http(s):// URL for `service`; None = disabled/absent."""
    return load().get("kea", {}).get(service, {}).get("socket") or None


def get_kea_pid(service: str) -> Optional[str]:
    """Pid file path for a Kea service; None if not configured."""
    return load().get("kea", {}).get(service, {}).get("pid") or None


def get_kea_conf(service: str) -> Optional[str]:
    """Conf file path for a Kea service (currently only d2); None if not configured."""
    return load().get("kea", {}).get(service, {}).get("conf") or None


def get_unbound_control() -> str:
    """Path to the unbound-control binary."""
    try:
        return load().get("unbound", {}).get("control") or "/usr/local/sbin/unbound-control"
    except RuntimeError:
        return "/usr/local/sbin/unbound-control"


def get_unbound_conf() -> str:
    """Path to unbound.conf."""
    try:
        return load().get("unbound", {}).get("conf") or "/var/unbound/unbound.conf"
    except RuntimeError:
        return "/var/unbound/unbound.conf"


def get_host_entries() -> str:
    """Path to Unbound's host_entries.conf."""
    try:
        return load().get("unbound", {}).get("host-entries") or "/var/unbound/host_entries.conf"
    except RuntimeError:
        return "/var/unbound/host_entries.conf"


def get_unbound_pid() -> str:
    """Path to Unbound's pid file."""
    try:
        return load().get("unbound", {}).get("pid") or "/var/run/unbound.pid"
    except RuntimeError:
        return "/var/run/unbound.pid"


def _logwatch(key: str, default: str) -> str:
    try:
        return load().get("logwatch", {}).get(key) or default
    except RuntimeError:
        return default


def get_logwatch_kea_log_dir() -> str:
    return _logwatch("kea-log-dir", "/var/log/kea")


def get_logwatch_kea_log_prefix() -> str:
    return _logwatch("kea-log-prefix", "kea")


def get_logwatch_listener_log_dir() -> str:
    return _logwatch("listener-log-dir", "/var/log/keaubnd")


def get_logwatch_listener_prefix() -> str:
    return _logwatch("listener-prefix", "keaubnd")


def get_logwatch_clean_script() -> str:
    return _logwatch("clean-script",
                     "/usr/local/opnsense/scripts/keaubnd/local-data-clean.py")


def get_logwatch_sync_script() -> str:
    return _logwatch("sync-script",
                     "/usr/local/opnsense/scripts/keaubnd/run-sync.py")


def _fast_reload(key: str, default):
    try:
        return load().get("fast-reload", {}).get(key, default)
    except RuntimeError:
        return default


def get_fast_reload_enabled() -> bool:
    """Whether daemon-triggered fast-reload is enabled.
    Defaults to False if keaubnd.json is absent (non-OPNsense deployments that
    haven't written it should not trigger fast-reload unexpectedly)."""
    v = _fast_reload("enabled", False)
    return bool(v)


def get_fast_reload_threshold() -> int:
    """Live-path NCR count before fast-reload is triggered; 0 = disabled."""
    v = _fast_reload("threshold", 5000)
    try:
        return max(0, int(v))
    except (TypeError, ValueError):
        return 5000


def get_fast_reload_command() -> str:
    """The unbound-control subcommand to use for heap reclamation.
    'fast-reload' on Unbound >= 1.22, 'reload' otherwise. Detected once by
    start.py at daemon launch and stored in keaubnd.json."""
    v = _fast_reload("reload_command", "reload")
    return v if v in ("fast-reload", "reload") else "reload"


def get_clean_stale_records() -> bool:
    """Whether to run a stale-record sweep on every daemon startup reconcile.
    Defaults to True (matches General.xml default) when keaubnd.json is absent."""
    try:
        return bool(load().get("clean_stale_records", True))
    except RuntimeError:
        return True


def get_write_magic_ptrs() -> bool:
    """Whether PTR records for dynamic lease IPs in collision groups point to the
    magic FQDN (True) or the bare hostname / nothing (False). Only meaningful when
    magic_names is enabled. Defaults to False when keaubnd.json is absent."""
    try:
        return bool(load().get("write_magic_ptrs", False))
    except RuntimeError:
        return False
