#!/usr/local/bin/python3
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Thomas Reagan
"""
kea_transport.py -- Connection layer for talking to Kea daemons directly.

The Kea Control Agent (kea-ctrl-agent) is deprecated and removed in current
Kea; the supported interface is to speak the command protocol directly to each
daemon (kea-dhcp4, kea-dhcp6, kea-dhcp-ddns) over its own control channel. This
module provides that, behind a transport abstraction so the call sites do not
care whether the channel is a unix socket or an HTTP listener:

  - UnixSocketTransport -- AF_UNIX stream socket (what OPNsense provisions today)
  - HttpTransport       -- HTTP/HTTPS listener on localhost (Kea's longer-term
                           direction; fully implemented here, selected only when
                           the running Kea config actually declares one)

resolve_kea_connection(service) figures out which transport to use by *reading
configuration* (never by probing sockets/ports on a running firewall):

  Step 0  explicit plugin override   (//OPNsense/KeaUnbound/... -- reserved,
          currently disabled in the UI, so this falls through)
  Step 1  configd discovery          (reserved no-op: OPNsense 26.1 exposes no
          socket-discovery action)
  Step 2  parse the active Kea conf   (/usr/local/etc/kea/kea-dhcp{4,6}.conf):
          read its control-socket / control-sockets stanza for type + path or
          host/port. This is the real source of truth and also reflects any
          hand-edited "manual configuration".
  Step 3  hardcoded OPNsense default  (/var/run/kea/kea{4,6}-ctrl-socket) --
          skipped when manual configuration is enabled, since guessing a path
          for an admin-owned config would be wrong.
  Step 4  graceful KeaUnavailableError

Resolution is memoized for the lifetime of the process only. Every caller is a
short-lived script (lease-sync, reservation-sync, audit, clean) that re-resolves
on its next invocation, so a Kea reconfigure is picked up by the next run with
no cache-invalidation logic -- process restart is the invalidation. The live
lease/reservation data itself is always fetched fresh; only the connection
descriptor is memoized.

Uses only the Python standard library so it runs on a stock OPNsense install.
"""

from __future__ import annotations

import json
import logging
import os
import socket as _socket
import ssl
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
from typing import Dict, List, Optional

# Matches SYSLOG_IDENT in keaunbound_sync; duplicated (rather than imported) to
# avoid a circular import, since keaunbound_sync imports from this module.
_LOG_TAG = "kea-ub"

CONFIG_XML = "/conf/config.xml"

# Per-service generated Kea config files and their top-level config keys.
_CONF_FILES = {
    "dhcp4": "/usr/local/etc/kea/kea-dhcp4.conf",
    "dhcp6": "/usr/local/etc/kea/kea-dhcp6.conf",
    "d2":    "/usr/local/etc/kea/kea-dhcp-ddns.conf",
}
_ROOT_KEYS = {"dhcp4": "Dhcp4", "dhcp6": "Dhcp6", "d2": "DhcpDdns"}

# Hardcoded OPNsense defaults -- identical to what OPNsense core's own KeaCtrl
# uses. Note OPNsense provisions no control socket for d2, so it has no default.
_DEFAULT_SOCKETS = {
    "dhcp4": "/var/run/kea/kea4-ctrl-socket",
    "dhcp6": "/var/run/kea/kea6-ctrl-socket",
}

# config.xml flags for OPNsense's "manual configuration" mode, per service.
# Confirmed against OPNsense 26.1: //OPNsense/Kea/dhcp{4,6}/general/manual_config.
# Read defensively so a missing path simply means "not manual".
_MANUAL_XPATHS = {
    "dhcp4": "OPNsense/Kea/dhcp4/general/manual_config",
    "dhcp6": "OPNsense/Kea/dhcp6/general/manual_config",
}

# config.xml enable flags per service: //OPNsense/Kea/dhcp{4,6}/general/enabled.
# A disabled service has no control socket to reach, so treating its absence as
# an error is wrong — we skip it (KeaServiceUnavailableError) rather than fail.
_ENABLED_XPATHS = {
    "dhcp4": "OPNsense/Kea/dhcp4/general/enabled",
    "dhcp6": "OPNsense/Kea/dhcp6/general/enabled",
}


class KeaUnavailableError(Exception):
    """Raised when a Kea daemon is not available or not responding."""
    pass


class KeaServiceUnavailableError(KeaUnavailableError):
    """Raised when the channel is reachable but the daemon rejected the command
    or the service is offline. Subclass of KeaUnavailableError so existing
    handlers still catch it, while callers wanting per-service tolerance can
    catch this and skip just that service."""
    pass


# ── Transports ────────────────────────────────────────────────────────────────

class UnixSocketTransport:
    """Talk to a Kea daemon over its AF_UNIX control socket.

    Kea's unix command manager handles one command per connection and closes the
    socket after sending the response, so we open a fresh connection per query
    and read until EOF. The response is a plain JSON object (HTTP responses, by
    contrast, are wrapped in a one-element array -- normalization happens in the
    caller so both transports are interchangeable)."""

    def __init__(self, path: str, timeout: float = 5.0):
        self.path = path
        self.timeout = timeout

    def query(self, command: str, arguments: Optional[Dict] = None,
              timeout: Optional[float] = None):
        if not os.path.exists(self.path):
            raise KeaUnavailableError(
                f"Kea control socket not found: {self.path} "
                f"(is the Kea daemon running?)"
            )
        payload: Dict = {"command": command}
        if arguments:
            payload["arguments"] = arguments
        blob = json.dumps(payload).encode("utf-8") + b"\n"
        to = timeout if timeout is not None else self.timeout

        chunks: List[bytes] = []
        try:
            with _socket.socket(_socket.AF_UNIX, _socket.SOCK_STREAM) as sock:
                sock.settimeout(to)
                sock.connect(self.path)
                sock.sendall(blob)
                while True:
                    chunk = sock.recv(65536)
                    if not chunk:
                        break
                    chunks.append(chunk)
        except _socket.timeout:
            raise KeaUnavailableError(f"Kea socket timed out: {self.path}")
        except (OSError, ConnectionError) as e:
            raise KeaUnavailableError(f"Kea socket error ({self.path}): {e}")

        try:
            return json.loads(b"".join(chunks).decode("utf-8"))
        except json.JSONDecodeError as e:
            raise KeaUnavailableError(f"Kea returned invalid JSON: {e}")


class HttpTransport:
    """Talk to a Kea daemon over its HTTP/HTTPS control listener.

    Used when the running Kea config declares an http/https control socket.
    `verify` toggles TLS certificate verification -- OPNsense-generated certs are
    typically self-signed, so verification is off by default for https here."""

    def __init__(self, host: str, port: int, tls: bool = False,
                 verify: bool = False, timeout: float = 5.0):
        self.host = host
        self.port = port
        self.tls = tls
        self.verify = verify
        self.timeout = timeout

    def _url(self) -> str:
        scheme = "https" if self.tls else "http"
        return f"{scheme}://{self.host}:{self.port}/"

    def query(self, command: str, arguments: Optional[Dict] = None,
              timeout: Optional[float] = None):
        payload: Dict = {"command": command}
        if arguments:
            payload["arguments"] = arguments
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            self._url(), data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        ctx = None
        if self.tls and not self.verify:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        to = timeout if timeout is not None else self.timeout

        try:
            with urllib.request.urlopen(req, timeout=to, context=ctx) as resp:
                body = resp.read()
        except urllib.error.HTTPError as e:
            raise KeaUnavailableError(f"Kea HTTP {e.code}: {e.reason}")
        except urllib.error.URLError as e:
            raise KeaUnavailableError(f"Kea HTTP unreachable: {e.reason}")
        except (TimeoutError, OSError) as e:
            raise KeaUnavailableError(f"Kea HTTP error: {e}")

        try:
            return json.loads(body)
        except json.JSONDecodeError as e:
            raise KeaUnavailableError(f"Kea returned invalid JSON: {e}")


# ── Resolution ────────────────────────────────────────────────────────────────

# Per-process memo of resolved transports (see module docstring for why this is
# the right scope and needs no invalidation).
_resolved: Dict[str, object] = {}


def resolve_kea_connection(service: str, timeout: float = 5.0):
    """Return a transport for `service`, memoized for the life of the process."""
    if service not in _resolved:
        _resolved[service] = _build_connection(service, timeout)
    return _resolved[service]


def _build_connection(service: str, timeout: float):
    log = logging.getLogger(_LOG_TAG)

    # Step -1: if the service is disabled in OPNsense, there is nothing to reach.
    # Report it as a per-service skip (not a hard error) so callers move on
    # quietly instead of surfacing a "control socket not found" warning.
    if not _is_service_enabled(service):
        raise KeaServiceUnavailableError(f"Kea {service} is not enabled")

    # Step 0: explicit plugin override (reserved -- UI fields disabled for now).
    override = _plugin_override(service, timeout)
    if override is not None:
        log.debug("kea %s: using plugin connection override", service)
        return override

    # Step 1: configd discovery -- reserved no-op (OPNsense 26.1 exposes none).

    # Step 2: parse the active Kea conf file.
    manual = _is_manual_config(service)
    desc = _parse_conf_socket(service)
    if desc is not None:
        log.debug("kea %s: resolved %s connection from conf file",
                  service, desc["type"])
        return _transport_from_desc(desc, timeout)

    # Step 3: hardcoded default -- but never guess for an admin-owned config.
    if manual:
        raise KeaUnavailableError(
            f"Kea {service}: manual configuration is enabled but no usable "
            f"control socket was found in {_CONF_FILES.get(service)}. Add a "
            f"control-socket stanza to the manual Kea configuration."
        )
    default = _DEFAULT_SOCKETS.get(service)
    if default:
        log.debug("kea %s: falling back to default socket %s", service, default)
        return UnixSocketTransport(default, timeout)

    # Step 4: nothing resolved.
    raise KeaUnavailableError(
        f"Cannot resolve a Kea connection for '{service}': no control socket "
        f"configured in {_CONF_FILES.get(service, 'its conf file')} and no "
        f"default available."
    )


def _plugin_override(service: str, timeout: float):
    """Reserved hook for the (currently disabled) plugin connection settings.

    When those settings are enabled, this is where we would read
    //OPNsense/KeaUnbound/... for an explicit unix/http override and return the
    matching transport. Until then it always falls through."""
    return None


def _is_manual_config(service: str) -> bool:
    """True if OPNsense's manual-configuration mode is enabled for the service,
    meaning the conf file is admin-owned and must not be second-guessed with a
    default socket path."""
    xpath = _MANUAL_XPATHS.get(service)
    if not xpath:
        return False
    try:
        node = ET.parse(CONFIG_XML).getroot().find(xpath)
    except (OSError, ET.ParseError):
        return False
    return node is not None and (node.text or "").strip() in ("1", "true", "yes")


def _is_service_enabled(service: str) -> bool:
    """True if OPNsense has the Kea service enabled. Defaults to True when the
    flag is absent so we never wrongly skip a service on a config that lacks it
    — only an explicit '0' is treated as disabled."""
    xpath = _ENABLED_XPATHS.get(service)
    if not xpath:
        return True
    try:
        node = ET.parse(CONFIG_XML).getroot().find(xpath)
    except (OSError, ET.ParseError):
        return True
    if node is None:
        return True
    return (node.text or "").strip() in ("1", "true", "yes")


def _parse_conf_socket(service: str) -> Optional[Dict]:
    """Parse the service's Kea conf file and return a connection descriptor for
    its control socket, or None if the file is absent/unparseable/has no socket.

    Handles both the singular `control-socket` (older Kea / OPNsense 26.1) and
    the `control-sockets` list (Kea 3.x), preferring http(s) over unix when both
    are present."""
    conf_path = _CONF_FILES.get(service)
    root_key = _ROOT_KEYS.get(service)
    if not conf_path or not root_key or not os.path.exists(conf_path):
        return None
    try:
        with open(conf_path) as f:
            conf = json.load(f)
    except (OSError, ValueError):
        return None

    root = conf.get(root_key, {})
    if isinstance(root.get("control-sockets"), list):
        sockets = root["control-sockets"]
    elif isinstance(root.get("control-socket"), dict):
        sockets = [root["control-socket"]]
    else:
        return None

    return _select_socket(sockets)


def _select_socket(sockets: List[Dict]) -> Optional[Dict]:
    """Pick a usable socket, preferring http(s) over unix."""
    unix_choice = None
    for sock in sockets:
        stype = (sock.get("socket-type") or "").lower()
        if stype in ("http", "https"):
            desc = _desc_from_socket(sock)
            if desc is not None:
                return desc
        elif stype == "unix" and unix_choice is None:
            unix_choice = sock
    return _desc_from_socket(unix_choice) if unix_choice is not None else None


def _desc_from_socket(sock: Dict) -> Optional[Dict]:
    stype = (sock.get("socket-type") or "").lower()
    if stype == "unix":
        name = sock.get("socket-name")
        return {"type": "unix", "path": name} if name else None
    if stype in ("http", "https"):
        try:
            port = int(sock.get("socket-port") or 0)
        except (TypeError, ValueError):
            port = 0
        if not port:
            return None
        return {
            "type": "http",
            "host": sock.get("socket-address") or "127.0.0.1",
            "port": port,
            "tls": stype == "https",
            "verify": False,
        }
    return None


def _transport_from_desc(desc: Dict, timeout: float):
    if desc["type"] == "unix":
        return UnixSocketTransport(desc["path"], timeout)
    if desc["type"] == "http":
        return HttpTransport(
            desc["host"], desc["port"],
            tls=desc.get("tls", False),
            verify=desc.get("verify", False),
            timeout=timeout,
        )
    raise KeaUnavailableError(f"Unknown Kea transport descriptor: {desc}")


# ── High-level query ──────────────────────────────────────────────────────────

def kea_query(command: str, arguments: Optional[Dict] = None,
              service: str = "dhcp4", timeout: float = 5.0) -> Dict:
    """Resolve the connection for `service`, run `command`, and return the
    normalized, result-checked response map.

    Normalization: HTTP (direct daemon) responses are wrapped in a one-element
    list for backward compatibility; unix-socket responses are a plain object.
    Both are reduced to a single map here so transports are interchangeable.

    Kea result codes: 0=success, 1=error, 2=unsupported, 3=empty (success, no
    data). EMPTY is treated as success; command-level failures raise
    KeaServiceUnavailableError."""
    transport = resolve_kea_connection(service, timeout)
    result = transport.query(command, arguments, timeout)

    if isinstance(result, list):
        if not result:
            raise KeaUnavailableError(
                f"Kea command '{command}' returned an empty response")
        result = result[0]
    if not isinstance(result, dict):
        raise KeaUnavailableError(
            f"Kea command '{command}' returned an unexpected response")

    rc = result.get("result")
    if rc == 3:
        return result
    if rc != 0:
        raise KeaServiceUnavailableError(
            f"Kea command '{command}' failed: {result.get('text', 'unknown error')}"
        )
    return result
