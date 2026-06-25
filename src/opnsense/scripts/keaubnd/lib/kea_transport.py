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
                           the runtime config records an http(s):// socket URL)

resolve_kea_connection(service) figures out which transport to use by reading
the runtime config written by start.py (/var/run/keaubnd/keaubnd.json). All
OPNsense-specific path resolution (parsing Kea conf files, reading config.xml
for enabled flags) happens once at daemon startup in start.py, not at runtime
in this module. Non-OPNsense deployments write keaubnd.json via their own
startup script.

Resolution is memoized for the lifetime of the process only. Every caller is a
short-lived script (kea-sync, audit, clean) that re-resolves on its next
invocation, so a Kea reconfigure is picked up by the next run with no
cache-invalidation logic -- process restart is the invalidation. The live
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
import urllib.parse
import urllib.request
from typing import Dict, List, Optional

# Matches SYSLOG_IDENT in keaubnd_sync; duplicated (rather than imported) to
# avoid a circular import, since keaubnd_sync imports from this module.
_LOG_TAG = "kea-ub"


class KeaUnavailableError(Exception):
    """Raised when a Kea daemon is not available or not responding."""
    pass


class KeaServiceUnavailableError(KeaUnavailableError):
    """Raised when a Kea service should be skipped rather than aborting the caller.

    Two sources:
      - Socket absent / not configured (service disabled or not started) — from
        _build_connection when the runtime config has no socket for that service.
      - rc == 2 (unsupported command) — from kea_query when a reachable daemon
        doesn't recognise the command (e.g. lease_cmds hook library not loaded).

    Subclass of KeaUnavailableError so existing handlers that catch the base
    class still work; callers that want per-service tolerance catch this directly.
    rc == 1 (command recognised but failed) raises the base KeaUnavailableError
    to signal a hard error from a reachable daemon."""
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

    # Step 0: explicit plugin override (reserved -- UI fields disabled for now).
    override = _plugin_override(service, timeout)
    if override is not None:
        log.debug("kea %s: using plugin connection override", service)
        return override

    # Read the socket value from the runtime config written by start.py.
    from . import keaubnd_runtime as _rt
    socket_val = _rt.get_kea_socket(service)
    if not socket_val:
        raise KeaServiceUnavailableError(
            f"Kea {service}: no socket configured (service disabled or not started)"
        )

    if socket_val.startswith(("http://", "https://")):
        parsed = urllib.parse.urlparse(socket_val)
        log.debug("kea %s: HTTP transport → %s", service, socket_val)
        return HttpTransport(
            host=parsed.hostname or "127.0.0.1",
            port=parsed.port or (443 if socket_val.startswith("https://") else 80),
            tls=socket_val.startswith("https://"),
            verify=False,
            timeout=timeout,
        )

    log.debug("kea %s: unix socket → %s", service, socket_val)
    return UnixSocketTransport(socket_val, timeout)


def _plugin_override(service: str, timeout: float):
    """Reserved hook for the (currently disabled) plugin connection settings."""
    return None


# ── High-level query ──────────────────────────────────────────────────────────

def kea_query(command: str, arguments: Optional[Dict] = None,
              service: str = "dhcp4", timeout: float = 5.0) -> Dict:
    """Resolve the connection for `service`, run `command`, and return the
    normalized, result-checked response map.

    Normalization: HTTP (direct daemon) responses are wrapped in a one-element
    list for backward compatibility; unix-socket responses are a plain object.
    Both are reduced to a single map here so transports are interchangeable.

    Kea result codes: 0=success, 1=error, 2=unsupported, 3=empty (success, no
    data). EMPTY (3) is treated as success. rc=2 (command not recognised by any
    loaded hook) raises KeaServiceUnavailableError so callers can skip that
    service. rc=1 (command recognised but the daemon returned an error) raises
    KeaUnavailableError — a reachable daemon that errors is not the same as a
    disabled service and must not be silently skipped."""
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
    if rc in (0, 3):
        return result
    if rc == 2:
        raise KeaServiceUnavailableError(
            f"Kea command '{command}' unsupported: {result.get('text', 'unknown')}"
        )
    raise KeaUnavailableError(
        f"Kea command '{command}' failed (rc={rc}): {result.get('text', 'unknown error')}"
    )
