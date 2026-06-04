# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Thomas Reagan
"""
Integration test conftest: SSH, API, deploy, and Kea injection fixtures.

All integration tests require live services on orbison.  Load connection
info from env vars or tests/.env:

    OPNSENSE_HOST       — hostname / IP of the OPNsense box
    OPNSENSE_API_KEY    — API key ID
    OPNSENSE_API_SECRET — API key secret
    OPNSENSE_SSH_USER   — SSH login user (default: tkr)

Tests that inject Kea data use IP range 192.168.99.200-254 and hostname
prefix "testhost-" to avoid colliding with real leases.
"""

from __future__ import annotations

import json
import os
import pathlib
import subprocess
import time
from typing import Any, Generator

import pytest
import requests
from requests.auth import HTTPDigestAuth

REPO = pathlib.Path(__file__).parents[2]

TEST_IP_PREFIX = "192.168.99."
TEST_HOST_PREFIX = "testhost-"
TEST_IP_START = 200


def _load_env():
    env_file = REPO / "tests" / ".env"
    if env_file.exists():
        for line in env_file.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                os.environ.setdefault(k.strip(), v.strip())


_load_env()


# ── Session-scoped box info ───────────────────────────────────────────────────

@pytest.fixture(scope="session")
def box():
    host = os.environ.get("OPNSENSE_HOST")
    if not host:
        pytest.skip("OPNSENSE_HOST not set — skipping integration tests")
    return {
        "host": host,
        "api_key": os.environ.get("OPNSENSE_API_KEY", ""),
        "api_secret": os.environ.get("OPNSENSE_API_SECRET", ""),
        "ssh_user": os.environ.get("OPNSENSE_SSH_USER", "tkr"),
    }


# ── SSH helper ────────────────────────────────────────────────────────────────

@pytest.fixture(scope="session")
def ssh(box):
    """Return a function ssh(cmd: str) -> str that runs cmd on the box via sudo."""

    def run(cmd: str, check: bool = True, timeout: int = 60) -> str:
        full = (
            f"ssh -o ConnectTimeout=10 -o StrictHostKeyChecking=no "
            f"{box['ssh_user']}@{box['host']} "
            f"'sudo -n sh -c {repr(cmd)}'"
        )
        result = subprocess.run(
            full, shell=True, capture_output=True, text=True, timeout=timeout
        )
        if check and result.returncode != 0:
            raise RuntimeError(
                f"SSH command failed (rc={result.returncode}):\n"
                f"  cmd: {cmd}\n"
                f"  stdout: {result.stdout.strip()}\n"
                f"  stderr: {result.stderr.strip()}"
            )
        return result.stdout.strip()

    return run


# ── OPNsense REST API client ──────────────────────────────────────────────────

@pytest.fixture(scope="session")
def api(box):
    """Return a requests.Session pre-configured for the OPNsense API."""
    if not box["api_key"]:
        pytest.skip("OPNSENSE_API_KEY not set — skipping API tests")

    session = requests.Session()
    session.auth = HTTPDigestAuth(box["api_key"], box["api_secret"])
    session.verify = False  # OPNsense uses self-signed cert
    session.headers.update({"Content-Type": "application/json"})
    session.base_url = f"https://{box['host']}/api/keaunbound"

    def get(path: str, **kw) -> dict:
        r = session.get(f"{session.base_url}/{path.lstrip('/')}", **kw)
        r.raise_for_status()
        return r.json()

    def post(path: str, data: dict | None = None, **kw) -> dict:
        r = session.post(f"{session.base_url}/{path.lstrip('/')}",
                         json=data or {}, **kw)
        r.raise_for_status()
        return r.json()

    session.api_get = get
    session.api_post = post
    return session


# ── Kea socket helper ─────────────────────────────────────────────────────────

@pytest.fixture(scope="session")
def kea(ssh):
    """Send a Kea command via the control socket, return parsed response."""

    def query(command: str, service: str = "dhcp4",
              arguments: dict | None = None) -> dict:
        socket = (
            "/var/run/kea/kea4-ctrl-socket"
            if service == "dhcp4"
            else "/var/run/kea/kea6-ctrl-socket"
        )
        payload = json.dumps({"command": command, "arguments": arguments or {}})
        cmd = (
            f"echo '{payload}' | "
            f"/usr/local/bin/python3 -c \""
            f"import socket, json, sys; "
            f"s = socket.socket(socket.AF_UNIX); "
            f"s.connect('{socket}'); "
            f"s.sendall(sys.stdin.buffer.read()); "
            f"parts = []; r = s.recv(65536);"
            f"while r: parts.append(r); r = s.recv(65536) if not b'\\n' in r else b'';"
            f"print(b''.join(parts).decode())\""
        )
        raw = ssh(cmd)
        resp = json.loads(raw)
        if isinstance(resp, list):
            resp = resp[0]
        return resp

    return query


# ── Unbound query helper ──────────────────────────────────────────────────────

@pytest.fixture(scope="session")
def unbound(ssh):
    """Return a dict of name → [lines] from unbound list_local_data."""

    def list_local_data() -> dict[str, list[str]]:
        raw = ssh("/usr/local/sbin/unbound-control "
                  "-c /var/unbound/unbound.conf list_local_data")
        data: dict[str, list[str]] = {}
        for line in raw.splitlines():
            parts = line.split()
            if len(parts) >= 5 and parts[3] in ("A", "AAAA", "PTR"):
                name = parts[0].rstrip(".")
                data.setdefault(name, []).append(line)
        return data

    def has_record(hostname: str, ip: str, rdtype: str = "A") -> bool:
        data = list_local_data()
        lines = data.get(hostname, [])
        return any(ip in line and rdtype in line for line in lines)

    def has_ptr(ip: str, hostname: str) -> bool:
        import ipaddress
        try:
            ptr_name = str(ipaddress.ip_address(ip).reverse_pointer)
        except ValueError:
            return False
        data = list_local_data()
        lines = data.get(ptr_name, [])
        return any(hostname.rstrip(".") in line for line in lines)

    def remove_record(hostname: str) -> None:
        ssh(f"/usr/local/sbin/unbound-control "
            f"-c /var/unbound/unbound.conf local_data_remove {hostname}")

    return type("UnboundHelper", (), {
        "list_local_data": staticmethod(list_local_data),
        "has_record": staticmethod(has_record),
        "has_ptr": staticmethod(has_ptr),
        "remove_record": staticmethod(remove_record),
    })()


# ── Test state log (injected / observed / cleaned) ───────────────────────────

@pytest.fixture
def test_log(request):
    """Attach structured metadata to the test for the run report."""
    log: dict[str, Any] = {}

    def record(key: str, value: Any):
        log[key] = value

    yield record

    # Attach to the pytest report node so conftest.py can write it
    request.node._injected = log.get("injected")
    request.node._observed = log.get("observed")
    request.node._cleaned = log.get("cleaned")


# ── Test IP / hostname allocator ──────────────────────────────────────────────

_ip_counter = TEST_IP_START
_host_counter = 0


@pytest.fixture
def test_host():
    """Allocate a unique test hostname and IP for one test."""
    global _ip_counter, _host_counter
    _host_counter += 1
    _ip_counter += 1
    hostname = f"{TEST_HOST_PREFIX}{_host_counter:03d}.lan"
    ip = f"{TEST_IP_PREFIX}{_ip_counter}"
    return {"hostname": hostname, "ip": ip}


# ── Deploy fixture ────────────────────────────────────────────────────────────

@pytest.fixture(scope="session")
def deploy(ssh, box):
    """Build and deploy the current working tree to orbison once per session."""
    import tempfile
    tarball = pathlib.Path(tempfile.mktemp(suffix=".tar.gz"))
    subprocess.run(
        [
            "tar",
            "--exclude=__pycache__",
            "--exclude=.DS_Store",
            "--exclude=._*",
            "--exclude=*.pyc",
            "-czf", str(tarball),
            "-C", str(REPO / "src"),
            ".",
        ],
        env={**os.environ, "COPYFILE_DISABLE": "1"},
        check=True,
    )
    subprocess.run(
        ["scp", "-o", "ConnectTimeout=10", str(tarball),
         f"{box['ssh_user']}@{box['host']}:/tmp/keaunbound-test.tar.gz"],
        check=True,
    )
    ssh(
        "tar --no-xattrs --no-acls --no-fflags "
        "-xzf /tmp/keaunbound-test.tar.gz -C /usr/local"
    )
    tarball.unlink(missing_ok=True)
