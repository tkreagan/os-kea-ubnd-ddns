# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Thomas Reagan
"""
Integration test conftest — password-based SSH via paramiko.

Infrastructure:
  dev-opnsense   OPNsense 26.1.9, em1 = 192.168.1.1/24
                 Plugin installed; build tree at PLUGIN_DIR
  dev-dhcpclient Debian 13, ens19 = 192.168.1.100 (DHCP from dev-opnsense)

Connection info from tests/.env or environment variables:

  OPNSENSE_HOST        hostname / IP of dev-opnsense
  OPNSENSE_SSH_USER    SSH user (default: dev)
  OPNSENSE_SSH_PASS    SSH + sudo password (default: dev)
  OPNSENSE_API_KEY     OPNsense API key ID
  OPNSENSE_API_SECRET  OPNsense API key secret
  DHCPCLIENT_HOST      hostname / IP of dev-dhcpclient
  DHCPCLIENT_SSH_USER  SSH user (default: dev)
  DHCPCLIENT_SSH_PASS  SSH + sudo password (default: dev)
  DHCPCLIENT_LAN_IF    DHCP interface on the client (default: ens19)
  PLUGIN_DIR           Build tree on the OPNsense box
                       (default: /usr/plugins/net/kea-unbound)

Test data:
  Injected leases/reservations use 192.168.1.201-254 (inside the subnet but
  outside the DHCP pool of .100-.200) and hostname prefix "testhost-".
"""

from __future__ import annotations

import io
import json
import os
import pathlib
import tempfile
import time
from typing import Any

import pytest
import requests
from requests.auth import HTTPDigestAuth

REPO = pathlib.Path(__file__).parents[2]

# Test-data allocation
TEST_IP_PREFIX = "192.168.1."
TEST_IP_START  = 201          # .201–.254: in subnet, outside DHCP pool
TEST_HOST_PREFIX = "testhost-"

_ip_counter   = TEST_IP_START
_host_counter = 0

PLUGIN_DIR_DEFAULT = "/usr/plugins/net/kea-unbound"


# ── Environment loading ───────────────────────────────────────────────────────

def _load_env() -> None:
    env_file = REPO / "tests" / ".env"
    if env_file.exists():
        for line in env_file.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                os.environ.setdefault(k.strip(), v.strip())


_load_env()


# ── Paramiko SSH session ──────────────────────────────────────────────────────

class SSHSession:
    """
    Thin wrapper around paramiko for password-based SSH.

    Usage:
        session = SSHSession("host", "user", "pass")
        output = session("sudo command")          # sudo via stdin password
        output = session.run("non-sudo command")  # no privilege escalation
        session.sftp_upload(local, remote)        # file upload
    """

    def __init__(self, host: str, user: str, password: str,
                 sudo_password: str | None = None):
        import paramiko
        self.host = host
        self.user = user
        self.password = password
        self.sudo_password = sudo_password or password

        self._client = paramiko.SSHClient()
        self._client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self._client.connect(
            host, username=user, password=password,
            look_for_keys=False, allow_agent=False,
            timeout=15,
        )

    def run(self, cmd: str, check: bool = True, timeout: int = 60) -> str:
        """Run cmd (no sudo). Return stdout as a string."""
        _, stdout, stderr = self._client.exec_command(cmd, timeout=timeout)
        out = stdout.read().decode().strip()
        err = stderr.read().decode().strip()
        rc = stdout.channel.recv_exit_status()
        if check and rc != 0:
            raise RuntimeError(
                f"[{self.host}] Command failed (rc={rc}):\n"
                f"  cmd: {cmd}\n"
                f"  out: {out[:500]}\n"
                f"  err: {err[:500]}"
            )
        return out

    def __call__(self, cmd: str, check: bool = True, timeout: int = 60) -> str:
        """Run cmd with sudo, supplying password via stdin."""
        # Wrap in sh -c so shell builtins and pipes work as expected
        full = (
            f"echo {self.sudo_password!r} | "
            f"sudo -S -p '' sh -c {cmd!r}"
        )
        return self.run(full, check=check, timeout=timeout)

    def script(self, interpreter: str, code: str, timeout: int = 30) -> str:
        """
        Feed `code` to `interpreter` over stdin — no quoting headaches.
        E.g. session.script("python3", "import os; print(os.uname())")
        """
        channel = self._client.get_transport().open_session()
        channel.settimeout(timeout)
        channel.exec_command(interpreter)
        channel.sendall(code.encode())
        channel.shutdown_write()
        out = b""
        while True:
            chunk = channel.recv(65536)
            if not chunk:
                break
            out += chunk
        rc = channel.recv_exit_status()
        channel.close()
        result = out.decode().strip()
        return result

    def sftp_put(self, local: pathlib.Path | str, remote: str) -> None:
        sftp = self._client.open_sftp()
        try:
            sftp.put(str(local), remote)
        finally:
            sftp.close()

    def close(self) -> None:
        self._client.close()


# ── Session-scoped connection info ────────────────────────────────────────────

@pytest.fixture(scope="session")
def opnsense_info():
    host = os.environ.get("OPNSENSE_HOST")
    if not host:
        pytest.skip("OPNSENSE_HOST not set — skipping integration tests")
    return {
        "host":       host,
        "user":       os.environ.get("OPNSENSE_SSH_USER",    "dev"),
        "password":   os.environ.get("OPNSENSE_SSH_PASS",    "dev"),
        "api_key":    os.environ.get("OPNSENSE_API_KEY",     ""),
        "api_secret": os.environ.get("OPNSENSE_API_SECRET",  ""),
        "plugin_dir": os.environ.get("PLUGIN_DIR", PLUGIN_DIR_DEFAULT),
    }


# backwards-compat alias so older tests that request `box` still work
@pytest.fixture(scope="session")
def box(opnsense_info):
    return opnsense_info


@pytest.fixture(scope="session")
def dhcpclient_info():
    host = os.environ.get("DHCPCLIENT_HOST")
    if not host:
        pytest.skip("DHCPCLIENT_HOST not set — skipping DHCP client tests")
    return {
        "host":     host,
        "user":     os.environ.get("DHCPCLIENT_SSH_USER", "dev"),
        "password": os.environ.get("DHCPCLIENT_SSH_PASS", "dev"),
        "lan_if":   os.environ.get("DHCPCLIENT_LAN_IF",  "ens19"),
    }


# ── SSH fixtures ──────────────────────────────────────────────────────────────

@pytest.fixture(scope="session")
def ssh(opnsense_info) -> SSHSession:
    """Authenticated SSH session to dev-opnsense (password, sudo included)."""
    s = SSHSession(
        opnsense_info["host"],
        opnsense_info["user"],
        opnsense_info["password"],
    )
    yield s
    s.close()


@pytest.fixture(scope="session")
def dhcpclient(dhcpclient_info) -> SSHSession:
    """Authenticated SSH session to dev-dhcpclient (password, sudo included)."""
    s = SSHSession(
        dhcpclient_info["host"],
        dhcpclient_info["user"],
        dhcpclient_info["password"],
    )
    yield s
    s.close()


# ── OPNsense REST API client ──────────────────────────────────────────────────

@pytest.fixture(scope="session")
def api(opnsense_info):
    """requests.Session pre-configured for the OPNsense plugin API."""
    if not opnsense_info["api_key"]:
        pytest.skip("OPNSENSE_API_KEY not set — skipping API tests")

    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    session = requests.Session()
    session.auth = HTTPDigestAuth(opnsense_info["api_key"],
                                  opnsense_info["api_secret"])
    session.verify = False
    session.headers.update({"Content-Type": "application/json"})
    _base = f"https://{opnsense_info['host']}/api/keaunbound"

    def get(path: str, **kw) -> dict:
        r = session.get(f"{_base}/{path.lstrip('/')}", **kw)
        r.raise_for_status()
        return r.json()

    def post(path: str, data: dict | None = None, **kw) -> dict:
        r = session.post(f"{_base}/{path.lstrip('/')}",
                         json=data or {}, **kw)
        r.raise_for_status()
        return r.json()

    session.api_get  = get
    session.api_post = post
    return session


# ── Kea control-socket helper ─────────────────────────────────────────────────

@pytest.fixture(scope="session")
def kea(ssh: SSHSession):
    """
    Send a Kea command to the daemon control socket; return the parsed response.

    Uses session.script() to feed a Python script over stdin — no shell quoting.
    Raises pytest.skip if the socket is missing (daemon not running).
    """
    _SOCKETS = {
        "dhcp4": "/var/run/kea/kea4-ctrl-socket",
        "dhcp6": "/var/run/kea/kea6-ctrl-socket",
    }

    def query(command: str, service: str = "dhcp4",
              arguments: dict | None = None) -> dict:
        sock = _SOCKETS.get(service, "/var/run/kea/kea4-ctrl-socket")
        payload = json.dumps({"command": command,
                              "arguments": arguments or {}})
        code = f"""
import socket, json, sys, os
path = {sock!r}
if not os.path.exists(path):
    print(json.dumps({{"result": 99, "text": "socket not found: " + path}}))
    sys.exit(0)
s = socket.socket(socket.AF_UNIX)
s.settimeout(10)
s.connect(path)
s.sendall({(payload + "\\n").encode()!r})
parts = []
while True:
    try:
        chunk = s.recv(65536)
        if not chunk:
            break
        parts.append(chunk)
    except socket.timeout:
        break
print(b"".join(parts).decode().strip())
"""
        raw = ssh.script("python3", code)
        try:
            resp = json.loads(raw)
        except json.JSONDecodeError as e:
            raise RuntimeError(f"Kea socket returned non-JSON: {raw!r}") from e
        if isinstance(resp, list):
            resp = resp[0]
        if resp.get("result") == 99:
            pytest.skip(f"Kea socket unavailable: {resp.get('text')}")
        return resp

    return query


# ── Unbound helper ────────────────────────────────────────────────────────────

@pytest.fixture(scope="session")
def unbound(ssh: SSHSession):
    """Helpers for querying and mutating Unbound's local_data store."""
    UC = "/usr/local/sbin/unbound-control -c /var/unbound/unbound.conf"

    def list_local_data() -> dict[str, list[str]]:
        raw = ssh(f"{UC} list_local_data", check=False)
        data: dict[str, list[str]] = {}
        for line in raw.splitlines():
            parts = line.split()
            if len(parts) >= 5 and parts[3] in ("A", "AAAA", "PTR"):
                name = parts[0].rstrip(".")
                data.setdefault(name, []).append(line)
        return data

    def has_record(hostname: str, ip: str, rdtype: str = "A") -> bool:
        for line in list_local_data().get(hostname, []):
            if ip in line and rdtype in line:
                return True
        return False

    def has_ptr(ip: str, hostname: str) -> bool:
        import ipaddress
        try:
            ptr_name = str(ipaddress.ip_address(ip).reverse_pointer)
        except ValueError:
            return False
        return any(hostname.rstrip(".") in l
                   for l in list_local_data().get(ptr_name, []))

    def add_record(record_str: str) -> None:
        ssh(f"{UC} local_data {record_str!r}")

    def remove_record(name: str) -> None:
        ssh(f"{UC} local_data_remove {name}", check=False)

    return type("UnboundHelper", (), {
        "list_local_data": staticmethod(list_local_data),
        "has_record":      staticmethod(has_record),
        "has_ptr":         staticmethod(has_ptr),
        "add_record":      staticmethod(add_record),
        "remove_record":   staticmethod(remove_record),
    })()


# ── Test state / run-log attachment ──────────────────────────────────────────

@pytest.fixture
def test_log(request):
    """Attach injected/observed/cleaned metadata for the JSON run log."""
    log: dict[str, Any] = {}

    def record(key: str, value: Any):
        log[key] = value

    yield record

    request.node._injected = log.get("injected")
    request.node._observed = log.get("observed")
    request.node._cleaned  = log.get("cleaned")


# ── Test IP / hostname allocator ──────────────────────────────────────────────

@pytest.fixture
def test_host():
    """Allocate a unique (hostname, ip) pair for one test."""
    global _ip_counter, _host_counter
    _host_counter += 1
    _ip_counter += 1
    if _ip_counter > 254:
        pytest.fail("Test IP pool exhausted — too many concurrent tests")
    hostname = f"{TEST_HOST_PREFIX}{_host_counter:03d}.lan"
    ip = f"{TEST_IP_PREFIX}{_ip_counter}"
    return {"hostname": hostname, "ip": ip}


# ── dhcp4 subnet-ID discovery ─────────────────────────────────────────────────

@pytest.fixture(scope="session")
def dhcp4_subnet_id(kea):
    resp = kea("config-get", service="dhcp4")
    subnets = resp.get("arguments", {}).get("Dhcp4", {}).get("subnet4", [])
    if not subnets:
        pytest.skip("No DHCPv4 subnets configured on dev-opnsense")
    return subnets[0]["id"]


# ── Deploy fixture ────────────────────────────────────────────────────────────

@pytest.fixture(scope="session")
def deploy(ssh: SSHSession, opnsense_info):
    """
    Upload the working tree to dev-opnsense and run `make upgrade`.

    Steps:
      1. Build a clean tarball of src/ locally (COPYFILE_DISABLE=1, no xattrs).
      2. Upload via SFTP to /tmp/keaunbound-src.tar.gz on dev-opnsense.
      3. Extract into the plugin build tree src/ directory.
      4. Run `make upgrade` (rebuilds .pkg and upgrades the installed package).
    """
    import subprocess

    plugin_dir = opnsense_info["plugin_dir"]

    with tempfile.NamedTemporaryFile(suffix=".tar.gz", delete=False) as f:
        tarball = pathlib.Path(f.name)

    try:
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

        ssh.sftp_put(tarball, "/tmp/keaunbound-src.tar.gz")

        # Extract into the build-tree src/ (replaces source files only)
        ssh(
            f"tar --no-xattrs --no-acls --no-fflags "
            f"-xzf /tmp/keaunbound-src.tar.gz "
            f"-C {plugin_dir}/src",
            timeout=30,
        )

        # Rebuild and upgrade the installed package
        ssh(f"cd {plugin_dir} && make upgrade", timeout=120)

    finally:
        tarball.unlink(missing_ok=True)
