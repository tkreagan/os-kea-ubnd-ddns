# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Thomas Reagan
"""
Integration test conftest — password-based SSH via paramiko.

Requires two machines reachable from the test runner:
  - An OPNsense box with the plugin installed and a Kea DHCPv4 subnet
  - A DHCP client box that holds a lease from the OPNsense box

All connection details come from tests/.env (copy .env.example and fill in).
No hostnames, IPs, usernames, or passwords are hardcoded here.

Environment variables (all required unless noted):
  OPNSENSE_HOST        hostname / IP of the OPNsense box
  OPNSENSE_SSH_USER    SSH user
  OPNSENSE_SSH_PASS    SSH + sudo password
  OPNSENSE_API_KEY     OPNsense API key ID    (optional — API tests skip if absent)
  OPNSENSE_API_SECRET  OPNsense API key secret (optional)
  DHCPCLIENT_HOST      hostname / IP of the DHCP client box
  DHCPCLIENT_SSH_USER  SSH user on the client
  DHCPCLIENT_SSH_PASS  SSH + sudo password on the client
  DHCPCLIENT_LAN_IF    Network interface that holds the DHCP lease
  DHCPCLIENT_HOSTNAME  Short hostname sent in DHCP requests (no domain)
  PLUGIN_DIR           Plugin build tree on the OPNsense box
                       (default: /usr/plugins/net/kea-ubnd-ddns)
  TEST_IP_PREFIX       IP prefix for injected test data, e.g. "192.168.1."
                       (default: "192.168.99." — safe for any network)
  TEST_IP_START        First octet of test range, e.g. 201
                       (default: 200)
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

# Test-data allocation — read from .env / environment so no topology is
# hardcoded in source.  Defaults are safe for any network (192.168.99.x
# is accepted by lease4-add even when out of the configured DHCP pool).
TEST_HOST_PREFIX = "testhost-"

PLUGIN_DIR_DEFAULT = "/usr/plugins/net/kea-ubnd-ddns"


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

# Resolve test IP range after env is loaded.
TEST_IP_PREFIX = os.environ.get("TEST_IP_PREFIX", "192.168.99.")
try:
    TEST_IP_START = int(os.environ.get("TEST_IP_START", "200"))
except ValueError:
    TEST_IP_START = 200

_ip_counter   = TEST_IP_START
_host_counter = 0


def _require_env(name: str, skip_msg: str | None = None) -> str:
    """Return env var value, or pytest.skip if missing/empty."""
    val = os.environ.get(name, "").strip()
    if not val:
        pytest.skip(skip_msg or f"{name} not set — skipping integration tests")
    return val


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
        import shlex
        # Wrap in sh -c so shell builtins and pipes work as expected.
        # Use shlex.quote() for shell-safe quoting — Python repr() escaping
        # does not translate to shell syntax when the string contains single quotes.
        full = (
            f"echo {shlex.quote(self.sudo_password)} | "
            f"sudo -S -p '' sh -c {shlex.quote(cmd)}"
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

    def sudo_script(self, interpreter: str, code: str, timeout: int = 30) -> str:
        """
        Like script() but runs the interpreter with sudo via a temporary file.

        Uploads code to a remote temp file over SFTP, then invokes it through
        the sudo-aware __call__ path.  Use when the script needs to write
        privileged files (e.g. /conf/config.xml).
        """
        import tempfile, pathlib as _pathlib
        remote = f"/tmp/_sudo_script_{id(self)}.py"
        with tempfile.NamedTemporaryFile(suffix=".py", mode="w", delete=False) as f:
            f.write(code)
            local = _pathlib.Path(f.name)
        try:
            self.sftp_put(local, remote)
            return self(f"{interpreter} {remote}; rm -f {remote}", timeout=timeout)
        finally:
            local.unlink(missing_ok=True)

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
    user = _require_env("OPNSENSE_SSH_USER")
    return {
        "host":       _require_env("OPNSENSE_HOST"),
        "user":       user,
        "ssh_user":   user,   # alias used by some tests
        "password":   _require_env("OPNSENSE_SSH_PASS"),
        "api_key":    os.environ.get("OPNSENSE_API_KEY",    ""),
        "api_secret": os.environ.get("OPNSENSE_API_SECRET", ""),
        "plugin_dir": os.environ.get("PLUGIN_DIR", PLUGIN_DIR_DEFAULT),
    }


# backwards-compat alias so older tests that request `box` still work
@pytest.fixture(scope="session")
def box(opnsense_info):
    return opnsense_info


@pytest.fixture(scope="session")
def dhcpclient_info():
    return {
        "host":     _require_env("DHCPCLIENT_HOST",
                                  "DHCPCLIENT_HOST not set — skipping DHCP client tests"),
        "user":     _require_env("DHCPCLIENT_SSH_USER"),
        "password": _require_env("DHCPCLIENT_SSH_PASS"),
        "lan_if":   _require_env("DHCPCLIENT_LAN_IF"),
        "hostname": _require_env("DHCPCLIENT_HOSTNAME"),
    }


# ── SSH fixtures ──────────────────────────────────────────────────────────────

@pytest.fixture(scope="session")
def ssh(opnsense_info) -> SSHSession:
    """Authenticated SSH session to the OPNsense box (password, sudo included)."""
    s = SSHSession(
        opnsense_info["host"],
        opnsense_info["user"],
        opnsense_info["password"],
    )
    yield s
    s.close()


@pytest.fixture(scope="session")
def dhcpclient(dhcpclient_info) -> SSHSession:
    """Authenticated SSH session to the DHCP client box (password, sudo included)."""
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
    key = opnsense_info["api_key"]
    if not key or key.startswith("<"):
        pytest.skip("OPNSENSE_API_KEY not configured — skipping API tests")

    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    session = requests.Session()
    session.auth = HTTPDigestAuth(opnsense_info["api_key"],
                                  opnsense_info["api_secret"])
    session.verify = False
    session.headers.update({"Content-Type": "application/json"})
    _base = f"https://{opnsense_info['host']}/api/keaubnd"

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

    def _raw_query(command: str, arguments: dict, sock: str) -> dict:
        payload = json.dumps({"command": command, "arguments": arguments})
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

    def _config_set_reservation(
        action: str, arguments: dict, sock: str
    ) -> dict:
        """Add/remove reservations via config-set (Kea 3.x has no hosts-database by default)."""
        code = f"""
import socket, json, sys, os

def kea_raw(cmd, args, path):
    payload = json.dumps({{"command": cmd, "arguments": args}}) + "\\n"
    s = socket.socket(socket.AF_UNIX)
    s.settimeout(10)
    s.connect(path)
    s.sendall(payload.encode())
    parts = []
    while True:
        try:
            chunk = s.recv(65536)
            if not chunk: break
            parts.append(chunk)
        except socket.timeout:
            break
    resp = json.loads(b"".join(parts).decode())
    return resp[0] if isinstance(resp, list) else resp

path = {sock!r}
action = {action!r}
arguments = {json.dumps(arguments)!r}
arguments = json.loads(arguments)

conf_resp = kea_raw("config-get", {{}}, path)
conf = conf_resp.get("arguments", {{}})
conf.pop("hash", None)

dhcp4 = conf.get("Dhcp4", {{}})
subnets = dhcp4.get("subnet4", []) or dhcp4.get("subnet6", [])

if action == "add":
    resv = arguments.get("reservation", {{}})
    subnet_id = resv.get("subnet-id") or arguments.get("subnet-id")
    target = next((s for s in subnets if not subnet_id or s.get("id") == subnet_id), subnets[0] if subnets else None)
    if target is None:
        print(json.dumps({{"result": 1, "text": "no subnet found"}}))
        sys.exit(0)
    resv_clean = {{k: v for k, v in resv.items() if k != "subnet-id"}}
    resv_ip = resv_clean.get("ip-address")
    existing = target.get("reservations", [])
    target["reservations"] = [r for r in existing if r.get("ip-address") != resv_ip]
    target["reservations"].append(resv_clean)
elif action == "del":
    subnet_id = arguments.get("subnet-id")
    ip = arguments.get("ip-address")
    target = next((s for s in subnets if not subnet_id or s.get("id") == subnet_id), subnets[0] if subnets else None)
    if target is not None:
        target["reservations"] = [r for r in target.get("reservations", []) if r.get("ip-address") != ip]

result = kea_raw("config-set", conf, path)
print(json.dumps(result))
"""
        raw = ssh.script("python3", code)
        try:
            resp = json.loads(raw)
        except json.JSONDecodeError as e:
            raise RuntimeError(f"Kea config-set returned non-JSON: {raw!r}") from e
        if isinstance(resp, list):
            resp = resp[0]
        return resp

    def query(command: str, service: str = "dhcp4",
              arguments: dict | None = None) -> dict:
        sock = _SOCKETS.get(service, "/var/run/kea/kea4-ctrl-socket")
        args = arguments or {}
        # Kea 3.x removed subnet4-reservation-add/del in favour of config-set
        # (reservation-add/del require a hosts-database backend that isn't configured
        # in this test environment). Intercept and implement via config-set.
        if command in ("subnet4-reservation-add", "reservation-add"):
            return _config_set_reservation("add", args, sock)
        if command in ("subnet4-reservation-del", "reservation-del"):
            return _config_set_reservation("del", args, sock)
        return _raw_query(command, args, sock)

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
        ssh(f"{UC} local_data {record_str}")

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


# ── System domain discovery ───────────────────────────────────────────────────

@pytest.fixture(scope="session")
def system_domain(ssh: SSHSession) -> str:
    """Read the fallback-system-domain from the daemon runtime config."""
    try:
        raw = ssh(
            "python3 -c \""
            "import json; "
            "print(json.load(open('/var/run/keaubnd/keaubnd.json'))"
            ".get('fallback-system-domain', 'lan'))"
            "\"",
            check=False,
        ).strip()
        return raw if raw else "lan"
    except Exception:
        return "lan"


# ── Test IP / hostname allocator ──────────────────────────────────────────────

@pytest.fixture
def test_host(system_domain: str):
    """Allocate a unique (hostname, label, ip) pair for one test.

    'hostname' is the FQDN that kea-sync.py will register in Unbound
    (label + system domain). 'label' is the bare hostname without domain,
    as stored in Kea reservations.
    """
    global _ip_counter, _host_counter
    _host_counter += 1
    _ip_counter += 1
    if _ip_counter > 254:
        pytest.fail("Test IP pool exhausted — too many concurrent tests")
    label = f"{TEST_HOST_PREFIX}{_host_counter:03d}"
    hostname = f"{label}.{system_domain}"
    ip = f"{TEST_IP_PREFIX}{_ip_counter}"
    return {"hostname": hostname, "label": label, "ip": ip}


# ── dhcp4 subnet-ID discovery ─────────────────────────────────────────────────

@pytest.fixture(scope="session")
def dhcp4_subnet_id(kea):
    resp = kea("config-get", service="dhcp4")
    subnets = resp.get("arguments", {}).get("Dhcp4", {}).get("subnet4", [])
    if not subnets:
        pytest.skip("No DHCPv4 subnets configured on the OPNsense box")
    return subnets[0]["id"]


# ── Environment configuration ─────────────────────────────────────────────────

@pytest.fixture(scope="session", autouse=True)
def chaos_env_configured():
    """
    Run configure-chaos-env.sh --opnsense-only before any test runs.

    This configures Kea (lease database, DDNS wiring, D2 forwarding to port 53535)
    and is idempotent — safe to run on every session. Uses tools/.env for SSH key.
    Skips gracefully if the script or tools/.env is absent.
    """
    import subprocess
    script = REPO / "tools" / "setup" / "configure-chaos-env.sh"
    env_file = REPO / "tools" / ".env"
    if not script.exists():
        pytest.skip("configure-chaos-env.sh not found — skipping environment setup")
        return
    if not env_file.exists():
        pytest.skip("tools/.env not found — cannot configure environment")
        return
    result = subprocess.run(
        ["bash", str(script), "--opnsense-only"],
        cwd=str(REPO),
        capture_output=True,
        text=True,
        timeout=300,
    )
    if result.returncode != 0:
        pytest.fail(
            f"configure-chaos-env.sh failed (rc={result.returncode}):\n"
            f"stdout: {result.stdout[-1000:]}\n"
            f"stderr: {result.stderr[-500:]}"
        )


# ── Deploy fixture ────────────────────────────────────────────────────────────

@pytest.fixture(scope="session")
def deploy(ssh: SSHSession, opnsense_info):
    """
    Upload the working tree to the OPNsense box and install it.

    Two strategies (auto-detected by checking for the Mk build infrastructure):
      make upgrade  — when /usr/plugins/Mk/plugins.mk exists on the OPNsense box.
      direct copy   — fallback: extract src/ directly into /usr/local/, restart configd.

    Steps:
      1. Build a clean tarball of src/ locally (COPYFILE_DISABLE=1, no xattrs).
      2. Upload via SFTP to /tmp/keaubnd-src.tar.gz on the OPNsense box.
      3a. If build tree: extract into plugin_dir/src and run `make upgrade`.
      3b. If no build tree: extract directly into /usr/local/, fix perms, restart configd.
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

        ssh.sftp_put(tarball, "/tmp/keaubnd-src.tar.gz")

        # Detect install strategy
        has_mk = ssh(
            f"test -f /usr/plugins/Mk/plugins.mk && echo yes || echo no",
            check=False,
        ).strip()

        if has_mk == "yes":
            # make upgrade path: create build tree if missing, then make upgrade
            ssh(f"mkdir -p {plugin_dir}/src", check=False)
            ssh(
                f"tar --no-xattrs --no-acls --no-fflags "
                f"-xzf /tmp/keaubnd-src.tar.gz "
                f"-C {plugin_dir}/src",
                timeout=30,
            )
            ssh(f"cd {plugin_dir} && make upgrade", timeout=120)
        else:
            # Direct copy path (no Mk infrastructure)
            ssh(
                "tar --no-xattrs --no-acls --no-fflags "
                "-xzf /tmp/keaubnd-src.tar.gz -C /usr/local/",
                timeout=30,
            )
            ssh("chmod 755 /usr/local/sbin/kea-ubnd-ddns.py", check=False)
            ssh(
                "find /usr/local/opnsense/scripts/keaubnd -name '*.py' "
                "-exec chmod 755 {} \\;",
                check=False,
            )
            ssh("service configd restart", check=False)

        ssh("rm -f /tmp/keaubnd-src.tar.gz", check=False)

    finally:
        tarball.unlink(missing_ok=True)


# ── DHCPv6 subnet-ID discovery ────────────────────────────────────────────────

@pytest.fixture(scope="session")
def kea6(kea):
    """
    Thin wrapper over the `kea` fixture for DHCPv6 operations.
    Skips if kea-dhcp6 socket is not present (daemon not running).
    """
    # Probe kea-dhcp6 availability immediately
    kea("config-get", service="dhcp6")
    # Return the same callable, but callers know the service is available
    return kea


@pytest.fixture(scope="session")
def dhcp6_subnet_id(kea6):
    resp = kea6("config-get", service="dhcp6")
    subnets = resp.get("arguments", {}).get("Dhcp6", {}).get("subnet6", [])
    if not subnets:
        pytest.skip("No DHCPv6 subnets configured on the OPNsense box")
    return subnets[0]["id"]


# ── Unique IPv6 test-address allocator ───────────────────────────────────────
# Allocates addresses in a configurable ULA range so v6 tests have unique IPs
# without conflicting with the DHCPv6 lease pool.
_v6_prefix = os.environ.get("TEST_IPV6_PREFIX", "fd00:db8:cafe::")
_v6_counter = 0


@pytest.fixture
def test_host_v6(system_domain: str):
    """Allocate a unique (hostname, label, v6_ip) pair for one test."""
    global _v6_counter, _host_counter
    _v6_counter += 1
    _host_counter += 1
    label = f"{TEST_HOST_PREFIX}v6-{_host_counter:03d}"
    hostname = f"{label}.{system_domain}"
    ip = f"{_v6_prefix}{_v6_counter}"
    return {"hostname": hostname, "label": label, "ip": ip}


# ── v6 lease release helper ───────────────────────────────────────────────────

@pytest.fixture(scope="session")
def v6_lease_release(kea6):
    """
    Release a DHCPv6 lease by its address, using the kea-dhcp6 control socket.
    Returns True if the delete succeeded; False if the lease was not found.
    """
    def _release(ip: str) -> bool:
        resp = kea6("lease6-del",
                    service="dhcp6",
                    arguments={"ip-address": ip, "type": "IA_NA"})
        return resp.get("result", -1) == 0

    return _release
