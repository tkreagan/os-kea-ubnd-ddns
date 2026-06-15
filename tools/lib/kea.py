# SPDX-License-Identifier: BSD-2-Clause
"""
Kea DHCP API client over SSH.

Injects Python one-liners that speak directly to kea's Unix control socket,
reusing the same socket path resolution that the plugin scripts use.
"""
from __future__ import annotations

import json
import textwrap
from typing import Any

from tools.lib.ssh import SSHSession


class KeaError(Exception):
    pass


# Socket paths — must match the plugin's fallback defaults
_SOCKETS = {
    "dhcp4": "/var/run/kea/kea4-ctrl-socket",
    "dhcp6": "/var/run/kea/kea6-ctrl-socket",
}

_QUERY_SCRIPT = textwrap.dedent("""\
    import socket, json, sys
    cmd = json.loads(sys.argv[1])
    sock_path = sys.argv[2]
    payload = json.dumps(cmd).encode()
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        s.connect(sock_path)
        s.sendall(payload)
        buf = b""
        while True:
            chunk = s.recv(65536)
            if not chunk:
                break
            buf += chunk
    print(buf.decode())
""")


class KeaClient:
    """
    Thin wrapper that queries Kea daemon APIs via remote Python script.

    All methods return the parsed JSON response dict (or raise KeaError).
    """

    def __init__(self, ssh: SSHSession):
        self._ssh = ssh

    def query(self, command: str, service: str = "dhcp4",
              arguments: dict | None = None, timeout: int = 10) -> Any:
        payload: dict = {"command": command, "service": [service]}
        if arguments is not None:
            payload["arguments"] = arguments

        sock = _SOCKETS.get(service, _SOCKETS["dhcp4"])
        code = textwrap.dedent(f"""\
            import socket, json
            payload = {json.dumps(payload)!r}.encode()
            sock_path = {sock!r}
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
                s.settimeout({timeout})
                s.connect(sock_path)
                s.sendall(payload)
                buf = b""
                while True:
                    chunk = s.recv(65536)
                    if not chunk:
                        break
                    buf += chunk
            print(buf.decode())
        """)
        try:
            # dev user is in wheel group and can reach the Kea unix socket
            # directly — sudo is not needed and would break stdin delivery
            # (echo|sudo pipeline consumes stdin before python3 can read it).
            raw = self._ssh.script("python3", code, timeout=timeout + 5)
        except RuntimeError as exc:
            raise KeaError(f"SSH/script error: {exc}") from exc

        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise KeaError(f"Bad JSON from Kea: {raw[:200]}") from exc

        # Kea wraps responses in a list when using service= routing
        if isinstance(parsed, list):
            if not parsed:
                raise KeaError("Empty response list from Kea")
            parsed = parsed[0]

        result_code = parsed.get("result", -1)
        if result_code not in (0, 3):  # 0=success, 3=empty (no leases)
            text = parsed.get("text", "")
            raise KeaError(f"Kea returned result={result_code}: {text}")

        return parsed.get("arguments", parsed)

    # ------------------------------------------------------------------
    # Lease operations
    # ------------------------------------------------------------------

    def lease4_add(self, ip: str, hw_addr: str, hostname: str,
                   valid_lft: int = 7200, subnet_id: int | None = None) -> dict:
        args: dict[str, Any] = {
            "ip-address": ip,
            "hw-address": hw_addr,
            "hostname": hostname,
            "valid-lft": valid_lft,
        }
        if subnet_id is not None:
            args["subnet-id"] = subnet_id
        return self.query("lease4-add", arguments=args)

    def lease4_del(self, ip: str) -> dict:
        return self.query("lease4-del", arguments={"ip-address": ip})

    def lease4_get(self, ip: str) -> dict | None:
        try:
            return self.query("lease4-get", arguments={"ip-address": ip,
                                                        "identifier-type": "address"})
        except KeaError as exc:
            if "not found" in str(exc).lower():
                return None
            raise

    def lease4_get_all(self) -> list[dict]:
        try:
            result = self.query("lease4-get-all", service="dhcp4")
        except KeaError as exc:
            if "empty" in str(exc).lower() or "result=3" in str(exc).lower():
                return []
            raise
        if isinstance(result, dict):
            return result.get("leases", [])
        return result if isinstance(result, list) else []

    def lease4_wipe(self, subnet_id: int | None = None) -> dict:
        """Remove ALL leases from all subnets (or a specific one)."""
        if subnet_id is not None:
            return self.query("lease4-wipe", arguments={"subnet-id": subnet_id})
        return self.query("lease4-wipe", arguments={})

    # ------------------------------------------------------------------
    # DHCPv6 lease operations
    # ------------------------------------------------------------------

    def lease6_add(self, ip: str, duid: str, hostname: str,
                   valid_lft: int = 7200, subnet_id: int | None = None,
                   lease_type: int = 0) -> dict:
        """Add a DHCPv6 IA_NA lease (lease_type=0). Use for test injection."""
        args: dict[str, Any] = {
            "ip-address": ip,
            "duid": duid,
            "iaid": 1,
            "hostname": hostname,
            "valid-lft": valid_lft,
            "type": "IA_NA",
        }
        if subnet_id is not None:
            args["subnet-id"] = subnet_id
        return self.query("lease6-add", service="dhcp6", arguments=args)

    def lease6_del(self, ip: str) -> dict:
        return self.query("lease6-del", service="dhcp6",
                          arguments={"ip-address": ip, "type": "IA_NA"})

    def lease6_get(self, ip: str) -> dict | None:
        try:
            return self.query("lease6-get", service="dhcp6",
                              arguments={"ip-address": ip,
                                         "identifier-type": "address"})
        except KeaError as exc:
            if "not found" in str(exc).lower():
                return None
            raise

    def lease6_get_all(self) -> list[dict]:
        try:
            result = self.query("lease6-get-all", service="dhcp6")
        except KeaError as exc:
            if "empty" in str(exc).lower() or "result=3" in str(exc).lower():
                return []
            raise
        if isinstance(result, dict):
            return result.get("leases", [])
        return result if isinstance(result, list) else []

    def lease6_wipe(self, subnet_id: int | None = None) -> dict:
        if subnet_id is not None:
            return self.query("lease6-wipe", service="dhcp6",
                              arguments={"subnet-id": subnet_id})
        return self.query("lease6-wipe", service="dhcp6", arguments={})

    # ------------------------------------------------------------------
    # Reservation operations
    # ------------------------------------------------------------------

    def has_host_database(self, service: str = "dhcp4") -> bool:
        """Return True if Kea has a hosts database backend available."""
        try:
            self.query("reservation-add", service=service, arguments={
                "reservation": {
                    "subnet-id": 0,
                    "ip-address": "0.0.0.1",
                    "hw-address": "00:00:00:00:00:01",
                    "hostname": "_probe_",
                }
            })
            # If it somehow succeeded, clean it up best-effort
            try:
                self.query("reservation-del", service=service, arguments={
                    "subnet-id": 0, "ip-address": "0.0.0.1",
                    "identifier-type": "address", "identifier": "0.0.0.1",
                })
            except KeaError:
                pass
            return True
        except KeaError as e:
            return "Host database not available" not in str(e)

    def reservation_add(self, subnet_id: int, ip: str,
                        hw_addr: str, hostname: str,
                        service: str = "dhcp4") -> None:
        """Add a host reservation via config-set (works without a hosts DB backend)."""
        svc_key = "Dhcp4" if service == "dhcp4" else "Dhcp6"
        subnet_key = "subnet4" if service == "dhcp4" else "subnet6"
        cfg = self.config_get(service)[svc_key]
        for subnet in cfg.get(subnet_key, []):
            if subnet.get("id") == subnet_id:
                reservations = subnet.setdefault("reservations", [])
                reservations[:] = [r for r in reservations
                                   if r.get("ip-address") != ip]
                entry: dict = {"ip-address": ip, "hostname": hostname}
                if service == "dhcp4":
                    entry["hw-address"] = hw_addr
                else:
                    entry["duid"] = hw_addr
                reservations.append(entry)
                break
        self.query("config-set", service=service, arguments={svc_key: cfg})

    def reservation_del(self, subnet_id: int, ip: str,
                        service: str = "dhcp4") -> None:
        """Remove a host reservation via config-set."""
        svc_key = "Dhcp4" if service == "dhcp4" else "Dhcp6"
        subnet_key = "subnet4" if service == "dhcp4" else "subnet6"
        cfg = self.config_get(service)[svc_key]
        for subnet in cfg.get(subnet_key, []):
            if subnet.get("id") == subnet_id:
                subnet["reservations"] = [
                    r for r in subnet.get("reservations", [])
                    if r.get("ip-address") != ip
                ]
                break
        self.query("config-set", service=service, arguments={svc_key: cfg})

    def reservation_add_v6_multi(self, subnet_id: int, duid: str,
                                hostname: str, ips: list[str]) -> None:
        """Add a DHCPv6 reservation with multiple addresses via config-set."""
        cfg = self.config_get("dhcp6")["Dhcp6"]
        for subnet in cfg.get("subnet6", []):
            if subnet.get("id") == subnet_id:
                reservations = subnet.setdefault("reservations", [])
                reservations[:] = [r for r in reservations
                                   if r.get("duid") != duid]
                reservations.append({
                    "duid": duid,
                    "hostname": hostname,
                    "ip-addresses": ips,
                })
                break
        self.query("config-set", service="dhcp6", arguments={"Dhcp6": cfg})

    def reservation_del_v6_by_duid(self, subnet_id: int, duid: str) -> None:
        """Remove a DHCPv6 reservation by DUID via config-set."""
        cfg = self.config_get("dhcp6")["Dhcp6"]
        for subnet in cfg.get("subnet6", []):
            if subnet.get("id") == subnet_id:
                subnet["reservations"] = [
                    r for r in subnet.get("reservations", [])
                    if r.get("duid") != duid
                ]
                break
        self.query("config-set", service="dhcp6", arguments={"Dhcp6": cfg})

    def reservation_get_all(self, subnet_id: int) -> list[dict]:
        try:
            result = self.query("reservation-get-all", arguments={"subnet-id": subnet_id})
        except KeaError:
            return []
        if isinstance(result, dict):
            return result.get("hosts", [])
        return []

    # ------------------------------------------------------------------
    # Config / subnet discovery
    # ------------------------------------------------------------------

    def config_get(self, service: str = "dhcp4") -> dict:
        return self.query("config-get", service=service)

    def discover_subnet_id(self, service: str = "dhcp4") -> int | None:
        """Return the subnet-id of the first configured subnet, or None."""
        try:
            cfg = self.config_get(service)
        except KeaError:
            return None
        key = "Dhcp4" if service == "dhcp4" else "Dhcp6"
        subnets = cfg.get(key, {}).get("subnet4" if service == "dhcp4" else "subnet6", [])
        if subnets:
            return subnets[0].get("id")
        return None

    def version_get(self) -> str:
        result = self.query("version-get")
        if isinstance(result, dict):
            return result.get("text", str(result))
        return str(result)
