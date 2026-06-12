# SPDX-License-Identifier: BSD-2-Clause
"""
Unbound local_data helpers over SSH.

Wraps `unbound-control -c /var/unbound/unbound.conf` commands.
"""
from __future__ import annotations

from tools.lib.ssh import SSHSession

UNBOUND_CTL = "/usr/local/sbin/unbound-control -c /var/unbound/unbound.conf"


class UnboundClient:

    def __init__(self, ssh: SSHSession):
        self._ssh = ssh

    def _ctl(self, args: str, timeout: int = 15) -> str:
        return self._ssh.sudo(f"{UNBOUND_CTL} {args}", timeout=timeout)

    # ------------------------------------------------------------------
    # Query
    # ------------------------------------------------------------------

    def list_local_data(self) -> dict[str, list[str]]:
        """Return {name: [raw_rdata_lines]} for all local_data entries."""
        raw = self._ctl("list_local_data", timeout=20)
        result: dict[str, list[str]] = {}
        for line in raw.splitlines():
            line = line.strip()
            if not line:
                continue
            parts = line.split(None, 4)
            if len(parts) < 5:
                continue
            name = parts[0].rstrip(".")
            result.setdefault(name, []).append(line)
        return result

    def has_record(self, hostname: str, ip: str, rdtype: str = "A") -> bool:
        data = self.list_local_data()
        target = hostname.rstrip(".")
        for name, lines in data.items():
            if name.rstrip(".") != target:
                continue
            for line in lines:
                if rdtype.upper() in line.upper() and ip in line:
                    return True
        return False

    def has_ptr(self, ip: str, hostname: str) -> bool:
        """Check whether an in-addr.arpa PTR record points to hostname."""
        arpa = _ip_to_arpa(ip)
        if not arpa:
            return False
        data = self.list_local_data()
        for name, lines in data.items():
            if name.rstrip(".") != arpa.rstrip("."):
                continue
            for line in lines:
                if hostname.rstrip(".") in line:
                    return True
        return False

    def local_data_count(self) -> int:
        data = self.list_local_data()
        return sum(len(v) for v in data.values())

    # ------------------------------------------------------------------
    # Mutation (for chaos injection)
    # ------------------------------------------------------------------

    def add_record(self, record_str: str) -> None:
        """Add a raw local_data record, e.g. 'foo.lan. 300 IN A 1.2.3.4'."""
        self._ctl(f"local_data {record_str!r}")

    def remove_record(self, name: str) -> None:
        """Remove all local_data for a name (forward or reverse)."""
        self._ctl(f"local_data_remove {name!r}", timeout=10)

    # ------------------------------------------------------------------
    # Status
    # ------------------------------------------------------------------

    def status(self) -> str:
        return self._ctl("status", timeout=10)

    def is_running(self) -> bool:
        try:
            out = self.status()
            return "is running" in out or "uptime" in out
        except Exception:
            return False


def _ip_to_arpa(ip: str) -> str | None:
    """Convert an IPv4 address to its in-addr.arpa name."""
    parts = ip.split(".")
    if len(parts) != 4:
        return None
    return ".".join(reversed(parts)) + ".in-addr.arpa"
