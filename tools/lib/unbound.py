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
        """Check whether an exact-type record exists for hostname → ip.

        Uses field-level comparison so "A" does not accidentally match "AAAA"
        lines (the old substring check "A" in line would do that).
        """
        data = self.list_local_data()
        target = hostname.rstrip(".")
        rdtype_upper = rdtype.upper()
        for name, lines in data.items():
            if name.rstrip(".") != target:
                continue
            for line in lines:
                # Format: "name. TTL IN TYPE rdata"
                parts = line.split()
                if len(parts) >= 5 and parts[3] == rdtype_upper and ip in parts[4:]:
                    return True
        return False

    def has_ptr(self, ip: str, hostname: str) -> bool:
        """Check whether an in-addr.arpa / ip6.arpa PTR record points to hostname.

        Works for both IPv4 (in-addr.arpa) and IPv6 (full 32-nibble ip6.arpa).
        """
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
    """Convert an IPv4 or IPv6 address to its reverse-DNS arpa name.

    IPv4 → x.x.x.x.in-addr.arpa
    IPv6 → full 32-nibble ip6.arpa
    """
    try:
        import ipaddress
        return str(ipaddress.ip_address(ip).reverse_pointer)
    except ValueError:
        return None
