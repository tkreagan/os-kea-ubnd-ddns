# SPDX-License-Identifier: BSD-2-Clause
"""
Remote DNS verification via drill / dig run on the target host.

Queries 127.0.0.1 so we're testing Unbound's actual runtime state,
not any upstream resolver.
"""
from __future__ import annotations

import re
from tools.lib.ssh import SSHSession


class DNSVerifier:

    def __init__(self, ssh: SSHSession, resolver: str = "127.0.0.1"):
        self._ssh = ssh
        self._resolver = resolver
        self._tool: str | None = None   # lazily detected ("drill" or "dig")

    def _detect_tool(self) -> str:
        if self._tool:
            return self._tool
        try:
            self._ssh.run("command -v drill", timeout=5)
            self._tool = "drill"
        except Exception:
            try:
                self._ssh.run("command -v dig", timeout=5)
                self._tool = "dig"
            except Exception:
                self._tool = "host"
        return self._tool

    def _query(self, name: str, rdtype: str = "A") -> str:
        tool = self._detect_tool()
        if tool == "drill":
            cmd = f"drill @{self._resolver} {name} {rdtype}"
        elif tool == "dig":
            cmd = f"dig @{self._resolver} +short {name} {rdtype}"
        else:
            # host doesn't support @server in all versions; fallback
            cmd = f"host -t {rdtype} {name} {self._resolver}"
        try:
            return self._ssh.run(cmd, timeout=10)
        except Exception:
            return ""

    def forward(self, hostname: str, domain: str) -> str | None:
        """Resolve hostname.domain A → first answer IPv4, or None."""
        fqdn = f"{hostname.rstrip('.')}.{domain.rstrip('.')}."
        raw = self._query(fqdn, "A")
        return _extract_answer(raw, "A")

    def forward_aaaa(self, hostname: str, domain: str) -> str | None:
        """Resolve hostname.domain AAAA → first answer IPv6, or None."""
        fqdn = f"{hostname.rstrip('.')}.{domain.rstrip('.')}."
        raw = self._query(fqdn, "AAAA")
        return _extract_answer(raw, "AAAA")

    def reverse(self, ip: str) -> str | None:
        """Resolve PTR for ip (IPv4 or IPv6) → first answer hostname, or None."""
        arpa = _ip_to_arpa(ip)
        if not arpa:
            return None
        raw = self._query(arpa + ".", "PTR")
        return _extract_answer(raw, "PTR")

    def verify_pair(self, hostname: str, ip: str, domain: str,
                    rdtype: str = "A") -> dict:
        """
        Check both forward A/AAAA and reverse PTR resolution.

        rdtype: "A" for IPv4 forward lookup, "AAAA" for IPv6.
        Returns:
          forward_ok:      bool
          ptr_ok:          bool
          forward_answer:  str|None
          ptr_answer:      str|None
        """
        if rdtype.upper() == "AAAA":
            fwd = self.forward_aaaa(hostname, domain)
        else:
            fwd = self.forward(hostname, domain)
        ptr = self.reverse(ip)
        fqdn = f"{hostname.rstrip('.')}.{domain.rstrip('.')}"
        return {
            "forward_ok": fwd == ip,
            "ptr_ok": ptr is not None and (
                ptr.rstrip(".") == fqdn or
                ptr.rstrip(".") == hostname
            ),
            "forward_answer": fwd,
            "ptr_answer": ptr,
        }

    def verify_all(self, pairs: list[tuple[str, str]], domain: str) -> list[dict]:
        """Verify a list of (hostname, ip) pairs. Returns one dict per pair."""
        results = []
        for hostname, ip in pairs:
            r = self.verify_pair(hostname, ip, domain)
            r["hostname"] = hostname
            r["ip"] = ip
            results.append(r)
        return results


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _extract_answer(raw: str, rdtype: str) -> str | None:
    """Extract the first answer from drill/dig/host output."""
    if not raw:
        return None
    rdtype_upper = rdtype.upper()
    for line in raw.splitlines():
        line = line.strip()
        # dig +short output: just the bare value on its own line
        if rdtype_upper == "A" and re.match(r"^\d+\.\d+\.\d+\.\d+$", line):
            return line
        if rdtype_upper == "AAAA" and re.match(r"^[0-9a-fA-F:]+$", line) and ":" in line:
            return line
        if rdtype_upper == "PTR" and line.endswith(".") and "NXDOMAIN" not in line:
            return line.rstrip(".")
        # drill/host answer-section lines: "name  TTL  IN  TYPE  value"
        if rdtype_upper in line.upper() and "ANSWER SECTION" not in line:
            parts = line.split()
            if len(parts) >= 5 and parts[3].upper() == rdtype_upper:
                return parts[4].rstrip(".")
    return None


def _ip_to_arpa(ip: str) -> str | None:
    """Convert an IPv4 or IPv6 address to its reverse-DNS arpa name."""
    try:
        import ipaddress
        return str(ipaddress.ip_address(ip).reverse_pointer)
    except ValueError:
        # Fallback for bare IPv4 dotted-quad without ipaddress available
        parts = ip.split(".")
        if len(parts) == 4:
            return ".".join(reversed(parts)) + ".in-addr.arpa"
        return None
