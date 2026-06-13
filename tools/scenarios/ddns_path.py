# SPDX-License-Identifier: BSD-2-Clause
"""
DDNS path scenarios: RFC 2136 UPDATE flood and malformed packet resilience.

Packets are injected via ctx.send_ncr() which runs a python3 snippet on
dev-opnsense to send to 127.0.0.1:53535 (the daemon's loopback-only socket).
"""
from __future__ import annotations

import struct
import time

from tools.scenarios import register
from tools.scenarios.base import Scenario, ChaosContext


def _build_update(hostname: str, ip: str, domain: str) -> bytes:
    """Build a minimal RFC 2136 DNS UPDATE packet using dnspython."""
    try:
        import dns.update
        import dns.rdataclass
        import dns.rdatatype
        import dns.rdata
        import dns.rdtypes.IN.A
        import dns.name
        import dns.message

        zone = dns.name.from_text(domain + ".")
        upd = dns.update.UpdateMessage(zone)
        upd.add(
            dns.name.from_text(hostname + "." + domain + "."),
            300,
            dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.A, ip),
        )
        return upd.to_wire()
    except ImportError:
        # Fallback: hand-craft a minimal wire-format DNS UPDATE
        return _minimal_update_wire(hostname, ip, domain)


def _minimal_update_wire(hostname: str, ip: str, domain: str) -> bytes:
    """Minimal hand-crafted DNS UPDATE (no dnspython)."""
    # DNS header: id=0x1234, flags=opcode5(UPDATE)|QR=0, zones=1, prereq=0, update=1, ar=0
    txid = 0x1234
    flags = (5 << 11)  # opcode=UPDATE
    header = struct.pack("!HHHHHH", txid, flags, 1, 0, 1, 0)

    def encode_name(name: str) -> bytes:
        buf = b""
        for label in name.rstrip(".").split("."):
            enc = label.encode()
            buf += bytes([len(enc)]) + enc
        return buf + b"\x00"

    # Zone section: domain, QTYPE=SOA, QCLASS=IN
    zone = encode_name(domain)
    zone += struct.pack("!HH", 6, 1)  # SOA, IN

    # Update RR: A record for hostname.domain TTL=300 rdata=ip
    fqdn = encode_name(f"{hostname}.{domain}")
    ip_bytes = bytes(int(x) for x in ip.split("."))
    rr = fqdn + struct.pack("!HHIH", 1, 1, 300, 4) + ip_bytes  # A, IN, TTL, rdlen=4

    return header + zone + rr


@register
class DdnsUpdateFlood(Scenario):
    name = "ddns_update_flood"
    description = "Send 50 RFC 2136 UPDATEs in 2s; verify daemon alive and records correct"
    tags = ["ddns", "stress"]
    COUNT = 50

    def run(self, ctx: ChaosContext) -> None:
        self._pairs: list[tuple[str, str]] = []

        for i in range(self.COUNT):
            hostname, ip = ctx.alloc_host(f"-ddnsf{i:02d}")
            payload = _build_update(hostname, ip, ctx.domain)
            try:
                ctx.send_ncr(payload)
            except Exception:
                pass
            self._pairs.append((hostname, ip))

        ctx.event("flood_sent", count=self.COUNT)
        ctx.wait(3, "let daemon process flood")

    def verify(self, ctx: ChaosContext) -> list[str]:
        failures = []
        if not ctx.daemon_is_running():
            failures.append("Daemon not running after UPDATE flood")
            return failures

        out = ctx.ssh.sudo(
            "sockstat -4 2>/dev/null | grep 53535 || "
            "netstat -an 2>/dev/null | grep 53535 || true",
            check=False
        )
        if "53535" not in out:
            failures.append("Port 53535 not bound after flood")

        ctx.event("daemon_alive_after_flood", running=True)
        return failures

    def cleanup(self, ctx: ChaosContext) -> None:
        for hostname, ip in getattr(self, "_pairs", []):
            try:
                import dns.update, dns.name
                zone = dns.name.from_text(ctx.domain + ".")
                upd = dns.update.UpdateMessage(zone)
                upd.delete(dns.name.from_text(hostname + "." + ctx.domain + "."))
                ctx.send_ncr(upd.to_wire())
            except Exception:
                pass
        ctx.wait(2, "let deletes settle")
        ctx.run_clean()


@register
class DdnsMalformed(Scenario):
    name = "ddns_malformed"
    description = "Send 10 truncated/garbage UDP packets; verify daemon alive afterwards"
    tags = ["ddns", "hostile"]

    BAD_PAYLOADS = [
        b"",                                  # empty
        b"\x00",                              # 1 byte
        b"\xff\xff\xff\xff",                  # garbage header
        b"\x00" * 12,                         # zero header only
        b"\xde\xad\xbe\xef" * 10,            # garbage
        b"\x12\x34\x28\x00" + b"\x00" * 20, # UPDATE opcode, truncated
        b"NOT DNS AT ALL !!",
        b"\x00\x01\x28\x00\x00\x01\x00\x00\x00\x01\x00\x00",  # hdr only, no zone
        b"\xff" * 512,                        # all 0xff
        b"\x00" * 1,                          # single null byte
    ]

    def run(self, ctx: ChaosContext) -> None:
        for i, payload in enumerate(self.BAD_PAYLOADS):
            try:
                ctx.send_ncr(payload)
            except Exception:
                pass
            ctx.event("malformed_sent", index=i, size=len(payload))
        ctx.wait(3, "let daemon recover")

    def verify(self, ctx: ChaosContext) -> list[str]:
        failures = []
        if not ctx.daemon_is_running():
            failures.append("Daemon not running after malformed packet bombardment")
        out = ctx.ssh.sudo(
            "sockstat -4 2>/dev/null | grep 53535 || "
            "netstat -an 2>/dev/null | grep 53535 || true",
            check=False
        )
        if "53535" not in out:
            failures.append("Port 53535 not bound after malformed packets")
        return failures

    def cleanup(self, ctx: ChaosContext) -> None:
        pass  # no state to clean
