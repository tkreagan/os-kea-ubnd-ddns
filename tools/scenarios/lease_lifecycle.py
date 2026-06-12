# SPDX-License-Identifier: BSD-2-Clause
"""
Lease lifecycle scenarios: CRUD, flood, TTL consistency.
"""
from __future__ import annotations

import time

from tools.scenarios import register
from tools.scenarios.base import Scenario, ChaosContext


@register
class LeaseCrud(Scenario):
    name = "lease_crud"
    description = "Inject 5 leases, sync, verify A+PTR; remove all, clean, verify gone"
    tags = ["lease", "basic"]

    def run(self, ctx: ChaosContext) -> None:
        self._pairs = []
        for i in range(5):
            hostname, ip = ctx.alloc_host(f"-crud{i}")
            mac = f"aa:bb:cc:dd:ee:{i:02x}"
            ctx.kea.lease4_add(ip, mac, hostname, valid_lft=3600,
                               subnet_id=ctx.subnet_id())
            self._pairs.append((hostname, ip))
            ctx.event("lease_added", hostname=hostname, ip=ip)

        ctx.run_sync("dynamic")
        ctx.wait(2, "let sync settle")

    def verify(self, ctx: ChaosContext) -> list[str]:
        failures = []
        for hostname, ip in self._pairs:
            if not ctx.unbound.has_record(f"{hostname}.{ctx.domain}", ip):
                failures.append(f"A record missing for {hostname} → {ip}")
            if not ctx.unbound.has_ptr(ip, f"{hostname}.{ctx.domain}"):
                failures.append(f"PTR record missing for {ip} → {hostname}")
            result = ctx.dns.verify_pair(hostname, ip, ctx.domain)
            if not result["forward_ok"]:
                failures.append(
                    f"drill forward failed for {hostname}: got {result['forward_answer']!r}"
                )
        return failures

    def cleanup(self, ctx: ChaosContext) -> None:
        for hostname, ip in getattr(self, "_pairs", []):
            try:
                ctx.kea.lease4_del(ip)
            except Exception:
                pass
        ctx.run_clean()
        ctx.wait(2, "post-cleanup settle")

        # Confirm removal
        audit = ctx.run_audit()
        remaining = [
            r for r in audit.get("records", [])
            if r.get("ip") in {ip for _, ip in getattr(self, "_pairs", [])}
        ]
        if remaining:
            ctx.event("cleanup_warn", remaining=len(remaining),
                      msg="Some injected records still present after clean")


@register
class LeaseFlood(Scenario):
    name = "lease_flood"
    description = "Inject 25 leases rapidly, sync, verify all registered; then clean"
    tags = ["lease", "stress"]
    N = 25

    def run(self, ctx: ChaosContext) -> None:
        self._pairs = []
        for i in range(self.N):
            hostname, ip = ctx.alloc_host(f"-flood{i:02d}")
            mac = f"aa:cc:dd:{i//256:02x}:{i%256:02x}:01"
            ctx.kea.lease4_add(ip, mac, hostname, valid_lft=600,
                               subnet_id=ctx.subnet_id())
            self._pairs.append((hostname, ip))
        ctx.event("leases_injected", count=self.N)
        ctx.run_sync("dynamic")
        ctx.wait(3, "let flood sync settle")

    def verify(self, ctx: ChaosContext) -> list[str]:
        failures = []
        data = ctx.unbound.list_local_data()
        for hostname, ip in self._pairs:
            fqdn = f"{hostname}.{ctx.domain}"
            if fqdn not in data and hostname not in data:
                failures.append(f"No Unbound record found for {hostname}")
        if failures:
            ctx.event("missing_records", count=len(failures))
        return failures

    def cleanup(self, ctx: ChaosContext) -> None:
        for _, ip in getattr(self, "_pairs", []):
            try:
                ctx.kea.lease4_del(ip)
            except Exception:
                pass
        ctx.run_clean()


@register
class TtlConsistency(Scenario):
    name = "ttl_consistency"
    description = "Verify Unbound TTL ≤ Kea remaining valid_lft after sync"
    tags = ["lease", "ttl"]
    VALID_LFT = 120

    def run(self, ctx: ChaosContext) -> None:
        hostname, ip = ctx.alloc_host("-ttl")
        mac = "aa:bb:cc:00:tt:01"
        self._hostname = hostname
        self._ip = ip
        self._injected_at = time.time()
        ctx.kea.lease4_add(ip, mac, hostname, valid_lft=self.VALID_LFT,
                           subnet_id=ctx.subnet_id())
        ctx.event("lease_added", hostname=hostname, ip=ip, valid_lft=self.VALID_LFT)
        ctx.run_sync("dynamic")
        ctx.wait(2, "let sync settle")

    def verify(self, ctx: ChaosContext) -> list[str]:
        failures = []
        elapsed = time.time() - self._injected_at
        max_expected_ttl = self.VALID_LFT - int(elapsed) + 5  # +5s grace

        data = ctx.unbound.list_local_data()
        fqdn = f"{self._hostname}.{ctx.domain}"
        lines = data.get(fqdn, data.get(self._hostname, []))
        if not lines:
            return [f"No Unbound record found for {self._hostname}"]

        for line in lines:
            parts = line.split()
            if len(parts) >= 2:
                try:
                    ttl = int(parts[1])
                    if ttl > max_expected_ttl:
                        failures.append(
                            f"TTL {ttl} > expected max {max_expected_ttl} "
                            f"for {self._hostname}"
                        )
                except (ValueError, IndexError):
                    pass
        return failures

    def cleanup(self, ctx: ChaosContext) -> None:
        try:
            ctx.kea.lease4_del(self._ip)
        except Exception:
            pass
        ctx.run_clean()
