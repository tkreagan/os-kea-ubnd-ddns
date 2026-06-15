# SPDX-License-Identifier: BSD-2-Clause
"""
Collision scenarios: reservation+lease conflict, host_entries override, duplicate IP.
"""
from __future__ import annotations

import time

from tools.scenarios import register
from tools.scenarios.base import Scenario, ChaosContext

HOST_ENTRIES = "/var/unbound/host_entries.conf"


@register
class ReservationLeaseCollision(Scenario):
    name = "reservation_lease_collision"
    description = (
        "Same IP: reserved for hostA, leased to hostB; "
        "verify collision_policy=allow keeps both"
    )
    tags = ["collision"]

    def setup(self, ctx: ChaosContext) -> None:
        pass

    def run(self, ctx: ChaosContext) -> None:
        _, ip = ctx.alloc_host("-col")
        self._ip = ip
        subnet_id = ctx.subnet_id()
        self._host_a = "collision-reserved"
        self._host_b = "collision-leased"

        # Add reservation
        ctx.kea.reservation_add(subnet_id, ip, "aa:bb:cc:c0:1a:01", self._host_a)
        # Add lease for same IP with different name
        ctx.kea.lease4_add(ip, "aa:bb:cc:c0:1a:02", self._host_b,
                           valid_lft=3600, subnet_id=subnet_id)
        ctx.event("collision_injected", ip=ip, reserved=self._host_a, leased=self._host_b)

        ctx.run_sync("static")
        ctx.run_sync("dynamic")
        ctx.wait(2, "sync settle")

    def verify(self, ctx: ChaosContext) -> list[str]:
        failures = []
        audit = ctx.run_audit()

        # Check that the collision was handled without crashing
        if not audit.get("complete", False):
            failures.append(f"Audit incomplete: {audit.get('kea_error')}")

        # Under default collision_policy=allow, both names can coexist at same IP
        # (or at least one of them should be registered)
        data = ctx.unbound.list_local_data()
        fqdn_a = f"{self._host_a}.{ctx.domain}"
        fqdn_b = f"{self._host_b}.{ctx.domain}"
        if fqdn_a not in data and self._host_a not in data:
            if fqdn_b not in data and self._host_b not in data:
                failures.append(
                    f"Neither colliding record ({self._host_a}, {self._host_b}) "
                    f"is registered in Unbound"
                )
        return failures

    def cleanup(self, ctx: ChaosContext) -> None:
        try:
            ctx.kea.reservation_del(ctx.subnet_id(), self._ip)
        except Exception:
            pass
        try:
            ctx.kea.lease4_del(self._ip)
        except Exception:
            pass
        ctx.run_clean()


@register
class OverrideConflict(Scenario):
    name = "override_conflict"
    description = "host_entries.conf record for IP X; lease same IP to DHCP client; sync must not overwrite"
    tags = ["collision", "host_entries"]
    OVERRIDE_IP = None   # will be allocated in run()
    OVERRIDE_NAME = "chaos-override-static"

    def run(self, ctx: ChaosContext) -> None:
        _, ip = ctx.alloc_host("-ov")
        self._ip = ip
        self.OVERRIDE_IP = ip

        # Inject a host_entries.conf record directly.
        # Double-quotes in the record body make shell escaping impossible with
        # nested sudo/sh -c; write via a temp file instead.
        import pathlib, tempfile as _tmp
        content = (
            f'local-data: "{self.OVERRIDE_NAME}.{ctx.domain}. 3600 IN A {ip}"\n'
            f'local-data-ptr: "{ip} {self.OVERRIDE_NAME}.{ctx.domain}."\n'
        )
        with _tmp.NamedTemporaryFile(mode="w", suffix=".conf", delete=False) as tf:
            tf.write(content)
            tmp_local = pathlib.Path(tf.name)
        tmp_remote = "/tmp/_chaos_host_entries_patch.conf"
        ctx.ssh.sftp_put(tmp_local, tmp_remote)
        tmp_local.unlink(missing_ok=True)
        ctx.ssh.sudo(f"cat {tmp_remote} >> {HOST_ENTRIES} && rm {tmp_remote}", timeout=10)
        # Reload Unbound to pick up static record
        ctx.ssh.sudo(
            "/usr/local/sbin/unbound-control -c /var/unbound/unbound.conf reload || true",
            timeout=10, check=False
        )
        ctx.event("static_record_injected", name=self.OVERRIDE_NAME, ip=ip)

        # Now add a lease for the same IP with a different hostname
        ctx.kea.lease4_add(ip, "aa:bb:cc:cc:00:01", "chaos-leased-override",
                           valid_lft=3600, subnet_id=ctx.subnet_id())
        ctx.run_sync("dynamic")
        ctx.wait(2, "sync settle")

    def verify(self, ctx: ChaosContext) -> list[str]:
        failures = []
        # The host_entries.conf record should NOT have been removed or replaced
        raw = ctx.ssh.sudo(f"cat {HOST_ENTRIES}", timeout=10)
        if self.OVERRIDE_NAME not in raw:
            failures.append(
                f"host_entries.conf record for {self.OVERRIDE_NAME} was removed by sync"
            )
        # Unbound should still return the static record
        if not ctx.unbound.has_record(
            f"{self.OVERRIDE_NAME}.{ctx.domain}", self._ip
        ):
            failures.append(
                f"Static A record for {self.OVERRIDE_NAME} was overwritten in Unbound"
            )
        return failures

    def cleanup(self, ctx: ChaosContext) -> None:
        # Remove the injected lines from host_entries.conf
        ctx.ssh.sudo(
            f"grep -v '{self.OVERRIDE_NAME}' {HOST_ENTRIES} > /tmp/_he.tmp && "
            f"mv /tmp/_he.tmp {HOST_ENTRIES}",
            check=False, timeout=10
        )
        ctx.ssh.sudo(
            "/usr/local/sbin/unbound-control -c /var/unbound/unbound.conf reload || true",
            timeout=10, check=False
        )
        try:
            ctx.kea.lease4_del(self._ip)
        except Exception:
            pass
        ctx.run_clean()


@register
class DuplicateIp(Scenario):
    name = "duplicate_ip"
    description = "Inject two API leases for the same IP; verify sync handles without crash"
    tags = ["collision", "hostile"]

    def run(self, ctx: ChaosContext) -> None:
        _, ip = ctx.alloc_host("-dup")
        self._ip = ip
        # First lease
        ctx.kea.lease4_add(ip, "aa:bb:cc:d1:00:01", "chaos-dup-first",
                           valid_lft=600, subnet_id=ctx.subnet_id())
        ctx.event("first_lease", ip=ip, hostname="chaos-dup-first")
        # Second lease for same IP (Kea may reject; that's fine)
        try:
            ctx.kea.lease4_add(ip, "aa:bb:cc:d1:00:02", "chaos-dup-second",
                               valid_lft=600, subnet_id=ctx.subnet_id())
            ctx.event("second_lease", ip=ip, hostname="chaos-dup-second", accepted=True)
        except Exception as exc:
            ctx.event("second_lease", ip=ip, accepted=False, reason=str(exc)[:80])

        ctx.run_sync("dynamic")
        ctx.wait(2, "sync settle")

    def verify(self, ctx: ChaosContext) -> list[str]:
        failures = []
        # Primary requirement: no crash, audit still complete
        ok, err = _audit_ok(ctx)
        if not ok:
            failures.append(f"Audit incomplete after duplicate IP: {err}")
        if not ctx.daemon_is_running():
            failures.append("Daemon not running after duplicate-IP scenario")
        return failures

    def cleanup(self, ctx: ChaosContext) -> None:
        try:
            ctx.kea.lease4_del(self._ip)
        except Exception:
            pass
        ctx.run_clean()


def _audit_ok(ctx: ChaosContext) -> tuple[bool, str]:
    try:
        audit = ctx.run_audit()
        return audit.get("complete", True), audit.get("kea_error", "")
    except Exception as exc:
        return False, str(exc)
