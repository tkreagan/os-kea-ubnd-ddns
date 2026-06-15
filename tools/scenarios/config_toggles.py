# SPDX-License-Identifier: BSD-2-Clause
"""
Config toggle scenarios: synthesize_ptr, collision_policy, stale_record_cleanup.
"""
from __future__ import annotations

import time

from tools.scenarios import register
from tools.scenarios.base import Scenario, ChaosContext

CONFIG_XML = "/conf/config.xml"
XMLSET = "/usr/local/sbin/configctl"


def _set_config(ctx: ChaosContext, xpath: str, value: str) -> None:
    """Set a config.xml node value using xmllint or php helper."""
    # Use a small python3 script to patch config.xml via lxml/xml.etree
    code = f"""
import xml.etree.ElementTree as ET
tree = ET.parse('/conf/config.xml')
root = tree.getroot()
parts = {xpath!r}.strip('/').split('/')
node = root
for part in parts[:-1]:
    child = node.find(part)
    if child is None:
        child = ET.SubElement(node, part)
    node = child
leaf = node.find(parts[-1])
if leaf is None:
    leaf = ET.SubElement(node, parts[-1])
leaf.text = {value!r}
ET.indent(tree)
tree.write('/conf/config.xml', xml_declaration=True, encoding='unicode')
print('ok')
"""
    ctx.ssh.sudo_script("python3", code, timeout=10)


def _get_config(ctx: ChaosContext, xpath: str) -> str:
    code = f"""
import xml.etree.ElementTree as ET
tree = ET.parse('/conf/config.xml')
root = tree.getroot()
parts = {xpath!r}.strip('/').split('/')
node = root
for part in parts:
    node = node.find(part)
    if node is None:
        print('')
        exit(0)
print(node.text or '')
"""
    return ctx.ssh.sudo_script("python3", code, timeout=10).strip()


SYNTH_PTR_PATH = "OPNsense/KeaUbnd/general/synthesize_ptr"
COLLISION_PATH = "OPNsense/KeaUbnd/general/collision_policy"


@register
class SynthesizePtrToggle(Scenario):
    name = "synthesize_ptr_toggle"
    description = "Disable synthesize_ptr; verify PTR not added; re-enable; verify PTR appears"
    tags = ["config", "ptr"]

    def setup(self, ctx: ChaosContext) -> None:
        self._original = _get_config(ctx, SYNTH_PTR_PATH)

    def run(self, ctx: ChaosContext) -> None:
        hostname, ip = ctx.alloc_host("-synptr")
        self._hostname = hostname
        self._ip = ip
        mac = "aa:cc:00:5e:01:01"

        # Disable synthesize_ptr
        _set_config(ctx, SYNTH_PTR_PATH, "0")
        ctx.event("synthesize_ptr_disabled")

        ctx.kea.lease4_add(ip, mac, hostname, valid_lft=600,
                           subnet_id=ctx.subnet_id())
        ctx.run_sync("dynamic")
        ctx.wait(2, "sync with ptr disabled")
        self._has_ptr_disabled = ctx.unbound.has_ptr(ip, f"{hostname}.{ctx.domain}")
        ctx.event("ptr_present_while_disabled", present=self._has_ptr_disabled)

        # Re-enable
        _set_config(ctx, SYNTH_PTR_PATH, "1")
        ctx.event("synthesize_ptr_enabled")
        ctx.run_sync("dynamic")
        ctx.wait(2, "sync with ptr enabled")
        self._has_ptr_enabled = ctx.unbound.has_ptr(ip, f"{hostname}.{ctx.domain}")
        ctx.event("ptr_present_while_enabled", present=self._has_ptr_enabled)

    def verify(self, ctx: ChaosContext) -> list[str]:
        failures = []
        if self._has_ptr_disabled:
            failures.append(
                "PTR was synthesized even though synthesize_ptr=0"
            )
        if not self._has_ptr_enabled:
            failures.append(
                "PTR was NOT synthesized after re-enabling synthesize_ptr"
            )
        return failures

    def cleanup(self, ctx: ChaosContext) -> None:
        _set_config(ctx, SYNTH_PTR_PATH, self._original or "1")
        try:
            ctx.kea.lease4_del(self._ip)
        except Exception:
            pass
        ctx.run_clean()


@register
class CollisionPolicyCycle(Scenario):
    name = "collision_policy_cycle"
    description = "Cycle allow/first_wins/last_wins with conflicting records; verify each outcome"
    tags = ["config", "collision"]

    def setup(self, ctx: ChaosContext) -> None:
        self._original = _get_config(ctx, COLLISION_PATH)

    def run(self, ctx: ChaosContext) -> None:
        self._results: dict[str, dict] = {}
        subnet_id = ctx.subnet_id()

        for policy in ("allow", "first_wins", "last_wins"):
            _set_config(ctx, COLLISION_PATH, policy)
            ctx.event("policy_set", policy=policy)

            _, ip = ctx.alloc_host(f"-cp-{policy[:2]}")
            host_a = f"cp-{policy[:2]}-first"
            host_b = f"cp-{policy[:2]}-second"

            ctx.kea.reservation_add(subnet_id, ip, f"aa:cc:0a:{ord(policy[0]):02x}:01:01", host_a)
            ctx.kea.lease4_add(ip, f"aa:cc:0a:{ord(policy[0]):02x}:02:02", host_b,
                               valid_lft=600, subnet_id=subnet_id)

            ctx.run_sync("static")
            ctx.run_sync("dynamic")
            ctx.wait(2, "policy sync settle")

            data = ctx.unbound.list_local_data()
            fqdn_a = f"{host_a}.{ctx.domain}"
            fqdn_b = f"{host_b}.{ctx.domain}"
            self._results[policy] = {
                "ip": ip,
                "host_a": host_a,
                "host_b": host_b,
                "has_a": fqdn_a in data or host_a in data,
                "has_b": fqdn_b in data or host_b in data,
            }
            ctx.event("policy_result", policy=policy, **self._results[policy])

            # Clean before next policy
            ctx.kea.reservation_del(subnet_id, ip)
            ctx.kea.lease4_del(ip)
            ctx.run_clean()
            ctx.wait(1, "inter-policy clean")

    def verify(self, ctx: ChaosContext) -> list[str]:
        failures = []
        for policy, r in self._results.items():
            if policy == "allow":
                # Both should coexist (or at least one)
                if not r["has_a"] and not r["has_b"]:
                    failures.append(f"allow policy: neither record registered")
            elif policy == "first_wins":
                if not r["has_a"]:
                    failures.append(
                        f"first_wins: first record (reservation {r['host_a']}) not present"
                    )
            elif policy == "last_wins":
                if not r["has_b"]:
                    failures.append(
                        f"last_wins: last record (lease {r['host_b']}) not present"
                    )
        return failures

    def cleanup(self, ctx: ChaosContext) -> None:
        _set_config(ctx, COLLISION_PATH, self._original or "allow")
        ctx.run_clean()


@register
class StaleRecordCleanup(Scenario):
    name = "stale_record_cleanup"
    description = (
        "Plant orphaned Unbound records with no Kea backing; run bulk clean; "
        "verify stale records removed and active lease records preserved"
    )
    tags = ["config", "cleanup"]

    def run(self, ctx: ChaosContext) -> None:
        # Plant two stale records (no lease, no reservation)
        _, stale_ip1 = ctx.alloc_host("-stclean-s1")
        _, stale_ip2 = ctx.alloc_host("-stclean-s2")
        self._stale1 = f"stclean-stale1.{ctx.domain}"
        self._stale2 = f"stclean-stale2.{ctx.domain}"

        ctx.unbound.add_record(f"{self._stale1}. 300 IN A {stale_ip1}")
        ctx.unbound.add_record(f"{self._stale2}. 300 IN A {stale_ip2}")
        ctx.event("stale_planted", names=[self._stale1, self._stale2])

        # Add a live lease so clean() knows there's real state
        hostname, live_ip = ctx.alloc_host("-stclean-live")
        self._live_hostname = hostname
        self._live_ip = live_ip
        ctx.kea.lease4_add(live_ip, "aa:bb:00:01:00:01", hostname,
                           valid_lft=600, subnet_id=ctx.subnet_id())
        ctx.run_sync("dynamic")
        ctx.event("live_lease_synced", hostname=hostname, ip=live_ip)

        # Run bulk clean — should remove orphaned records
        ctx.run_clean()
        ctx.wait(2, "clean settle")

    def verify(self, ctx: ChaosContext) -> list[str]:
        failures = []
        data = ctx.unbound.list_local_data()

        if self._stale1 in data or "stclean-stale1" in str(data):
            failures.append(f"Stale record {self._stale1} still present after clean")
        if self._stale2 in data or "stclean-stale2" in str(data):
            failures.append(f"Stale record {self._stale2} still present after clean")

        live_fqdn = f"{self._live_hostname}.{ctx.domain}"
        if live_fqdn not in data and self._live_hostname not in str(data):
            failures.append(f"Active lease record {live_fqdn} was incorrectly removed")

        return failures

    def cleanup(self, ctx: ChaosContext) -> None:
        try:
            ctx.kea.lease4_del(self._live_ip)
        except Exception:
            pass
        for name in (self._stale1, self._stale2):
            try:
                ctx.unbound.remove_record(f"{name}.")
            except Exception:
                pass
        ctx.run_clean()
