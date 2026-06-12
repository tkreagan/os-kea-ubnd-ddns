# SPDX-License-Identifier: BSD-2-Clause
"""
Hostile / non-conforming input scenarios.
"""
from __future__ import annotations

from tools.scenarios import register
from tools.scenarios.base import Scenario, ChaosContext


def _inject_and_sync(ctx: ChaosContext, hostname: str, ip: str,
                     mac: str = "aa:bb:cc:dd:ee:ff") -> None:
    ctx.kea.lease4_add(ip, mac, hostname, valid_lft=300,
                       subnet_id=ctx.subnet_id())
    ctx.run_sync("dynamic")
    ctx.wait(2, "sync settle")


def _audit_ok(ctx: ChaosContext) -> tuple[bool, str]:
    try:
        audit = ctx.run_audit()
        complete = audit.get("complete", True)
        return complete, audit.get("kea_error", "")
    except Exception as exc:
        return False, str(exc)


@register
class BlankHostname(Scenario):
    name = "blank_hostname"
    description = "Inject lease with empty hostname; verify no empty DNS name, no crash"
    tags = ["hostile", "basic"]

    def run(self, ctx: ChaosContext) -> None:
        _, ip = ctx.alloc_host("-blank")
        self._ip = ip
        _inject_and_sync(ctx, "", ip, mac="aa:bb:cc:00:00:01")

    def verify(self, ctx: ChaosContext) -> list[str]:
        failures = []
        data = ctx.unbound.list_local_data()
        for name in data:
            if not name.strip():
                failures.append(f"Empty name in Unbound: {name!r}")
        ok, err = _audit_ok(ctx)
        if not ok:
            failures.append(f"Audit incomplete after blank hostname: {err}")
        return failures

    def cleanup(self, ctx: ChaosContext) -> None:
        try:
            ctx.kea.lease4_del(self._ip)
        except Exception:
            pass
        ctx.run_clean()


@register
class NumericHostname(Scenario):
    name = "numeric_hostname"
    description = "Inject lease with all-digit hostname; verify is_sane_name rejects it"
    tags = ["hostile"]

    def run(self, ctx: ChaosContext) -> None:
        _, ip = ctx.alloc_host("-num")
        self._ip = ip
        _inject_and_sync(ctx, "123456789", ip, mac="aa:bb:cc:00:00:02")

    def verify(self, ctx: ChaosContext) -> list[str]:
        failures = []
        data = ctx.unbound.list_local_data()
        if "123456789" in data or f"123456789.{ctx.domain}" in data:
            failures.append("Numeric hostname '123456789' was registered in Unbound (should be rejected)")
        ok, err = _audit_ok(ctx)
        if not ok:
            failures.append(f"Audit incomplete: {err}")
        return failures

    def cleanup(self, ctx: ChaosContext) -> None:
        try:
            ctx.kea.lease4_del(self._ip)
        except Exception:
            pass
        ctx.run_clean()


@register
class LongHostname(Scenario):
    name = "long_hostname"
    description = "Inject 256-char hostname; verify graceful skip and no crash"
    tags = ["hostile"]
    LONG_NAME = "a" * 256

    def run(self, ctx: ChaosContext) -> None:
        _, ip = ctx.alloc_host("-long")
        self._ip = ip
        _inject_and_sync(ctx, self.LONG_NAME, ip, mac="aa:bb:cc:00:00:03")

    def verify(self, ctx: ChaosContext) -> list[str]:
        failures = []
        data = ctx.unbound.list_local_data()
        if self.LONG_NAME in data or f"{self.LONG_NAME}.{ctx.domain}" in data:
            failures.append("Overlong hostname was registered in Unbound (should be skipped)")
        ok, err = _audit_ok(ctx)
        if not ok:
            failures.append(f"Audit incomplete: {err}")
        return failures

    def cleanup(self, ctx: ChaosContext) -> None:
        try:
            ctx.kea.lease4_del(self._ip)
        except Exception:
            pass
        ctx.run_clean()


@register
class SpecialCharsHostname(Scenario):
    name = "special_chars"
    description = "Inject hostname with spaces and slashes; verify clean handling"
    tags = ["hostile"]
    BAD_NAME = "foo bar/baz"

    def run(self, ctx: ChaosContext) -> None:
        _, ip = ctx.alloc_host("-spec")
        self._ip = ip
        _inject_and_sync(ctx, self.BAD_NAME, ip, mac="aa:bb:cc:00:00:04")

    def verify(self, ctx: ChaosContext) -> list[str]:
        failures = []
        data = ctx.unbound.list_local_data()
        for name in data:
            if " " in name or "/" in name:
                failures.append(f"Special-char name made it into Unbound: {name!r}")
        ok, err = _audit_ok(ctx)
        if not ok:
            failures.append(f"Audit incomplete after special-char hostname: {err}")
        return failures

    def cleanup(self, ctx: ChaosContext) -> None:
        try:
            ctx.kea.lease4_del(self._ip)
        except Exception:
            pass
        ctx.run_clean()


@register
class UnicodeHostname(Scenario):
    name = "unicode_hostname"
    description = "Inject non-ASCII hostname; verify no crash and no malformed DNS record"
    tags = ["hostile"]
    UNICODE_NAME = "ünïcödé-hôst"

    def run(self, ctx: ChaosContext) -> None:
        _, ip = ctx.alloc_host("-uni")
        self._ip = ip
        _inject_and_sync(ctx, self.UNICODE_NAME, ip, mac="aa:bb:cc:00:00:05")

    def verify(self, ctx: ChaosContext) -> list[str]:
        failures = []
        # Kea itself may accept or reject the unicode name; either is fine as long
        # as the sync scripts don't crash and audit stays complete.
        ok, err = _audit_ok(ctx)
        if not ok:
            failures.append(f"Audit incomplete after unicode hostname: {err}")
        # Daemon should still be alive
        if not ctx.daemon_is_running():
            failures.append("Daemon not running after unicode hostname injection")
        return failures

    def cleanup(self, ctx: ChaosContext) -> None:
        try:
            ctx.kea.lease4_del(self._ip)
        except Exception:
            pass
        ctx.run_clean()
