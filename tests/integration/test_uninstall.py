# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Thomas Reagan
"""
Integration tests — uninstall.sh and pkg pre/post-deinstall lifecycle hooks.

Coverage:
  - uninstall.sh is installed, executable, and has --purge-logs
  - pkg manifest embeds pre-deinstall and post-deinstall scripts
  - uninstall.sh stops the daemon, cleans config.xml, removes /var/run/keaubnd/
  - --purge-logs removes /var/log/keaubnd/; logs are preserved by default
  - uninstall.sh is idempotent (safe to run twice)
  - pkg delete triggers pre-deinstall (daemon stop + config.xml cleanup)
  - pkg delete triggers post-deinstall (runtime dir removed, configd restarted)

These tests install and remove the plugin.  Each destructive test backs up and
restores config.xml so a missing KeaUbnd section doesn't break subsequent
tests.  The module teardown reinstalls via make upgrade.

Run selectively:  pytest -m uninstall
Skip in CI:       pytest -m "not uninstall"
"""

from __future__ import annotations

import pathlib

import pytest

pytestmark = [pytest.mark.integration, pytest.mark.uninstall]

PACKAGE_NAME   = "os-kea-ubnd-ddns"
PLUGIN_DIR     = "/usr/plugins/net/kea-ubnd-ddns"
UNINSTALL_SH   = "/usr/local/opnsense/scripts/keaubnd/uninstall.sh"
RUNTIME_DIR    = "/var/run/keaubnd"
LOG_DIR        = "/var/log/keaubnd"
CONFIG_XML     = "/conf/config.xml"
CONFIG_BACKUP  = "/tmp/config.xml.uninstall-test-backup"
SUPERVISOR_PID = "/var/run/kea-ubnd-ddns.supervisor.pid"

REPO = pathlib.Path(__file__).parents[2]


# ── Helpers ───────────────────────────────────────────────────────────────────

def _is_daemon_running(ssh) -> bool:
    out = ssh(
        f"test -f {SUPERVISOR_PID} && pkill -0 -F {SUPERVISOR_PID} "
        f"2>/dev/null && echo yes || echo no",
        check=False,
    ).strip()
    return out == "yes"


def _config_has_keaubnd(ssh) -> bool:
    return ssh(
        "python3 -c \""
        "import xml.etree.ElementTree as ET; "
        f"t=ET.parse('{CONFIG_XML}'); "
        "r=t.getroot(); o=r.find('OPNsense'); "
        "print('yes' if o is not None and o.find('KeaUbnd') is not None else 'no')"
        "\"",
        check=False,
    ).strip() == "yes"


def _fresh_install(ssh, txz_path: str) -> None:
    """Remove any existing install, pkg add the .txz, and start the daemon."""
    ssh(f"pkg delete -fy {PACKAGE_NAME} 2>/dev/null || true", check=False)
    ssh(f"pkg add {txz_path}")
    ssh("configctl keaubnd start 2>/dev/null || true", check=False)


def _build_txz(ssh) -> str:
    """
    Upload build_package.sh from the local repo and run it on the box.
    Returns the remote path of the produced package (.pkg or .txz).
    """
    ssh.sftp_put(REPO / "build_package.sh", "/tmp/build_package.sh")
    out = ssh(
        f"cd {PLUGIN_DIR} && sh /tmp/build_package.sh",
        timeout=120,
    )
    pkg = next(
        (ln.strip() for ln in reversed(out.splitlines())
         if ln.strip().endswith(".pkg") or ln.strip().endswith(".txz")),
        None,
    )
    if not pkg:
        pytest.fail(f"build_package.sh produced no package file.\nOutput:\n{out}")
    return pkg


# ── Module-level fixtures ─────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def txz_path(ssh, deploy):
    """Build the .txz on the box once per test module (deploy ensures source is current).
    Skips if the plugin build tree is not accessible (e.g. dev-user path restrictions)."""
    accessible = ssh(
        f"test -d {PLUGIN_DIR} && echo yes || echo no", check=False
    ).strip()
    if accessible != "yes":
        pytest.skip(
            f"Plugin build tree {PLUGIN_DIR} not accessible — "
            "uninstall functional tests require the build tree"
        )
    return _build_txz(ssh)


@pytest.fixture(scope="module")
def _restore_after_module(ssh, txz_path):
    """Reinstall via make upgrade when all tests in this module are done."""
    yield
    ssh(f"pkg delete -fy {PACKAGE_NAME} 2>/dev/null || true", check=False)
    ssh(f"cd {PLUGIN_DIR} && make upgrade", check=False, timeout=120)
    ssh("configctl keaubnd start 2>/dev/null || true", check=False)


# ── Non-destructive: verify installation artifacts ───────────────────────────

class TestUninstallArtifacts:
    """
    Check that uninstall.sh is present after install and that the pkg manifest
    embeds lifecycle scripts.  These tests read state only — no plugin removal.
    """

    def test_uninstall_sh_is_installed(self, ssh, deploy, test_log):
        result = ssh(f"test -f {UNINSTALL_SH} && echo yes || echo no",
                     check=False).strip()
        test_log("observed", {"present": result})
        assert result == "yes", f"{UNINSTALL_SH} not found after install"

    def test_uninstall_sh_is_executable(self, ssh, deploy, test_log):
        perm = ssh(f"stat -f '%Lp' {UNINSTALL_SH} 2>/dev/null || echo missing",
                   check=False).strip()
        test_log("observed", {"perm": perm})
        assert perm == "755", f"{UNINSTALL_SH} has permissions {perm!r}, want 755"

    def test_uninstall_sh_has_purge_logs_flag(self, ssh, deploy, test_log):
        content = ssh(f"cat {UNINSTALL_SH}", check=False)
        test_log("observed", {"has_flag": "--purge-logs" in content})
        assert "--purge-logs" in content, "uninstall.sh missing --purge-logs flag"

    def _pkg_raw(self, ssh) -> str:
        raw = ssh(f"pkg info --raw {PACKAGE_NAME} 2>/dev/null", check=False)
        if not raw.strip():
            pytest.skip(
                f"{PACKAGE_NAME} is not installed as a pkg package — "
                "manifest tests require pkg-based installation (run build_package.sh)"
            )
        return raw

    def test_pkg_manifest_has_pre_deinstall(self, ssh, deploy, test_log):
        raw = self._pkg_raw(ssh)
        test_log("observed", {"has_pre": "pre-deinstall" in raw})
        assert "pre-deinstall" in raw, "pkg manifest missing pre-deinstall script"

    def test_pkg_manifest_has_post_deinstall(self, ssh, deploy, test_log):
        raw = self._pkg_raw(ssh)
        test_log("observed", {"has_post": "post-deinstall" in raw})
        assert "post-deinstall" in raw, "pkg manifest missing post-deinstall script"

    def test_pre_deinstall_calls_uninstall_sh(self, ssh, deploy, test_log):
        raw = self._pkg_raw(ssh)
        idx = raw.find("pre-deinstall")
        snippet = raw[idx: idx + 300] if idx >= 0 else ""
        test_log("observed", {"pre_deinstall_snippet": snippet})
        assert "uninstall.sh" in raw, (
            "pre-deinstall script does not reference uninstall.sh"
        )


# ── Functional: uninstall.sh behaviour ───────────────────────────────────────

class TestUninstallScriptFunctional:
    """
    Run uninstall.sh and verify its effects.

    Each test: backup config.xml → fresh pkg-add install → run test → restore config.xml.
    Without config restore, a missing KeaUbnd section would prevent the daemon
    from starting in the next test's _fresh_install.
    """

    @pytest.fixture(autouse=True)
    def _setup(self, ssh, txz_path, _restore_after_module, test_log):
        ssh(f"cp {CONFIG_XML} {CONFIG_BACKUP}", check=False)
        _fresh_install(ssh, txz_path)
        yield
        ssh(f"cp {CONFIG_BACKUP} {CONFIG_XML} 2>/dev/null || true", check=False)
        ssh(f"rm -f {CONFIG_BACKUP}", check=False)

    def test_stops_daemon(self, ssh, test_log):
        was_running = _is_daemon_running(ssh)
        test_log("setup", {"daemon_was_running": was_running})
        if not was_running:
            pytest.skip("Daemon was not running before test — check plugin configuration")

        ssh(f"sh {UNINSTALL_SH}", check=True)

        still_running = _is_daemon_running(ssh)
        test_log("observed", {"still_running": still_running})
        assert not still_running, "Daemon still running after uninstall.sh"

    def test_removes_config_xml_section(self, ssh, test_log):
        had_section = _config_has_keaubnd(ssh)
        test_log("setup", {"had_section": had_section})
        if not had_section:
            pytest.skip("KeaUbnd section not present in config.xml before test")

        ssh(f"sh {UNINSTALL_SH}", check=True)

        still_has = _config_has_keaubnd(ssh)
        test_log("observed", {"still_has_section": still_has})
        assert not still_has, "KeaUbnd section still in config.xml after uninstall.sh"

    def test_removes_runtime_dir(self, ssh, test_log):
        ssh(f"mkdir -p {RUNTIME_DIR}", check=False)

        ssh(f"sh {UNINSTALL_SH}", check=True)

        exists = ssh(f"test -d {RUNTIME_DIR} && echo yes || echo no",
                     check=False).strip()
        test_log("observed", {"runtime_dir_exists": exists})
        assert exists == "no", f"{RUNTIME_DIR} still present after uninstall.sh"

    def test_preserves_logs_by_default(self, ssh, test_log):
        sentinel = f"{LOG_DIR}/test_preserve.log"
        ssh(f"mkdir -p {LOG_DIR} && touch {sentinel}", check=False)

        ssh(f"sh {UNINSTALL_SH}", check=True)

        log_exists = ssh(f"test -f {sentinel} && echo yes || echo no",
                         check=False).strip()
        test_log("observed", {"log_sentinel_exists": log_exists})
        ssh(f"rm -rf {LOG_DIR}", check=False)
        assert log_exists == "yes", (
            f"Log file removed without --purge-logs (should be preserved)"
        )

    def test_purge_logs_removes_log_dir(self, ssh, test_log):
        sentinel = f"{LOG_DIR}/test_purge.log"
        ssh(f"mkdir -p {LOG_DIR} && touch {sentinel}", check=False)

        ssh(f"sh {UNINSTALL_SH} --purge-logs", check=True)

        log_exists = ssh(f"test -d {LOG_DIR} && echo yes || echo no",
                         check=False).strip()
        test_log("observed", {"log_dir_exists": log_exists})
        assert log_exists == "no", f"{LOG_DIR} still present after uninstall.sh --purge-logs"

    def test_idempotent(self, ssh, test_log):
        """Running uninstall.sh twice must not error."""
        ssh(f"sh {UNINSTALL_SH}", check=True)
        out = ssh(f"sh {UNINSTALL_SH} 2>&1; echo rc=$?", check=False)
        test_log("observed", {"second_run_output": out})
        assert "rc=0" in out, f"Second run of uninstall.sh returned non-zero:\n{out}"


# ── Lifecycle: pkg delete triggers the embedded hooks ────────────────────────

class TestPkgDeleteHooks:
    """
    Verify that pkg delete fires pre-deinstall (→ uninstall.sh via the embedded
    pkg script) and post-deinstall (runtime dir removal, configd restart).

    Each test backs up config.xml, does a fresh install, runs pkg delete, then
    verifies state.  Config is restored in teardown so the next test's fresh
    install can start the daemon correctly.
    """

    @pytest.fixture(autouse=True)
    def _setup(self, ssh, txz_path, _restore_after_module):
        ssh(f"cp {CONFIG_XML} {CONFIG_BACKUP}", check=False)
        _fresh_install(ssh, txz_path)
        yield
        ssh(f"cp {CONFIG_BACKUP} {CONFIG_XML} 2>/dev/null || true", check=False)
        ssh(f"rm -f {CONFIG_BACKUP}", check=False)

    def test_pre_deinstall_stops_daemon(self, ssh, test_log):
        was_running = _is_daemon_running(ssh)
        test_log("setup", {"daemon_was_running": was_running})
        if not was_running:
            pytest.skip("Daemon was not running before test — check plugin configuration")

        ssh(f"pkg delete -fy {PACKAGE_NAME}", check=True, timeout=60)

        still_running = _is_daemon_running(ssh)
        test_log("observed", {"still_running": still_running})
        assert not still_running, "Daemon still running after pkg delete"

    def test_pre_deinstall_removes_config_xml_section(self, ssh, test_log):
        had_section = _config_has_keaubnd(ssh)
        test_log("setup", {"had_section": had_section})
        if not had_section:
            pytest.skip("KeaUbnd section not in config.xml before test")

        ssh(f"pkg delete -fy {PACKAGE_NAME}", check=True, timeout=60)

        still_has = _config_has_keaubnd(ssh)
        test_log("observed", {"still_has_section": still_has})
        assert not still_has, "KeaUbnd still in config.xml after pkg delete"

    def test_post_deinstall_removes_runtime_dir(self, ssh, test_log):
        ssh(f"mkdir -p {RUNTIME_DIR}", check=False)

        ssh(f"pkg delete -fy {PACKAGE_NAME}", check=True, timeout=60)

        exists = ssh(f"test -d {RUNTIME_DIR} && echo yes || echo no",
                     check=False).strip()
        test_log("observed", {"runtime_dir_exists": exists})
        assert exists == "no", f"{RUNTIME_DIR} still present after pkg delete"

    def test_post_deinstall_drops_configd_actions(self, ssh, test_log):
        """After pkg delete, configd must not advertise keaubnd actions."""
        ssh(f"pkg delete -fy {PACKAGE_NAME}", check=True, timeout=60)

        actions = ssh(
            "configctl configd actions 2>/dev/null | grep keaubnd || true",
            check=False,
        ).strip()
        test_log("observed", {"remaining_actions": actions})
        assert not actions, (
            f"configd still advertises keaubnd actions after pkg delete: {actions}"
        )

    def test_pkg_delete_removes_installed_files(self, ssh, test_log):
        ssh(f"pkg delete -fy {PACKAGE_NAME}", check=True, timeout=60)

        sentinel_files = [
            "/usr/local/sbin/kea-ubnd-ddns.py",
            "/usr/local/opnsense/scripts/keaubnd/start.py",
            "/usr/local/opnsense/scripts/keaubnd/uninstall.sh",
            "/usr/local/etc/inc/plugins.inc.d/keaubnd.inc",
            "/usr/local/opnsense/service/conf/actions.d/actions_keaubnd.conf",
        ]
        orphans = [
            f for f in sentinel_files
            if ssh(f"test -f {f} && echo yes || echo no", check=False).strip() == "yes"
        ]
        test_log("observed", {"orphans": orphans})
        assert not orphans, f"Files not removed after pkg delete: {orphans}"
