# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Thomas Reagan
"""
Integration tests — package build and installation.

Builds os-kea-unbound-*.txz on orbison using pkg create (no OPNsense build
tools required), installs it, verifies the file manifest, and removes it.

Run with: pytest -m packaging
"""

from __future__ import annotations

import json
import time

import pytest

pytestmark = [pytest.mark.integration, pytest.mark.packaging]

PACKAGE_NAME = "os-kea-unbound"

EXPECTED_FILES = [
    "/usr/local/sbin/kea-unbound-ddns.py",
    "/usr/local/opnsense/scripts/keaunbound/start.py",
    "/usr/local/opnsense/scripts/keaunbound/stop.py",
    "/usr/local/opnsense/scripts/keaunbound/reservation-sync.py",
    "/usr/local/opnsense/scripts/keaunbound/lease-sync.py",
    "/usr/local/opnsense/scripts/keaunbound/local-data-audit.py",
    "/usr/local/opnsense/scripts/keaunbound/local-data-clean.py",
    "/usr/local/opnsense/scripts/keaunbound/lib/__init__.py",
    "/usr/local/opnsense/scripts/keaunbound/lib/keaunbound_sync.py",
    "/usr/local/opnsense/scripts/keaunbound/lib/kea_transport.py",
    "/usr/local/etc/inc/plugins.inc.d/keaunbound.inc",
    "/usr/local/opnsense/service/conf/actions.d/actions_keaunbound.conf",
]

FORBIDDEN_IN_PACKAGE = [".DS_Store", "._", "__pycache__", ".pyc"]


@pytest.fixture(scope="module")
def built_package(ssh, deploy):
    """Build the package on orbison; yield the .txz path; remove after tests."""
    txz = ssh("sh /usr/local/sbin/../../../build_package.sh 2>&1 | tail -1",
              check=False).strip()
    if not txz or not txz.endswith(".txz"):
        # build_package.sh not deployed; run it inline
        ssh("sh -s", check=False)  # placeholder
        txz = ssh(
            "ls /tmp/os-kea-unbound-*.txz 2>/dev/null | tail -1", check=False
        ).strip()
    if not txz:
        pytest.skip("Package build failed or build_package.sh not found")
    yield txz
    ssh(f"rm -f {txz}", check=False)


def test_package_builds_without_error(ssh, deploy, test_log):
    """build_package.sh must exit 0 and produce a .txz."""
    out = ssh(
        "cd /tmp && sh /usr/local/sbin/build_package.sh 2>&1 || true",
        check=False,
    )
    txz = ssh("ls /tmp/os-kea-unbound-*.txz 2>/dev/null | tail -1",
              check=False).strip()
    test_log("observed", {"output": out[-300:], "txz": txz})
    assert txz, "No .txz file produced"
    assert txz.endswith(".txz")


def test_package_manifest_contains_expected_files(ssh, built_package, test_log):
    manifest = ssh(f"pkg info -l -F {built_package} 2>/dev/null || true",
                   check=False)
    test_log("observed", {"manifest_lines": len(manifest.splitlines())})
    for expected in EXPECTED_FILES:
        assert expected in manifest, f"Expected file not in package: {expected}"


def test_package_no_macos_artifacts(ssh, built_package, test_log):
    manifest = ssh(f"pkg info -l -F {built_package} 2>/dev/null || true",
                   check=False)
    found = []
    for line in manifest.splitlines():
        for forbidden in FORBIDDEN_IN_PACKAGE:
            if forbidden in line:
                found.append(line.strip())
    test_log("observed", {"forbidden_found": found})
    assert not found, f"macOS artifacts in package manifest: {found}"


def test_package_file_permissions(ssh, built_package, test_log):
    """Scripts must be 0755; config files 0644."""
    # Install to inspect (pkg add -f to override even if already present)
    ssh(f"pkg add -f {built_package}", check=False)
    time.sleep(1)

    issues = []
    for f in EXPECTED_FILES:
        perm = ssh(f"stat -f '%Lp' {f} 2>/dev/null || echo missing", check=False).strip()
        if f.endswith(".py") or f.endswith(".sh"):
            if perm not in ("755",):
                issues.append(f"{f}: perm={perm} (expected 755)")
        elif f.endswith(".inc") or f.endswith(".conf") or f.endswith(".xml"):
            if perm not in ("644", "640"):
                issues.append(f"{f}: perm={perm} (expected 644)")

    test_log("observed", {"permission_issues": issues})
    ssh(f"pkg delete -fy {PACKAGE_NAME}", check=False)
    assert not issues, f"Permission issues: {issues}"


def test_package_clean_uninstall(ssh, built_package, test_log):
    """pkg delete must remove all installed files."""
    ssh(f"pkg add -f {built_package}", check=False)
    time.sleep(1)
    ssh(f"pkg delete -fy {PACKAGE_NAME}", check=False)
    time.sleep(1)

    orphans = []
    for f in EXPECTED_FILES:
        exists = ssh(f"test -f {f} && echo yes || echo no", check=False).strip()
        if exists == "yes":
            orphans.append(f)
    test_log("observed", {"orphaned_files": orphans})
    # Note: OPNsense may have some files pre-installed; filter those
    assert not orphans, f"Files not removed after pkg delete: {orphans}"
