# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Thomas Reagan
"""
Integration tests — package build and installation.

Builds os-kea-unbound-*.pkg on the dev box using the opnsense/plugins
make(1) toolchain (make package / make upgrade), then inspects the result.

Checks three distinct surfaces for macOS artifact contamination:
  1. The source tree on disk before packaging (._* files, xattrs)
  2. The package file list / manifest after `make package`
  3. The installed filesystem after `make upgrade`

Run with: pytest -m packaging
"""

from __future__ import annotations

import pytest

pytestmark = [pytest.mark.integration, pytest.mark.packaging]

PACKAGE_NAME = "os-kea-unbound"
PLUGIN_DIR = "/usr/plugins/net/kea-unbound"
PKG_GLOB = f"{PLUGIN_DIR}/work/pkg/{PACKAGE_NAME}-*.pkg"

# Every file that must appear in the installed package.
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
    "/usr/local/opnsense/service/templates/OPNsense/Syslog/local/keaunbound.conf",
    "/usr/local/opnsense/mvc/app/models/OPNsense/KeaUnbound/General.xml",
    "/usr/local/opnsense/mvc/app/models/OPNsense/KeaUnbound/General.php",
    "/usr/local/opnsense/mvc/app/models/OPNsense/KeaUnbound/ACL/ACL.xml",
    "/usr/local/opnsense/mvc/app/models/OPNsense/KeaUnbound/Menu/Menu.xml",
    "/usr/local/opnsense/version/kea-unbound",
]

# Patterns that must never appear in any package file path or on disk.
MACOS_ARTIFACT_PATTERNS = [
    "._",        # AppleDouble sidecar files/dirs (._General.xml, ._OPNsense, etc.)
    ".DS_Store", # macOS directory metadata
    "__pycache__",
    ".pyc",
]


# ── Fixtures ────────────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def built_pkg(ssh):
    """Run `make package` on the dev box; yield the .pkg path."""
    ssh(f"cd {PLUGIN_DIR} && sudo make clean 2>/dev/null; sudo make package", check=True)
    pkg = ssh(f"ls {PKG_GLOB} 2>/dev/null | tail -1", check=False).strip()
    if not pkg:
        pytest.fail("make package produced no .pkg file")
    yield pkg


@pytest.fixture(scope="module")
def installed_pkg(ssh, built_pkg):
    """Install the package with `make upgrade`; yield; remove after tests."""
    ssh(f"cd {PLUGIN_DIR} && sudo make upgrade", check=True)
    yield
    ssh(f"sudo pkg delete -fy {PACKAGE_NAME}", check=False)


# ── Surface 1: source tree on the dev box ───────────────────────────────────

class TestSourceTree:
    """The src/ tree that will be packaged must be free of macOS artifacts."""

    def test_no_appledouble_sidecars_in_src(self, ssh, test_log):
        """No ._* files anywhere under src/."""
        found = ssh(
            f"find {PLUGIN_DIR}/src -name '._*' 2>/dev/null",
            check=False,
        ).strip()
        test_log("observed", {"found": found})
        assert not found, (
            f"AppleDouble sidecar files in src/: {found}\n"
            "Fix: re-upload with COPYFILE_DISABLE=1 tar"
        )

    def test_no_pycache_in_src(self, ssh, test_log):
        """No __pycache__ or .pyc files in src/."""
        found = ssh(
            f"find {PLUGIN_DIR}/src -name '__pycache__' -o -name '*.pyc' 2>/dev/null",
            check=False,
        ).strip()
        test_log("observed", {"found": found})
        assert not found, f"Compiled Python artifacts in src/: {found}"

    def test_no_ds_store_in_src(self, ssh, test_log):
        """No .DS_Store files in src/."""
        found = ssh(
            f"find {PLUGIN_DIR}/src -name '.DS_Store' 2>/dev/null",
            check=False,
        ).strip()
        test_log("observed", {"found": found})
        assert not found, f".DS_Store files in src/: {found}"

    def test_model_xml_files_have_correct_names(self, ssh, test_log):
        """
        Every .xml file in the models tree must have a plain filename (no leading ._).
        This is the specific failure mode: OPNsense's ConfigMaintenance::loadModels()
        scans for *.xml and derives PHP class names from filenames — ._General.xml
        causes it to try to instantiate OPNsense\\KeaUnbound\\._General which doesn't
        exist and crashes the MVC framework.
        """
        xml_files = ssh(
            f"find {PLUGIN_DIR}/src/opnsense/mvc/app/models -name '*.xml' 2>/dev/null",
            check=False,
        ).strip().splitlines()
        bad = [f for f in xml_files if "/._" in f or f.rsplit("/", 1)[-1].startswith("._")]
        test_log("observed", {"xml_files": xml_files, "bad": bad})
        assert not bad, (
            f"Model XML files with AppleDouble-style names: {bad}\n"
            "These will crash OPNsense's ConfigMaintenance::loadModels()"
        )


# ── Surface 2: the .pkg file manifest ───────────────────────────────────────

class TestPackageManifest:
    """The built .pkg must contain the right files and no macOS artifacts."""

    def test_package_builds(self, built_pkg, test_log):
        test_log("observed", {"pkg": built_pkg})
        assert built_pkg.endswith(".pkg")
        assert PACKAGE_NAME in built_pkg

    def test_package_name_is_stable_not_devel(self, built_pkg, test_log):
        """Package must be os-kea-unbound-VERSION.pkg, not os-kea-unbound-devel-*."""
        basename = built_pkg.rsplit("/", 1)[-1]
        test_log("observed", {"basename": basename})
        assert "-devel" not in basename, (
            "Package built in devel mode — check that Mk/devel.mk is absent from "
            "the /usr/plugins/Mk/ directory on the build host"
        )

    def test_package_is_arch_independent(self, ssh, built_pkg, test_log):
        """PLUGIN_NO_ABI=yes must produce FreeBSD:*:* not a locked arch."""
        arch = ssh(
            f"pkg info -F {built_pkg} | grep Architecture", check=False
        ).strip()
        test_log("observed", {"arch": arch})
        assert "FreeBSD:*:*" in arch, (
            f"Package is arch-locked: {arch} — add PLUGIN_NO_ABI=yes to Makefile"
        )

    def test_package_contains_expected_files(self, ssh, built_pkg, test_log):
        """All required files appear in the package plist."""
        plist = ssh(
            f"pkg query -F {built_pkg} '%Fp'", check=False
        ).strip()
        missing = [f for f in EXPECTED_FILES if f not in plist]
        test_log("observed", {"missing": missing})
        assert not missing, f"Files missing from package: {missing}"

    def test_package_has_no_macos_artifacts(self, ssh, built_pkg, test_log):
        """
        No AppleDouble sidecars, .DS_Store, __pycache__, or .pyc in the plist.
        This catches contamination that slipped through the tar upload.
        """
        plist = ssh(
            f"pkg query -F {built_pkg} '%Fp'", check=False
        ).strip()
        found = []
        for line in plist.splitlines():
            for pattern in MACOS_ARTIFACT_PATTERNS:
                if pattern in line:
                    found.append(line.strip())
                    break
        test_log("observed", {"found": found})
        assert not found, (
            f"macOS artifacts in package plist: {found}\n"
            "Fix: re-upload src/ using COPYFILE_DISABLE=1 tar"
        )

    def test_package_tier_is_community(self, ssh, built_pkg, test_log):
        """Version annotation must show tier=3 (community), not tier=4 (devel)."""
        info = ssh(f"pkg info -F {built_pkg}", check=False)
        test_log("observed", {"info_snippet": info[-500:]})
        assert "product_tier   : 3" in info, (
            "Package is tier 4 (devel) — remove Mk/devel.mk from build host"
        )

    def test_package_post_install_script_exists(self, ssh, test_log):
        """Auto-generated +POST_INSTALL must restart configd and run migrations."""
        script = ssh(
            f"cat {PLUGIN_DIR}/work/src/+POST_INSTALL 2>/dev/null", check=False
        ).strip()
        test_log("observed", {"script": script})
        assert "configd" in script, "+POST_INSTALL missing configd restart"
        assert "run_migrations" in script, "+POST_INSTALL missing model migration"
        assert "rc.configure_plugins" in script, "+POST_INSTALL missing configure hooks"


# ── Surface 3: the installed filesystem ─────────────────────────────────────

class TestInstalledFiles:
    """After `make upgrade`, the live filesystem must be clean."""

    def test_all_expected_files_present(self, ssh, installed_pkg, test_log):
        missing = []
        for f in EXPECTED_FILES:
            result = ssh(f"test -f {f} && echo yes || echo no", check=False).strip()
            if result != "yes":
                missing.append(f)
        test_log("observed", {"missing": missing})
        assert not missing, f"Expected files not on disk after install: {missing}"

    def test_no_appledouble_sidecars_installed(self, ssh, installed_pkg, test_log):
        """
        No ._* files anywhere under the paths our plugin touches.
        This is the exact failure mode reported: ._General.xml causes
        OPNsense to try to instantiate a non-existent PHP class and crash.
        """
        paths_to_check = [
            "/usr/local/opnsense/mvc/app/models/OPNsense/KeaUnbound",
            "/usr/local/opnsense/mvc/app/controllers/OPNsense/KeaUnbound",
            "/usr/local/opnsense/mvc/app/views/OPNsense/KeaUnbound",
            "/usr/local/opnsense/scripts/keaunbound",
            "/usr/local/sbin",
            "/usr/local/etc/inc/plugins.inc.d",
            "/usr/local/opnsense/service/conf/actions.d",
        ]
        found = []
        for path in paths_to_check:
            result = ssh(
                f"find {path} -name '._*' 2>/dev/null", check=False
            ).strip()
            if result:
                found.extend(result.splitlines())
        test_log("observed", {"found": found})
        assert not found, (
            f"AppleDouble sidecar files present after install: {found}\n"
            "These will cause OPNsense MVC framework errors."
        )

    def test_no_pycache_installed(self, ssh, installed_pkg, test_log):
        found = ssh(
            "find /usr/local/opnsense/scripts/keaunbound "
            "-name '__pycache__' -o -name '*.pyc' 2>/dev/null",
            check=False,
        ).strip()
        test_log("observed", {"found": found})
        assert not found, f"Compiled Python artifacts installed: {found}"

    def test_pkg_registered(self, ssh, installed_pkg, test_log):
        """pkg(8) must know about the package (not just raw-copied files)."""
        info = ssh(f"pkg info {PACKAGE_NAME}", check=False).strip()
        test_log("observed", {"info_first_line": info.splitlines()[0] if info else ""})
        assert PACKAGE_NAME in info, "Package not registered with pkg(8)"

    def test_configd_actions_registered(self, ssh, installed_pkg, test_log):
        """All 7 configd actions must be present after install."""
        actions = ssh(
            "sudo /usr/local/sbin/configctl configd actions 2>/dev/null | grep keaunbound",
            check=False,
        ).strip()
        test_log("observed", {"actions": actions})
        expected_actions = [
            "keaunbound start",
            "keaunbound stop",
            "keaunbound restart",
            "keaunbound status",
            "keaunbound sync_static",
            "keaunbound sync_dynamic",
            "keaunbound clean",
        ]
        missing = [a for a in expected_actions if a not in actions]
        assert not missing, f"configd actions not registered after install: {missing}"

    def test_script_permissions(self, ssh, installed_pkg, test_log):
        """Executable scripts must be 0755; data files 0644."""
        issues = []
        checks = [
            ("/usr/local/sbin/kea-unbound-ddns.py", "755"),
            ("/usr/local/opnsense/scripts/keaunbound/start.py", "755"),
            ("/usr/local/opnsense/scripts/keaunbound/lease-sync.py", "755"),
            ("/usr/local/opnsense/scripts/keaunbound/local-data-audit.py", "755"),
            ("/usr/local/opnsense/scripts/keaunbound/local-data-clean.py", "755"),
            ("/usr/local/etc/inc/plugins.inc.d/keaunbound.inc", "644"),
            ("/usr/local/opnsense/service/conf/actions.d/actions_keaunbound.conf", "644"),
            ("/usr/local/opnsense/mvc/app/models/OPNsense/KeaUnbound/General.xml", "644"),
        ]
        for path, expected_perm in checks:
            perm = ssh(f"stat -f '%Lp' {path} 2>/dev/null || echo missing", check=False).strip()
            if perm != expected_perm:
                issues.append(f"{path}: got {perm!r}, want {expected_perm!r}")
        test_log("observed", {"issues": issues})
        assert not issues, f"Permission issues after install: {issues}"

    def test_clean_uninstall(self, ssh, test_log):
        """pkg delete must remove all plugin files; no orphans left behind."""
        ssh(f"sudo pkg delete -fy {PACKAGE_NAME}", check=False)
        orphans = []
        # Check a representative sample — not every OPNsense-framework path
        plugin_only_files = [
            "/usr/local/sbin/kea-unbound-ddns.py",
            "/usr/local/opnsense/scripts/keaunbound/start.py",
            "/usr/local/etc/inc/plugins.inc.d/keaunbound.inc",
            "/usr/local/opnsense/service/conf/actions.d/actions_keaunbound.conf",
            "/usr/local/opnsense/version/kea-unbound",
        ]
        for f in plugin_only_files:
            exists = ssh(f"test -f {f} && echo yes || echo no", check=False).strip()
            if exists == "yes":
                orphans.append(f)
        test_log("observed", {"orphans": orphans})
        assert not orphans, f"Files not removed after pkg delete: {orphans}"
