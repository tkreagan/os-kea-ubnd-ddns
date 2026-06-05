#!/bin/sh
# build_package.sh -- Build os-kea-unbound-VERSION.txz on the OPNsense box.
#
# Does NOT require the OPNsense build tools tree (/usr/tools, /usr/plugins).
# Uses pkg(8) directly with a generated +MANIFEST.
#
# Usage (run locally — it SSHes to the OPNsense box):
#   ./build_package.sh
#
# Usage (run directly on the OPNsense box as root/sudo):
#   sh /usr/local/sbin/build_package.sh    # if deployed
#   sh build_package.sh                    # from repo root on the box
#
# Output: /tmp/os-kea-unbound-VERSION.txz
# The .txz is printed to stdout on the last line so callers can capture it.

set -e

REPO="$(cd "$(dirname "$0")" && pwd)"
SSH_USER="${OPNSENSE_SSH_USER:?OPNSENSE_SSH_USER must be set}"
HOST="${OPNSENSE_HOST:?OPNSENSE_HOST must be set}"

# ── Read version from Makefile ────────────────────────────────────────────────
VERSION=$(grep '^PLUGIN_VERSION' "$REPO/Makefile" | awk '{print $NF}')
PKGNAME="os-kea-unbound"
OUTFILE="/tmp/${PKGNAME}-${VERSION}.txz"

# ── Check if running on the box or locally ────────────────────────────────────
if [ "$(uname)" = "FreeBSD" ]; then
    # Running ON the OPNsense box — do the build directly
    _build_on_box
else
    # Running on macOS — deploy and build remotely
    _build_remotely
fi

# ── Local build function (FreeBSD only) ──────────────────────────────────────
_build_on_box() {
    STAGE=$(mktemp -d -t keaunbound-pkg)
    trap "rm -rf $STAGE" EXIT

    # Stage all source files
    mkdir -p \
        "$STAGE/usr/local/sbin" \
        "$STAGE/usr/local/opnsense/scripts/keaunbound/lib" \
        "$STAGE/usr/local/etc/inc/plugins.inc.d" \
        "$STAGE/usr/local/opnsense/service/conf/actions.d" \
        "$STAGE/usr/local/opnsense/service/templates/OPNsense/Syslog/local" \
        "$STAGE/usr/local/opnsense/mvc/app/controllers/OPNsense/Keaunbound/Api" \
        "$STAGE/usr/local/opnsense/mvc/app/models/OPNsense/Keaunbound" \
        "$STAGE/usr/local/opnsense/mvc/app/views/OPNsense/Keaunbound" \
        "$STAGE/usr/local/opnsense/mvc/app/forms"

    install -m 755 src/sbin/kea-unbound-ddns.py \
        "$STAGE/usr/local/sbin/kea-unbound-ddns.py"

    for f in start.py stop.py reservation-sync.py lease-sync.py \
              local-data-audit.py local-data-clean.py; do
        install -m 755 "src/opnsense/scripts/keaunbound/$f" \
            "$STAGE/usr/local/opnsense/scripts/keaunbound/$f"
    done
    install -m 644 src/opnsense/scripts/keaunbound/lib/__init__.py \
        "$STAGE/usr/local/opnsense/scripts/keaunbound/lib/__init__.py"
    install -m 644 src/opnsense/scripts/keaunbound/lib/keaunbound_sync.py \
        "$STAGE/usr/local/opnsense/scripts/keaunbound/lib/keaunbound_sync.py"
    install -m 644 src/opnsense/scripts/keaunbound/lib/kea_transport.py \
        "$STAGE/usr/local/opnsense/scripts/keaunbound/lib/kea_transport.py"
    install -m 644 src/etc/inc/plugins.inc.d/keaunbound.inc \
        "$STAGE/usr/local/etc/inc/plugins.inc.d/keaunbound.inc"
    install -m 644 \
        src/opnsense/service/conf/actions.d/actions_keaunbound.conf \
        "$STAGE/usr/local/opnsense/service/conf/actions.d/actions_keaunbound.conf"

    # MVC: controllers, models, views, forms
    find src/opnsense/mvc -name "*.php" -o -name "*.volt" -o -name "*.xml" | \
    while read -r f; do
        rel="${f#src/opnsense/mvc/}"
        dest="$STAGE/usr/local/opnsense/mvc/$rel"
        mkdir -p "$(dirname "$dest")"
        install -m 644 "$f" "$dest"
    done

    # Syslog template
    if [ -f src/opnsense/service/templates/OPNsense/Syslog/local/keaunbound.conf ]; then
        install -m 644 \
            src/opnsense/service/templates/OPNsense/Syslog/local/keaunbound.conf \
            "$STAGE/usr/local/opnsense/service/templates/OPNsense/Syslog/local/keaunbound.conf"
    fi

    # Verify no macOS artifacts leaked in
    BAD=$(find "$STAGE" -name ".DS_Store" -o -name "._*" -o -name "*.pyc" \
               -o -name "__pycache__" 2>/dev/null)
    if [ -n "$BAD" ]; then
        echo "ERROR: macOS artifacts in staging area:" >&2
        echo "$BAD" >&2
        exit 1
    fi

    # Build the +MANIFEST
    cat > "$STAGE/+MANIFEST" <<MANIFEST
name: ${PKGNAME}
version: ${VERSION}
origin: opnsense-plugins/${PKGNAME}
comment: Kea DHCP to Unbound DNS registration (DDNS bridge)
www: https://github.com/tkreagan/os-kea-unbound
maintainer: tk@rgn.ltd
prefix: /usr/local
desc: <<EOD
Automatically registers Kea DHCP leases and static reservations in Unbound DNS.
Runs an RFC 2136 DNS UPDATE stub listener for kea-dhcp-ddns, plus on-demand
synchronisation scripts and a scheduled stale-record cleanup.
EOD
deps: {
  py313-dnspython: {origin: "net/py-dnspython", version: "2.8"}
}
MANIFEST

    # Build the package
    pkg create -M "$STAGE/+MANIFEST" -r "$STAGE" -o /tmp/
    echo "$OUTFILE"
}

# ── Remote build via SSH ──────────────────────────────────────────────────────
_build_remotely() {
    echo "==> Building tarball..."
    COPYFILE_DISABLE=1 tar \
        --exclude='__pycache__' \
        --exclude='.DS_Store' \
        --exclude='._*' \
        --exclude='*.pyc' \
        --exclude='.git' \
        -czf /tmp/keaunbound-src.tar.gz \
        -C "$REPO" \
        Makefile pkg-descr src build_package.sh

    echo "==> Uploading to $HOST..."
    scp -o ConnectTimeout=10 /tmp/keaunbound-src.tar.gz \
        "$SSH_USER@$HOST:/tmp/"

    echo "==> Building package on $HOST..."
    ssh -o ConnectTimeout=20 "$SSH_USER@$HOST" 'sh -s' <<'REMOTE'
set -e
cd /tmp
rm -rf keaunbound-build && mkdir keaunbound-build
tar --no-xattrs --no-acls --no-fflags \
    -xzf /tmp/keaunbound-src.tar.gz -C /tmp/keaunbound-build
cd /tmp/keaunbound-build
sudo -n sh build_package.sh
REMOTE

    echo "==> Downloading package..."
    scp -o ConnectTimeout=10 \
        "$SSH_USER@$HOST:$OUTFILE" \
        "$REPO/"
    echo "Package: $REPO/$(basename "$OUTFILE")"
}
