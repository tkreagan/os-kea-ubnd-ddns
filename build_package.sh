#!/bin/sh
# build_package.sh — Build os-kea-unbound-VERSION.txz on the OPNsense box.
#
# Does NOT require the OPNsense build tools tree (/usr/tools, /usr/plugins).
# Uses pkg(8) directly with a generated +MANIFEST.
#
# Usage (run from repo root on macOS — SSHes to the OPNsense box):
#   ./build_package.sh
#
# Usage (run directly on the OPNsense box as root/sudo):
#   sh build_package.sh
#
# Output: ./os-kea-unbound-VERSION.txz  (on macOS, downloaded from the box)
#         /tmp/os-kea-unbound-VERSION.txz  (on the OPNsense box itself)
#
# Environment (read from tools/.env on macOS; not needed on FreeBSD):
#   OPNSENSE_HOST      defaults to DEV_OPNSENSE_HOST or dev-opnsense.plhm.rgn.cm
#   OPNSENSE_SSH_USER  defaults to DEV_OPNSENSE_SSH_USER or del
#   OPNSENSE_SSH_KEY   defaults to DEV_OPNSENSE_SSH_KEY or ~/.ssh/del_rgn.cm.private

set -e

REPO="$(cd "$(dirname "$0")" && pwd)"

# ── Read version from Makefile ────────────────────────────────────────────────
VERSION=$(grep '^PLUGIN_VERSION' "$REPO/Makefile" | awk '{print $NF}')
PKGNAME="os-kea-unbound"
OUTFILE_REMOTE="/tmp/${PKGNAME}-${VERSION}.txz"
OUTFILE_LOCAL="${REPO}/${PKGNAME}-${VERSION}.txz"

# ── Build on FreeBSD (OPNsense box) ──────────────────────────────────────────
_build_on_box() {
    STAGE=$(mktemp -d -t keaunbound-pkg)
    trap "rm -rf $STAGE" EXIT

    # ── Stage files ───────────────────────────────────────────────────────────
    mkdir -p \
        "$STAGE/usr/local/sbin" \
        "$STAGE/usr/local/opnsense/scripts/keaunbound/lib" \
        "$STAGE/usr/local/etc/inc/plugins.inc.d" \
        "$STAGE/usr/local/opnsense/service/conf/actions.d" \
        "$STAGE/usr/local/opnsense/service/templates/OPNsense/Syslog/local"

    install -m 755 src/sbin/kea-unbound-ddns.py \
        "$STAGE/usr/local/sbin/kea-unbound-ddns.py"
    install -m 755 src/sbin/kea-unbound-logwatch.py \
        "$STAGE/usr/local/sbin/kea-unbound-logwatch.py"

    for f in start.py stop.py kea-sync.py local-data-audit.py local-data-clean.py; do
        install -m 755 "src/opnsense/scripts/keaunbound/$f" \
            "$STAGE/usr/local/opnsense/scripts/keaunbound/$f"
    done

    for f in __init__.py keaunbound_sync.py kea_transport.py \
              consistency_sm.py pid_watch.py preconditions.py logwatch.py; do
        install -m 644 "src/opnsense/scripts/keaunbound/lib/$f" \
            "$STAGE/usr/local/opnsense/scripts/keaunbound/lib/$f"
    done

    install -m 644 src/etc/inc/plugins.inc.d/keaunbound.inc \
        "$STAGE/usr/local/etc/inc/plugins.inc.d/keaunbound.inc"
    install -m 644 \
        src/opnsense/service/conf/actions.d/actions_keaunbound.conf \
        "$STAGE/usr/local/opnsense/service/conf/actions.d/actions_keaunbound.conf"
    install -m 644 \
        src/opnsense/service/templates/OPNsense/Syslog/local/keaunbound.conf \
        "$STAGE/usr/local/opnsense/service/templates/OPNsense/Syslog/local/keaunbound.conf"

    # MVC: controllers, models, views, forms
    find src/opnsense/mvc -name "*.php" -o -name "*.volt" -o -name "*.xml" | \
    while read -r f; do
        rel="${f#src/opnsense/mvc/}"
        dest="$STAGE/usr/local/opnsense/mvc/$rel"
        mkdir -p "$(dirname "$dest")"
        install -m 644 "$f" "$dest"
    done

    # ── Verify no macOS artifacts in staging area ─────────────────────────────
    BAD=$(find "$STAGE" \( -name ".DS_Store" -o -name "._*" -o -name "*.pyc" \
               -o -name "__pycache__" \) 2>/dev/null || true)
    if [ -n "$BAD" ]; then
        echo "ERROR: macOS artifacts in staging area:" >&2
        echo "$BAD" >&2
        exit 1
    fi

    # ── Build +MANIFEST ───────────────────────────────────────────────────────
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

    # ── Build package ─────────────────────────────────────────────────────────
    pkg create -M "$STAGE/+MANIFEST" -r "$STAGE" -o /tmp/

    # ── Verify package contents ───────────────────────────────────────────────
    echo "==> Verifying package contents..."
    BAD_ENTRIES=$(pkg info -l -F "$OUTFILE_REMOTE" 2>/dev/null \
        | grep -E '\._|\.DS_Store|__pycache__|/tools/|/tests/|/\.git/' || true)
    if [ -n "$BAD_ENTRIES" ]; then
        echo "ERROR: Unexpected entries in package:" >&2
        echo "$BAD_ENTRIES" >&2
        exit 1
    fi
    echo "    Package contents: OK"
    echo "$OUTFILE_REMOTE"
}

# ── Build remotely from macOS ─────────────────────────────────────────────────
_build_remotely() {
    # Load .env for SSH credentials (env vars take precedence over .env values)
    _ENV_FILE="${REPO}/tools/.env"
    if [ -f "$_ENV_FILE" ]; then
        # POSIX sh compatible .env loader
        while IFS= read -r _line; do
            _line="${_line%%#*}"
            case "$_line" in *=*) ;; *) continue ;; esac
            _key="${_line%%=*}"
            _val="${_line#*=}"
            # Only export if not already set in environment
            eval "[ -z \"\${${_key}+x}\" ] && export ${_key}=\"${_val}\"" 2>/dev/null || true
        done < "$_ENV_FILE"
    fi

    HOST="${OPNSENSE_HOST:-${DEV_OPNSENSE_HOST:-dev-opnsense.plhm.rgn.cm}}"
    SSH_USER="${OPNSENSE_SSH_USER:-${DEV_OPNSENSE_SSH_USER:-del}}"
    SSH_KEY="${OPNSENSE_SSH_KEY:-${DEV_OPNSENSE_SSH_KEY:-$HOME/.ssh/del_rgn.cm.private}}"
    # Expand leading tilde
    SSH_KEY=$(echo "$SSH_KEY" | sed "s|^~|$HOME|")
    SSH_OPTS="-i $SSH_KEY -o StrictHostKeyChecking=no -o ConnectTimeout=10 \
-o PreferredAuthentications=publickey -o PubkeyAuthentication=yes \
-o IdentityAgent=none -o BatchMode=yes"
    REMOTE="${SSH_USER}@${HOST}"

    echo "==> Building source tarball..."
    # Exclude macOS artifacts and dev/test tooling — only ship src/ and build files
    COPYFILE_DISABLE=1 tar \
        --exclude='__pycache__' \
        --exclude='.DS_Store' \
        --exclude='._*' \
        --exclude='*.pyc' \
        --exclude='.git' \
        -czf /tmp/keaunbound-build.tar.gz \
        -C "$REPO" \
        Makefile pkg-descr src build_package.sh

    echo "==> Uploading to ${HOST}..."
    SSH_AUTH_SOCK="" scp $SSH_OPTS /tmp/keaunbound-build.tar.gz "${REMOTE}:/tmp/"

    echo "==> Building package on ${HOST}..."
    # shellcheck disable=SC2087
    SSH_AUTH_SOCK="" ssh $SSH_OPTS "$REMOTE" 'sh -s' << 'REMOTE_HEREDOC'
set -e
cd /tmp
rm -rf keaunbound-build && mkdir keaunbound-build
tar --no-xattrs --no-acls --no-fflags \
    -xzf /tmp/keaunbound-build.tar.gz -C /tmp/keaunbound-build
cd /tmp/keaunbound-build
sudo -n sh build_package.sh
rm -rf /tmp/keaunbound-build /tmp/keaunbound-build.tar.gz
REMOTE_HEREDOC

    echo "==> Downloading package..."
    SSH_AUTH_SOCK="" scp $SSH_OPTS "${REMOTE}:${OUTFILE_REMOTE}" "$OUTFILE_LOCAL"
    echo "Package: ${OUTFILE_LOCAL}"
}

# ── Dispatch ──────────────────────────────────────────────────────────────────
if [ "$(uname)" = "FreeBSD" ]; then
    _build_on_box
else
    _build_remotely
fi
