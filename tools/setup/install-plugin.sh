#!/usr/bin/env bash
# install-plugin.sh — Build os-kea-unbound from the local repo and install on
# dev-opnsense.  Run from the repo root on macOS after any source change.
# Does NOT touch configuration — run configure-chaos-env.sh once for that.
#
# Two install strategies (auto-detected):
#   make upgrade  — used when /usr/plugins/Mk/plugins.mk exists (dev build tree)
#   direct copy   — copies src/ → /usr/local/ directly; no pkg registration needed
#
# Usage: sh tools/setup/install-plugin.sh [HOST]
#   HOST defaults to dev-opnsense.plhm.rgn.cm
set -euo pipefail

OPNSENSE_HOST="${1:-dev-opnsense.plhm.rgn.cm}"
SSH_USER="${DEV_SSH_USER:-del}"
SSH_KEY="${DEV_SSH_KEY:-$HOME/.ssh/del_rgn.cm.private}"
SSH_OPTS="-i $SSH_KEY -o StrictHostKeyChecking=no -o PreferredAuthentications=publickey -o PubkeyAuthentication=yes -o IdentityAgent=none -o BatchMode=yes"
REMOTE="$SSH_USER@$OPNSENSE_HOST"

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"

step() { echo; echo "==> $*"; }
die()  { echo "ERROR: $*" >&2; exit 1; }

# ── 1. Build source tarball locally ───────────────────────────────────────────
step "Building source tarball"
TMP_TAR="$(mktemp /tmp/keaunbound-src-XXXXXX.tar.gz)"
trap 'rm -f "$TMP_TAR"' EXIT
COPYFILE_DISABLE=1 tar \
    --exclude='__pycache__' --exclude='.DS_Store' \
    --exclude='._*'         --exclude='*.pyc' \
    -czf "$TMP_TAR" -C "$REPO_ROOT/src" .
echo "  $(du -sh "$TMP_TAR" | cut -f1)  $TMP_TAR"

# ── 2. Upload source tarball ───────────────────────────────────────────────────
step "Uploading to $OPNSENSE_HOST"
SSH_AUTH_SOCK="" scp $SSH_OPTS "$TMP_TAR" "$REMOTE:/tmp/keaunbound-src.tar.gz"

# ── 3. Detect install strategy and install ────────────────────────────────────
step "Installing"
# shellcheck disable=SC2087
SSH_AUTH_SOCK="" ssh $SSH_OPTS "$REMOTE" sh -s << 'REMOTE_EOF'
set -e
sudo sh -c '
    PLUGIN_DIR=/usr/plugins/net/kea-unbound
    MK_FILE=/usr/plugins/Mk/plugins.mk

    if [ -f "$MK_FILE" ]; then
        echo "  Strategy: make upgrade (Mk infrastructure present)"

        # Create plugin build tree if missing
        if [ ! -d "$PLUGIN_DIR" ]; then
            echo "  Creating build tree at $PLUGIN_DIR..."
            mkdir -p "$PLUGIN_DIR/src"
        fi

        tar --no-xattrs --no-acls --no-fflags \
            -xzf /tmp/keaunbound-src.tar.gz -C "$PLUGIN_DIR/src"
        cd "$PLUGIN_DIR"
        make upgrade
    else
        echo "  Strategy: direct file install (no Mk infrastructure)"

        tar --no-xattrs --no-acls --no-fflags \
            -xzf /tmp/keaunbound-src.tar.gz -C /usr/local/

        # Ensure scripts are executable
        chmod 755 /usr/local/sbin/kea-unbound-ddns.py
        find /usr/local/opnsense/scripts/keaunbound -name "*.py" -exec chmod 755 {} \;

        # Register configd actions (restart configd to pick them up)
        echo "  Restarting configd to register new actions..."
        service configd restart
        sleep 3
    fi

    rm -f /tmp/keaunbound-src.tar.gz
'
REMOTE_EOF

# ── 4. Restart services ────────────────────────────────────────────────────────
step "Restarting kea and keaunbound"
# shellcheck disable=SC2087
SSH_AUTH_SOCK="" ssh $SSH_OPTS "$REMOTE" sh -s << 'REMOTE_EOF'
sudo sh -c '
    /usr/local/sbin/configctl kea restart
    sleep 4
    /usr/local/sbin/configctl keaunbound restart
    sleep 3
    echo
    echo "  kea status:"
    /usr/local/sbin/configctl kea status 2>&1 | head -4 || true
    echo "  plugin status:"
    /usr/local/sbin/pluginctl -s kea-unbound-ddns status 2>&1 || true
'
REMOTE_EOF

step "Done."
