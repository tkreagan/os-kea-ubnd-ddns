#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-2-Clause
#
# setup-chaos-boxes.sh — prepare dev-opnsense and dev-dhcpclient for chaos monkey
#
# Run this after rolling back either box to a pre-chaos-monkey snapshot.
# Idempotent: safe to run on already-configured boxes.
#
# Prerequisites on the Mac running this script:
#   - SSH key ~/.ssh/del_rgn.cm.private installed on both boxes for user 'del'
#   - Both boxes reachable by hostname (dev-opnsense.plhm.rgn.cm, dev-dhcpclient.plhm.rgn.cm)
#   - sshpass available if fallback to password auth is needed (brew install sshpass)
#   - python3 + paramiko available (pip3 install paramiko)
#
# Usage:
#   cd <repo-root>
#   bash tools/setup-chaos-boxes.sh [--opnsense-only] [--dhcpclient-only]

set -euo pipefail

OPNSENSE_HOST="dev-opnsense.plhm.rgn.cm"
DHCPCLIENT_HOST="dev-dhcpclient.plhm.rgn.cm"
SSH_USER="del"
SSH_KEY="${HOME}/.ssh/del_rgn.cm.private"
SSH_OPTS="-i ${SSH_KEY} -o StrictHostKeyChecking=no -o ConnectTimeout=10 -o BatchMode=yes"

SETUP_OPNSENSE=true
SETUP_DHCPCLIENT=true

for arg in "$@"; do
    case "$arg" in
        --opnsense-only)   SETUP_DHCPCLIENT=false ;;
        --dhcpclient-only) SETUP_OPNSENSE=false ;;
        --help|-h)
            echo "Usage: $0 [--opnsense-only] [--dhcpclient-only]"
            exit 0
            ;;
    esac
done

# ─── helpers ────────────────────────────────────────────────────────────────

run_ssh() {
    local host="$1"; shift
    ssh ${SSH_OPTS} "${SSH_USER}@${host}" "$@"
}

run_sudo() {
    local host="$1"; shift
    # 'del' has NOPASSWD sudo; -n prevents hanging on a password prompt
    run_ssh "$host" sudo -n sh -c "$*"
}

check_key_auth() {
    local host="$1"
    if ssh ${SSH_OPTS} "${SSH_USER}@${host}" true 2>/dev/null; then
        return 0
    fi
    echo "[ERROR] Key auth failed for ${SSH_USER}@${host}"
    echo "        Ensure ~/.ssh/del_rgn.cm.private is authorised on ${host}."
    echo "        If the box was just restored from a pre-key snapshot, install the key first:"
    echo "          ssh-copy-id -i ~/.ssh/del_rgn.cm.private.pub ${SSH_USER}@${host}"
    return 1
}

# ─── dev-dhcpclient setup ───────────────────────────────────────────────────

setup_dhcpclient() {
    echo ""
    echo "=== Setting up ${DHCPCLIENT_HOST} ==="

    check_key_auth "${DHCPCLIENT_HOST}"

    # 1. Install isc-dhcp-client if missing
    echo "  [1/2] Checking isc-dhcp-client..."
    if run_ssh "${DHCPCLIENT_HOST}" command -v dhclient >/dev/null 2>&1; then
        echo "        dhclient already installed ($(run_ssh "${DHCPCLIENT_HOST}" dhclient --version 2>&1 | head -1))"
    else
        echo "        Installing isc-dhcp-client..."
        run_sudo "${DHCPCLIENT_HOST}" "apt-get update -qq && apt-get install -y isc-dhcp-client"
        echo "        Installed: $(run_ssh "${DHCPCLIENT_HOST}" dhclient --version 2>&1 | head -1)"
    fi

    # 2. Bring the LAN interface (ens19) up
    # The interface is not managed by systemd-networkd on this box; bring it up
    # manually and persist via a small networkd .network file so it survives reboot.
    echo "  [2/2] Ensuring ens19 is up..."
    LAN_IF="ens19"
    IF_STATE=$(run_ssh "${DHCPCLIENT_HOST}" "ip link show ${LAN_IF} 2>/dev/null | grep -o 'state [A-Z]*' || echo 'state MISSING'")
    echo "        Current state: ${IF_STATE}"

    if echo "${IF_STATE}" | grep -qE 'state (UP|UNKNOWN)'; then
        echo "        Interface already up."
    else
        run_sudo "${DHCPCLIENT_HOST}" "ip link set ${LAN_IF} up"
        echo "        Brought up."
    fi

    # Persist with a minimal networkd file (unmanaged → no auto-DHCP by networkd,
    # just keeps the link up so dhclient can use it for scenarios)
    NETWORKD_CONF="/etc/systemd/network/10-chaos-${LAN_IF}.network"
    if run_ssh "${DHCPCLIENT_HOST}" "test -f ${NETWORKD_CONF}" 2>/dev/null; then
        echo "        networkd config already present at ${NETWORKD_CONF}"
    else
        echo "        Writing ${NETWORKD_CONF} to keep ${LAN_IF} up on reboot..."
        CONF_CONTENT="[Match]
Name=${LAN_IF}

[Link]
RequiredForOnline=no

[Network]
DHCP=no
LinkLocalAddressing=no
"
        run_ssh "${DHCPCLIENT_HOST}" "sudo -n tee ${NETWORKD_CONF} > /dev/null" <<< "${CONF_CONTENT}"
        run_sudo "${DHCPCLIENT_HOST}" "systemctl restart systemd-networkd || true"
        run_sudo "${DHCPCLIENT_HOST}" "ip link set ${LAN_IF} up || true"
    fi

    echo "  dev-dhcpclient ready."
}

# ─── dev-opnsense setup ─────────────────────────────────────────────────────

setup_opnsense() {
    echo ""
    echo "=== Setting up ${OPNSENSE_HOST} ==="

    check_key_auth "${OPNSENSE_HOST}"

    echo "  [1/1] Running configure-chaos-env.sh --opnsense-only..."
    bash tools/setup/configure-chaos-env.sh --opnsense-only
    echo "  dev-opnsense ready."
}

# ─── main ───────────────────────────────────────────────────────────────────

echo "Chaos monkey box setup"
echo "  opnsense:   ${OPNSENSE_HOST}"
echo "  dhcpclient: ${DHCPCLIENT_HOST}"
echo "  SSH key:    ${SSH_KEY}"

if [[ ! -f "${SSH_KEY}" ]]; then
    echo ""
    echo "[ERROR] SSH key not found: ${SSH_KEY}"
    exit 1
fi

if $SETUP_DHCPCLIENT; then
    setup_dhcpclient
fi

if $SETUP_OPNSENSE; then
    setup_opnsense
fi

echo ""
echo "Both boxes configured. Verify with:"
echo "  python3 tools/chaos_monkey.py --setup-only"
echo ""
echo "Then run all scenarios:"
echo "  python3 tools/chaos_monkey.py --all"
