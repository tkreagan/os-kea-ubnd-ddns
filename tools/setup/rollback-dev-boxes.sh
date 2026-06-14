#!/usr/bin/env bash
# rollback-dev-boxes.sh — Roll back both dev VMs to a snapshot.
# Calls rollback-vm.sh for each VM sequentially.
#
# Usage:
#   bash tools/setup/rollback-dev-boxes.sh              # interactive snapshot picker
#   bash tools/setup/rollback-dev-boxes.sh --latest     # each VM's newest snapshot
#   bash tools/setup/rollback-dev-boxes.sh SNAPNAME     # specific snapshot by name
#
# To roll back only one VM use rollback-vm.sh directly:
#   bash tools/setup/rollback-vm.sh 113 dev-opnsense.plhm.rgn.cm --latest
#
# Environment (read from tools/.env):
#   PROXMOX_HOST, PROXMOX_API_TOKEN, PROXMOX_NODE
#   PROXMOX_VM_DEV_OPNSENSE, PROXMOX_VM_DEV_DHCPCLIENT
#   DEV_OPNSENSE_HOST, DEV_DHCPCLIENT_HOST

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# ── Load .env ─────────────────────────────────────────────────────────────────
ENV_FILE="${ENV_FILE:-tools/.env}"
if [[ -f "$ENV_FILE" ]]; then
    while IFS= read -r _line; do
        _line="${_line%%#*}"
        _line="${_line#"${_line%%[![:space:]]*}"}"
        [[ -z "$_line" || "$_line" != *=* ]] && continue
        _key="${_line%%=*}"
        _val="${_line#*=}"
        _val="${_val%\"}" ; _val="${_val#\"}"
        _val="${_val%"${_val##*[^[:space:]]}"}"
        export "${_key}=${_val}" 2>/dev/null || true
    done < "$ENV_FILE"
fi

VM_OPN="${PROXMOX_VM_DEV_OPNSENSE:-113}"
VM_CLI="${PROXMOX_VM_DEV_DHCPCLIENT:-114}"
OPN_HOST="${DEV_OPNSENSE_HOST:-dev-opnsense.plhm.rgn.cm}"
CLI_HOST="${DEV_DHCPCLIENT_HOST:-dev-dhcpclient.plhm.rgn.cm}"

die() { echo "ERROR: $*" >&2; exit 1; }

# ── Argument parsing ───────────────────────────────────────────────────────────
MODE="interactive"
SNAPNAME=""

for arg in "$@"; do
    case "$arg" in
        --latest) MODE="latest" ;;
        --help|-h)
            sed -n '/^#/!q; s/^# \?//p' "$0" | head -14
            exit 0 ;;
        -*) die "Unknown flag: $arg" ;;
        *) SNAPNAME="$arg"; MODE="named" ;;
    esac
done

# ── Snapshot selection ────────────────────────────────────────────────────────
# In --latest mode: each VM picks its own newest snapshot via rollback-vm.sh.
# In named/interactive mode: resolve a single snapshot name using opnsense's list,
# then apply the same name to both VMs.

SNAP_OPN=""
SNAP_CLI=""

if [[ "$MODE" == "latest" ]]; then
    SNAP_OPN="--latest"
    SNAP_CLI="--latest"
elif [[ "$MODE" == "named" ]]; then
    SNAP_OPN="$SNAPNAME"
    SNAP_CLI="$SNAPNAME"
else
    # Interactive: query opnsense's snapshot list and let the user pick one name
    # to apply to both VMs.
    PVE_HOST="${PROXMOX_HOST:-bnl.plhm.rgn.cm}"
    PVE_TOKEN="${PROXMOX_API_TOKEN:?Need PROXMOX_API_TOKEN in tools/.env}"
    PVE_NODE="${PROXMOX_NODE:-bnl}"

    pve_get() {
        SSH_AUTH_SOCK="" curl -sf -k -X GET \
            -H "Authorization: PVEAPIToken=${PVE_TOKEN}" \
            "https://${PVE_HOST}:8006/api2/json/nodes/${PVE_NODE}/${1}"
    }

    echo
    echo "==> Querying snapshots for dev-opnsense (VM ${VM_OPN})"
    SNAP_LINES=$(pve_get "qemu/${VM_OPN}/snapshot" | python3 -c "
import json, sys, datetime
snaps = json.load(sys.stdin)['data']
snaps = [s for s in snaps if s.get('name') != 'current' and s.get('snaptime')]
snaps.sort(key=lambda s: s['snaptime'], reverse=True)
for i, s in enumerate(snaps, 1):
    ts = datetime.datetime.fromtimestamp(s['snaptime']).strftime('%Y-%m-%d %H:%M')
    desc = s.get('description', '').replace('\n', ' ')[:40]
    marker = '  [default]' if i == 1 else ''
    print(f'{i}\t{s[\"name\"]}\t{ts}\t{desc}{marker}')
")
    [[ -z "$SNAP_LINES" ]] && die "No snapshots found for VM ${VM_OPN}"

    echo
    echo "  #  Name                  Date              Description"
    echo "  ─────────────────────────────────────────────────────────────"
    while IFS=$'\t' read -r idx name ts desc; do
        printf "  %-3s  %-22s  %-16s  %s\n" "$idx" "$name" "$ts" "$desc"
    done <<< "$SNAP_LINES"
    echo

    DEFAULT_SNAP=$(echo "$SNAP_LINES" | head -1 | cut -f2)
    printf "  Select snapshot [%s]: " "$DEFAULT_SNAP"
    read -r CHOICE
    if [[ -z "$CHOICE" ]]; then
        SNAPNAME="$DEFAULT_SNAP"
    elif echo "$SNAP_LINES" | cut -f1 | grep -qx "$CHOICE"; then
        SNAPNAME=$(echo "$SNAP_LINES" | awk -F'\t' -v n="$CHOICE" '$1==n{print $2}')
    elif echo "$SNAP_LINES" | cut -f2 | grep -qx "$CHOICE"; then
        SNAPNAME="$CHOICE"
    else
        die "Invalid selection: ${CHOICE}"
    fi
    echo "    Selected: ${SNAPNAME}"

    SNAP_OPN="$SNAPNAME"
    SNAP_CLI="$SNAPNAME"
fi

echo
echo "============================================================"
echo "  dev-opnsense   (VM ${VM_OPN}) → ${OPN_HOST}  [${SNAP_OPN}]"
echo "  dev-dhcpclient (VM ${VM_CLI}) → ${CLI_HOST}  [${SNAP_CLI}]"
echo "============================================================"

START_TIME=$(date +%s)

# ── Rollback each VM ──────────────────────────────────────────────────────────
ENV_FILE="$ENV_FILE" bash "$SCRIPT_DIR/rollback-vm.sh" "$VM_OPN" "$OPN_HOST" "$SNAP_OPN"
ENV_FILE="$ENV_FILE" bash "$SCRIPT_DIR/rollback-vm.sh" "$VM_CLI" "$CLI_HOST" "$SNAP_CLI"

ELAPSED=$(( $(date +%s) - START_TIME ))
echo
echo "============================================================"
printf "Done. Both VMs rolled back. (%ds)\n" "$ELAPSED"
echo
echo "Next steps:"
echo "  bash tools/setup/install-plugin.sh"
echo "  bash tools/setup/configure-chaos-env.sh"
echo "  python3 tools/chaos_monkey.py --setup-only"
echo "============================================================"
