#!/usr/bin/env bash
# rollback-vm.sh — Stop, roll back to a snapshot, and restart a single Proxmox VM.
#
# Usage:
#   bash tools/setup/rollback-vm.sh VMID HOSTNAME [--latest | SNAPNAME]
#
#   VMID      Proxmox VM ID (e.g. 113)
#   HOSTNAME  SSH hostname to poll after start (e.g. dev-opnsense.plhm.rgn.cm)
#   --latest  Automatically select the most recent snapshot
#   SNAPNAME  Roll back to this specific snapshot by name
#   (none)    Interactive: show a snapshot menu and prompt
#
# Environment (read from tools/.env):
#   PROXMOX_HOST, PROXMOX_API_TOKEN, PROXMOX_NODE
#   DEV_OPNSENSE_SSH_USER, DEV_OPNSENSE_SSH_KEY

set -euo pipefail

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

PVE_HOST="${PROXMOX_HOST:-bnl.plhm.rgn.cm}"
PVE_TOKEN="${PROXMOX_API_TOKEN:?Need PROXMOX_API_TOKEN in tools/.env}"
PVE_NODE="${PROXMOX_NODE:-bnl}"
SSH_USER="${DEV_OPNSENSE_SSH_USER:-del}"
SSH_KEY="${DEV_OPNSENSE_SSH_KEY:-$HOME/.ssh/del_rgn.cm.private}"
SSH_KEY="${SSH_KEY/#\~/$HOME}"

# ── Args ──────────────────────────────────────────────────────────────────────
VMID="${1:?Usage: rollback-vm.sh VMID HOSTNAME [--latest | SNAPNAME]}"
VM_HOSTNAME="${2:?Usage: rollback-vm.sh VMID HOSTNAME [--latest | SNAPNAME]}"
SNAP_ARG="${3:-}"

# ── Helpers ───────────────────────────────────────────────────────────────────
step() { echo; echo "==> $*"; }
info() { echo "    $*"; }
die()  { echo "ERROR: $*" >&2; exit 1; }

pve_api() {
    local method="$1" path="$2"
    shift 2
    SSH_AUTH_SOCK="" curl -sf -k -X "$method" \
        -H "Authorization: PVEAPIToken=${PVE_TOKEN}" \
        "$@" \
        "https://${PVE_HOST}:8006/api2/json/nodes/${PVE_NODE}/${path}"
}
pve_get()  { pve_api GET  "$@"; }
pve_post() { pve_api POST "$@"; }

wait_for_task() {
    local upid="$1" label="${2:-task}"
    local encoded
    encoded=$(python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1],safe=''))" "$upid")
    local i status exit_status resp
    for i in $(seq 1 60); do
        resp=$(pve_get "tasks/${encoded}/status" 2>/dev/null || true)
        status=$(echo "$resp" | python3 -c "import json,sys; d=json.load(sys.stdin)['data']; print(d.get('status',''))" 2>/dev/null || true)
        if [[ "$status" == "stopped" ]]; then
            exit_status=$(echo "$resp" | python3 -c "import json,sys; d=json.load(sys.stdin)['data']; print(d.get('exitstatus','?'))" 2>/dev/null || true)
            if [[ "$exit_status" == "OK" ]]; then
                info "${label}: done"
                return 0
            else
                echo "  [ERROR] ${label} failed: exitstatus=${exit_status}" >&2
                return 1
            fi
        fi
        sleep 3
    done
    echo "  [ERROR] ${label} timed out after 180s" >&2
    return 1
}

wait_for_vm_status() {
    local vmid="$1" want="$2" label="${3:-VM $vmid}"
    local i got
    for i in $(seq 1 40); do
        got=$(pve_get "qemu/${vmid}/status/current" 2>/dev/null \
            | python3 -c "import json,sys; print(json.load(sys.stdin)['data']['status'])" 2>/dev/null || true)
        if [[ "$got" == "$want" ]]; then
            info "${label}: ${want}"
            return 0
        fi
        sleep 3
    done
    echo "  [ERROR] ${label} did not reach '${want}' after 120s (last: ${got:-unknown})" >&2
    return 1
}

wait_for_ssh() {
    local host="$1" label="${2:-$host}"
    info "Waiting for SSH on ${label}..."
    local i
    for i in $(seq 1 40); do
        if SSH_AUTH_SOCK="" ssh \
                -i "$SSH_KEY" \
                -o StrictHostKeyChecking=no \
                -o ConnectTimeout=5 \
                -o PreferredAuthentications=publickey \
                -o PubkeyAuthentication=yes \
                -o IdentityAgent=none \
                -o BatchMode=yes \
                "${SSH_USER}@${host}" true 2>/dev/null; then
            info "${label}: SSH ready"
            return 0
        fi
        sleep 5
    done
    echo "  [ERROR] SSH on ${label} did not come up after 200s" >&2
    return 1
}

list_snapshots() {
    local vmid="$1"
    pve_get "qemu/${vmid}/snapshot" \
    | python3 -c "
import json, sys, datetime
snaps = json.load(sys.stdin)['data']
snaps = [s for s in snaps if s.get('name') != 'current' and s.get('snaptime')]
snaps.sort(key=lambda s: s['snaptime'], reverse=True)
for i, s in enumerate(snaps, 1):
    ts = datetime.datetime.fromtimestamp(s['snaptime']).strftime('%Y-%m-%d %H:%M')
    desc = s.get('description', '').replace('\n', ' ')[:40]
    marker = '  [default]' if i == 1 else ''
    print(f'{i}\t{s[\"name\"]}\t{ts}\t{desc}{marker}')
"
}

latest_snapshot() {
    local vmid="$1"
    pve_get "qemu/${vmid}/snapshot" \
    | python3 -c "
import json, sys
snaps = json.load(sys.stdin)['data']
snaps = [s for s in snaps if s.get('name') != 'current' and s.get('snaptime')]
snaps.sort(key=lambda s: s['snaptime'], reverse=True)
print(snaps[0]['name'] if snaps else '')
"
}

rollback_vm() {
    local vmid="$1" hostname="$2" snapname="$3"

    local cur_status
    cur_status=$(pve_get "qemu/${vmid}/status/current" \
        | python3 -c "import json,sys; print(json.load(sys.stdin)['data']['status'])" 2>/dev/null || true)

    if [[ "$cur_status" == "running" ]]; then
        info "Shutting down ${hostname} (VM ${vmid})..."
        local upid
        upid=$(pve_post "qemu/${vmid}/status/shutdown" \
            -d "timeout=30" \
            | python3 -c "import json,sys; print(json.load(sys.stdin)['data'])")
        wait_for_task "$upid" "shutdown ${hostname}" || true
        cur_status=$(pve_get "qemu/${vmid}/status/current" \
            | python3 -c "import json,sys; print(json.load(sys.stdin)['data']['status'])" 2>/dev/null || true)
        if [[ "$cur_status" != "stopped" ]]; then
            info "Graceful shutdown timed out — hard stopping..."
            upid=$(pve_post "qemu/${vmid}/status/stop" \
                | python3 -c "import json,sys; print(json.load(sys.stdin)['data'])")
            wait_for_task "$upid" "stop ${hostname}"
        fi
        wait_for_vm_status "$vmid" "stopped" "$hostname"
    else
        info "${hostname} (VM ${vmid}) already stopped"
    fi

    info "Rolling back ${hostname} → snapshot '${snapname}'..."
    local upid
    upid=$(pve_post "qemu/${vmid}/snapshot/${snapname}/rollback" \
        | python3 -c "import json,sys; print(json.load(sys.stdin)['data'])")
    wait_for_task "$upid" "rollback ${hostname}"

    info "Starting ${hostname}..."
    pve_post "qemu/${vmid}/status/start" | python3 -c "import json,sys; json.load(sys.stdin)" 2>/dev/null || true
    wait_for_vm_status "$vmid" "running" "$hostname"
    wait_for_ssh "$hostname" "$hostname"
}

# ── Snapshot selection ────────────────────────────────────────────────────────
SNAPNAME=""

if [[ "$SNAP_ARG" == "--latest" ]]; then
    step "Querying latest snapshot for ${VM_HOSTNAME} (VM ${VMID})"
    SNAPNAME=$(latest_snapshot "$VMID")
    [[ -z "$SNAPNAME" ]] && die "No snapshots found for VM ${VMID}"
    info "Latest: ${SNAPNAME}"
elif [[ -n "$SNAP_ARG" ]]; then
    SNAPNAME="$SNAP_ARG"
    info "Using named snapshot: ${SNAPNAME}"
else
    step "Querying snapshots for ${VM_HOSTNAME} (VM ${VMID})"
    SNAP_LINES=$(list_snapshots "$VMID")
    [[ -z "$SNAP_LINES" ]] && die "No snapshots found for VM ${VMID}"

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
    info "Selected: ${SNAPNAME}"
fi

# ── Run ───────────────────────────────────────────────────────────────────────
START_TIME=$(date +%s)

echo
echo "============================================================"
echo "  VM ${VMID} (${VM_HOSTNAME}) → snapshot '${SNAPNAME}'"
echo "============================================================"

step "${VM_HOSTNAME} (VM ${VMID})"
rollback_vm "$VMID" "$VM_HOSTNAME" "$SNAPNAME"

ELAPSED=$(( $(date +%s) - START_TIME ))
echo
echo "============================================================"
printf "Done. %s on '%s'. (%ds)\n" "$VM_HOSTNAME" "$SNAPNAME" "$ELAPSED"
echo "============================================================"
