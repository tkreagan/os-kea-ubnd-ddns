#!/usr/bin/env bash
# configure-chaos-env.sh — One-time setup for both dev boxes to run chaos monkey.
#
# Run this once after restoring either box to a clean snapshot.  Idempotent.
#
# What it does on dev-opnsense:
#   1. Patches config.xml: enable dhcp6, ddns, keaunbound; set manual_config=1
#      for dhcp4/dhcp6/ddns so OPNsense never regenerates the Kea configs.
#   2. Writes kea-dhcp4.conf, kea-dhcp6.conf, kea-dhcp-ddns.conf with test
#      subnets, DDNS wiring, and both hook libraries.
#   3. Reloads Kea templates (updates keactrl.conf: dhcp6=yes, dhcp_ddns=yes).
#   4. Adds fd00:cafe::1/64 alias to em1 (ULA prefix for DHCPv6 test subnet).
#   5. Restarts Kea (all three daemons) and the plugin daemon.
#
# What it does on dev-dhcpclient:
#   6. Ensures ens19 is up and isc-dhcp-client is installed.
#   7. Writes a systemd-networkd file to keep ens19 up on reboot.
#
# Usage:
#   cd <repo-root>
#   bash tools/setup/configure-chaos-env.sh
#   bash tools/setup/configure-chaos-env.sh --opnsense-only
#   bash tools/setup/configure-chaos-env.sh --dhcpclient-only
#
# Environment overrides (or set in tools/.env):
#   DEV_OPNSENSE_HOST     default: dev-opnsense.plhm.rgn.cm
#   DEV_OPNSENSE_SSH_USER default: del
#   DEV_OPNSENSE_SSH_KEY  default: ~/.ssh/del_rgn.cm.private
#   DEV_DHCPCLIENT_HOST   default: dev-dhcpclient.plhm.rgn.cm
#   DEV_DHCPCLIENT_SSH_USER default: del
#   DEV_DHCPCLIENT_SSH_KEY  default: ~/.ssh/del_rgn.cm.private
#   DEV_LAN_IF            default: em1     (OPNsense LAN interface)
#   DEV_DHCPCLIENT_LAN_IF default: ens19   (dhcpclient LAN interface)
#   DEV_DOMAIN            default: lan
#   TEST_V4_SUBNET        default: 192.168.1.0/24
#   TEST_V4_POOL          default: 192.168.1.100 - 192.168.1.200
#   TEST_V4_GW            default: 192.168.1.1
#   TEST_V6_PREFIX        default: fd00:cafe::
#   TEST_V6_SUBNET        default: fd00:cafe::/64
#   TEST_V6_POOL          default: fd00:cafe::100 - fd00:cafe::2ff
#   TEST_V6_GW            default: fd00:cafe::1

set -euo pipefail

# ── Load .env if present ──────────────────────────────────────────────────────
ENV_FILE="${ENV_FILE:-tools/.env}"
if [[ -f "$ENV_FILE" ]]; then
    while IFS= read -r line; do
        line="${line%%#*}"      # strip comments
        line="${line// /}"      # strip spaces
        [[ -z "$line" ]] && continue
        [[ "$line" != *=* ]] && continue
        key="${line%%=*}"
        val="${line#*=}"
        val="${val%\"}"
        val="${val#\"}"
        export "${key}=${val}" 2>/dev/null || true
    done < "$ENV_FILE"
fi

OPNSENSE_HOST="${DEV_OPNSENSE_HOST:-dev-opnsense.plhm.rgn.cm}"
OPNSENSE_USER="${DEV_OPNSENSE_SSH_USER:-del}"
OPNSENSE_KEY="${DEV_OPNSENSE_SSH_KEY:-$HOME/.ssh/del_rgn.cm.private}"
OPNSENSE_KEY="${OPNSENSE_KEY/#\~/$HOME}"   # expand leading ~ if any

DHCPCLIENT_HOST="${DEV_DHCPCLIENT_HOST:-dev-dhcpclient.plhm.rgn.cm}"
DHCPCLIENT_USER="${DEV_DHCPCLIENT_SSH_USER:-del}"
DHCPCLIENT_KEY="${DEV_DHCPCLIENT_SSH_KEY:-$HOME/.ssh/del_rgn.cm.private}"
DHCPCLIENT_KEY="${DHCPCLIENT_KEY/#\~/$HOME}"  # expand leading ~ if any

LAN_IF="${DEV_LAN_IF:-em1}"
CLIENT_LAN_IF="${DEV_DHCPCLIENT_LAN_IF:-ens19}"
DOMAIN="${DEV_DOMAIN:-lan}"

V4_SUBNET="${TEST_V4_SUBNET:-192.168.1.0/24}"
V4_POOL="${TEST_V4_POOL:-192.168.1.100 - 192.168.1.200}"
V4_GW="${TEST_V4_GW:-192.168.1.1}"

V6_PREFIX="${TEST_V6_PREFIX:-fd00:cafe::}"
V6_SUBNET="${TEST_V6_SUBNET:-fd00:cafe::/64}"
V6_POOL="${TEST_V6_POOL:-fd00:cafe::100 - fd00:cafe::2ff}"
V6_GW="${TEST_V6_GW:-fd00:cafe::1}"

SETUP_OPNSENSE=true
SETUP_DHCPCLIENT=true

for arg in "$@"; do
    case "$arg" in
        --opnsense-only)   SETUP_DHCPCLIENT=false ;;
        --dhcpclient-only) SETUP_OPNSENSE=false ;;
        --help|-h)
            grep '^# ' "$0" | head -20 | sed 's/^# //'
            exit 0 ;;
    esac
done

# ── Helpers ───────────────────────────────────────────────────────────────────

step() { echo; echo "==> $*"; }
info() { echo "    $*"; }
die()  { echo "ERROR: $*" >&2; exit 1; }

_ssh_opts() {
    local key="$1"
    echo "-i $key -o StrictHostKeyChecking=no -o ConnectTimeout=15 \
          -o PreferredAuthentications=publickey -o PubkeyAuthentication=yes \
          -o IdentityAgent=none -o BatchMode=yes"
}

opn_ssh() {
    # shellcheck disable=SC2046
    SSH_AUTH_SOCK="" ssh $(_ssh_opts "$OPNSENSE_KEY") "${OPNSENSE_USER}@${OPNSENSE_HOST}" "$@"
}

opn_sudo() {
    opn_ssh "sudo $*"
}

opn_sudo_python() {
    # Run a Python script (read from stdin) on the remote under sudo.
    # Uploads to a temp file so stdin stays available for the script itself.
    local tmp_local tmp_remote
    tmp_local=$(mktemp /tmp/chaos_setup_XXXXXX.py)
    tmp_remote="/tmp/_chaos_setup_$$.py"
    cat > "$tmp_local"
    # shellcheck disable=SC2046
    SSH_AUTH_SOCK="" scp $(_ssh_opts "$OPNSENSE_KEY") "$tmp_local" \
        "${OPNSENSE_USER}@${OPNSENSE_HOST}:${tmp_remote}" 2>/dev/null
    rm -f "$tmp_local"
    opn_ssh "sudo python3 $tmp_remote; sudo rm -f $tmp_remote"
}

client_ssh() {
    # shellcheck disable=SC2046
    SSH_AUTH_SOCK="" ssh $(_ssh_opts "$DHCPCLIENT_KEY") "${DHCPCLIENT_USER}@${DHCPCLIENT_HOST}" "$@"
}

client_sudo() {
    client_ssh "sudo $*"
}

check_key_auth() {
    local host="$1" user="$2" key="$3"
    # shellcheck disable=SC2046
    if SSH_AUTH_SOCK="" ssh $(_ssh_opts "$key") "$user@$host" true 2>/dev/null; then
        info "Key auth OK for $user@$host"
        return 0
    fi
    echo
    echo "[ERROR] Key auth failed for $user@$host"
    echo "  Key: $key"
    echo "  Fix: ssh-copy-id -i ${key}.pub $user@$host"
    return 1
}

# Upload a local file to a remote temporary path, then sudo-move it.
upload_file() {
    local local_src="$1" remote_dest="$2" label="$3"
    local tmp_remote="/tmp/_chaos_setup_$(basename "$remote_dest")"
    # shellcheck disable=SC2046
    SSH_AUTH_SOCK="" scp $(_ssh_opts "$OPNSENSE_KEY") \
        "$local_src" "${OPNSENSE_USER}@${OPNSENSE_HOST}:${tmp_remote}"
    opn_sudo "cp $tmp_remote $remote_dest && rm $tmp_remote"
    info "Wrote $remote_dest ($label)"
}

# ── dev-opnsense setup ────────────────────────────────────────────────────────

setup_opnsense() {
    step "Configuring ${OPNSENSE_HOST}"
    check_key_auth "$OPNSENSE_HOST" "$OPNSENSE_USER" "$OPNSENSE_KEY"

    # ── Step 1: Patch config.xml via Python ───────────────────────────────────
    step "[1/6] Patching config.xml (manual_config, dhcp6, ddns, plugin)"

    local config_patch
    config_patch=$(cat <<'PYEOF'
import xml.etree.ElementTree as ET
import sys

ET.register_namespace("", "")
tree = ET.parse("/conf/config.xml")
root = tree.getroot()

def get_or_create(parent, tag):
    child = parent.find(tag)
    if child is None:
        child = ET.SubElement(parent, tag)
    return child

def set_val(parent, path, value):
    parts = path.split("/")
    node = parent
    for p in parts[:-1]:
        node = get_or_create(node, p)
    leaf = get_or_create(node, parts[-1])
    leaf.text = str(value)

opn = get_or_create(root, "OPNsense")

# Kea dhcp4: keep enabled, set manual_config=1
kea = get_or_create(opn, "Kea")
dhcp4 = get_or_create(kea, "dhcp4")
dhcp4_gen = get_or_create(dhcp4, "general")
set_val(dhcp4_gen, "enabled", "1")
set_val(dhcp4_gen, "manual_config", "1")

# Kea dhcp6: enable + manual_config=1
dhcp6 = get_or_create(kea, "dhcp6")
dhcp6_gen = get_or_create(dhcp6, "general")
set_val(dhcp6_gen, "enabled", "1")
set_val(dhcp6_gen, "manual_config", "1")
# Clear any track6 refs from dhcp6 interface config — not needed here
# (dhcp6 subnet is in kea-dhcp6.conf, not driven by config.xml in manual mode)

# Kea ddns: enable + manual_config=1
ddns = get_or_create(kea, "ddns")
ddns_gen = get_or_create(ddns, "general")
set_val(ddns_gen, "enabled", "1")
set_val(ddns_gen, "manual_config", "1")

# Plugin: enable + sensible defaults
ku = get_or_create(opn, "KeaUnbound")
gen = get_or_create(ku, "general")
set_val(gen, "enabled", "1")
set_val(gen, "sync_static_reservations", "1")
set_val(gen, "sync_dynamic_leases", "1")
set_val(gen, "synthesize_ptr", "1")
set_val(gen, "collision_policy", "last_wins")
set_val(gen, "listen_port", "53535")

# Preserve xml_declaration by re-writing the original header
original = open("/conf/config.xml").read(200)
decl = ""
if original.startswith("<?xml"):
    decl = original[:original.index("?>") + 2] + "\n"

body = ET.tostring(root, encoding="unicode")
with open("/conf/config.xml", "w") as f:
    f.write(decl + body)

print("config.xml patched OK")
PYEOF
)

    echo "$config_patch" | opn_sudo_python
    info "config.xml updated"

    # ── Step 2: Write kea-dhcp4.conf ─────────────────────────────────────────
    step "[2/6] Writing kea-dhcp4.conf"

    local tmp4
    tmp4=$(mktemp /tmp/kea-dhcp4-XXXXXX.json)
    cat > "$tmp4" <<EOF
{
  "Dhcp4": {
    "valid-lifetime": 4000,
    "decline-probation-period": 600,
    "interfaces-config": {
      "interfaces": ["${LAN_IF}"],
      "dhcp-socket-type": "raw"
    },
    "lease-database": {
      "type": "memfile",
      "persist": true,
      "name": "/var/db/kea/kea-leases4.csv"
    },
    "dhcp-ddns": {
      "enable-updates": true,
      "server-ip": "127.0.0.1",
      "server-port": 53001
    },
    "ddns-send-updates": true,
    "ddns-qualifying-suffix": "${DOMAIN}",
    "ddns-override-no-update": true,
    "control-socket": {
      "socket-type": "unix",
      "socket-name": "/var/run/kea/kea4-ctrl-socket"
    },
    "subnet4": [
      {
        "id": 1,
        "subnet": "${V4_SUBNET}",
        "interface": "${LAN_IF}",
        "pools": [{"pool": "${V4_POOL}"}],
        "ddns-send-updates": true,
        "ddns-qualifying-suffix": "${DOMAIN}",
        "ddns-override-no-update": true,
        "option-data": [
          {"name": "domain-name", "data": "${DOMAIN}"},
          {"name": "routers", "data": "${V4_GW}"},
          {"name": "domain-name-servers", "data": "${V4_GW}"}
        ]
      }
    ],
    "hooks-libraries": [
      {"library": "/usr/local/lib/kea/hooks/libdhcp_lease_cmds.so"},
      {"library": "/usr/local/lib/kea/hooks/libdhcp_host_cmds.so"}
    ],
    "loggers": [
      {
        "name": "kea-dhcp4",
        "output_options": [{"output": "syslog"}],
        "severity": "INFO"
      }
    ]
  }
}
EOF
    upload_file "$tmp4" "/usr/local/etc/kea/kea-dhcp4.conf" "dhcp4"
    rm -f "$tmp4"

    # ── Step 3: Write kea-dhcp6.conf ─────────────────────────────────────────
    step "[3/6] Writing kea-dhcp6.conf (subnet ${V6_SUBNET})"

    local tmp6
    tmp6=$(mktemp /tmp/kea-dhcp6-XXXXXX.json)
    cat > "$tmp6" <<EOF
{
  "Dhcp6": {
    "valid-lifetime": 4000,
    "interfaces-config": {
      "interfaces": ["${LAN_IF}"]
    },
    "lease-database": {
      "type": "memfile",
      "persist": true,
      "name": "/var/db/kea/kea-leases6.csv"
    },
    "dhcp-ddns": {
      "enable-updates": true,
      "server-ip": "127.0.0.1",
      "server-port": 53001
    },
    "ddns-send-updates": true,
    "ddns-qualifying-suffix": "${DOMAIN}",
    "ddns-override-no-update": true,
    "control-socket": {
      "socket-type": "unix",
      "socket-name": "/var/run/kea/kea6-ctrl-socket"
    },
    "subnet6": [
      {
        "id": 1,
        "subnet": "${V6_SUBNET}",
        "interface": "${LAN_IF}",
        "pools": [{"pool": "${V6_POOL}"}],
        "ddns-send-updates": true,
        "ddns-qualifying-suffix": "${DOMAIN}",
        "ddns-override-no-update": true
      }
    ],
    "hooks-libraries": [
      {"library": "/usr/local/lib/kea/hooks/libdhcp_lease_cmds.so"},
      {"library": "/usr/local/lib/kea/hooks/libdhcp_host_cmds.so"}
    ],
    "loggers": [
      {
        "name": "kea-dhcp6",
        "output_options": [{"output": "syslog"}],
        "severity": "INFO"
      }
    ]
  }
}
EOF
    upload_file "$tmp6" "/usr/local/etc/kea/kea-dhcp6.conf" "dhcp6"
    rm -f "$tmp6"

    # ── Step 4: Write kea-dhcp-ddns.conf ─────────────────────────────────────
    step "[4/6] Writing kea-dhcp-ddns.conf (v4 + v6 reverse zones)"

    # Derive IPv4 reverse zone from V4_SUBNET (e.g. "192.168.1.0/24" → "1.168.192.in-addr.arpa.")
    local v4_rev_zone
    v4_rev_zone=$(python3 -c "
prefix='${V4_SUBNET}'.split('/')[0]
octets = prefix.split('.')[:3]
print('.'.join(reversed(octets)) + '.in-addr.arpa.')
")

    # Derive IPv6 reverse zone from V6_PREFIX (e.g. "fd00:cafe::" → nibble-reversed .ip6.arpa.)
    local v6_rev_zone
    v6_rev_zone=$(python3 -c "
import ipaddress
prefix = '${V6_PREFIX}'
# expand and strip trailing colons / zeros to get the first 64 bits
net = ipaddress.IPv6Network(prefix + ('0' if prefix.endswith('::') else '0') + '/64', strict=False)
addr = net.network_address.exploded   # 'fd00:0cafe:0000:...'
nibbles = addr.replace(':', '')[:16]  # first 64 bits = 16 nibbles
rev = '.'.join(reversed(list(nibbles)))
print(rev + '.ip6.arpa.')
")

    local tmpd
    tmpd=$(mktemp /tmp/kea-ddns-XXXXXX.json)
    cat > "$tmpd" <<EOF
{
  "DhcpDdns": {
    "ip-address": "127.0.0.1",
    "port": 53001,
    "tsig-keys": [],
    "forward-ddns": {
      "ddns-domains": [
        {
          "name": "${DOMAIN}.",
          "dns-servers": [{"ip-address": "127.0.0.1", "port": 53535}]
        }
      ]
    },
    "reverse-ddns": {
      "ddns-domains": [
        {
          "name": "${v4_rev_zone}",
          "dns-servers": [{"ip-address": "127.0.0.1", "port": 53535}]
        },
        {
          "name": "${v6_rev_zone}",
          "dns-servers": [{"ip-address": "127.0.0.1", "port": 53535}]
        }
      ]
    },
    "loggers": [
      {
        "name": "kea-dhcp-ddns",
        "output_options": [{"output": "syslog"}],
        "severity": "INFO"
      }
    ]
  }
}
EOF
    info "IPv4 reverse zone: ${v4_rev_zone}"
    info "IPv6 reverse zone: ${v6_rev_zone}"
    upload_file "$tmpd" "/usr/local/etc/kea/kea-dhcp-ddns.conf" "ddns"
    rm -f "$tmpd"

    # ── Step 5: Reload templates + add IPv6 alias + restart services ──────────
    step "[5/6] Reloading Kea templates and restarting services"

    # Ensure /var/db/kea and /var/run/kea exist on the remote
    opn_sudo "mkdir -p /var/db/kea /var/run/kea"

    # Template reload updates keactrl.conf to enable dhcp6 and dhcp_ddns
    info "configctl template reload OPNsense/Kea..."
    opn_sudo "/usr/local/sbin/configctl template reload OPNsense/Kea" || true

    # Verify keactrl.conf now has dhcp6=yes and dhcp_ddns=yes
    local keactrl
    keactrl=$(opn_sudo "cat /usr/local/etc/kea/keactrl.conf 2>/dev/null || true")
    if echo "$keactrl" | grep -q "^dhcp6=yes"; then
        info "keactrl.conf: dhcp6=yes  ✓"
    else
        info "keactrl.conf: dhcp6 not yes after template reload — patching directly"
        # Fallback: patch keactrl.conf directly if template reload didn't update it
        opn_sudo "sed -i '' 's/^dhcp6=.*/dhcp6=yes/' /usr/local/etc/kea/keactrl.conf || true"
        opn_sudo "sed -i '' 's/^dhcp_ddns=.*/dhcp_ddns=yes/' /usr/local/etc/kea/keactrl.conf || true"
        opn_sudo "grep -q '^dhcp6=' /usr/local/etc/kea/keactrl.conf || echo 'dhcp6=yes' >> /usr/local/etc/kea/keactrl.conf"
        opn_sudo "grep -q '^dhcp_ddns=' /usr/local/etc/kea/keactrl.conf || echo 'dhcp_ddns=yes' >> /usr/local/etc/kea/keactrl.conf"
    fi
    if echo "$keactrl" | grep -q "^dhcp_ddns=yes"; then
        info "keactrl.conf: dhcp_ddns=yes  ✓"
    fi

    # Add IPv6 ULA alias to LAN interface (enables DHCPv6 to bind on it)
    info "Adding ${V6_GW}/64 to ${LAN_IF}..."
    opn_sudo "ifconfig ${LAN_IF} inet6 ${V6_GW} prefixlen 64 alias 2>/dev/null || true"
    opn_ssh "ifconfig ${LAN_IF} | grep '${V6_GW}'" && info "${V6_GW}/64 confirmed on ${LAN_IF}" || info "Note: verify ${V6_GW} is on ${LAN_IF} if DHCPv6 fails"

    # Restart Kea (all three daemons: dhcp4, dhcp6, d2)
    info "configctl kea restart..."
    opn_sudo "/usr/local/sbin/configctl kea restart 2>&1" || true
    sleep 5

    # Verify sockets appeared
    local v4_sock v6_sock
    v4_sock=$(opn_sudo "test -S /var/run/kea/kea4-ctrl-socket && echo yes || echo no" 2>/dev/null || echo no)
    v6_sock=$(opn_sudo "test -S /var/run/kea/kea6-ctrl-socket && echo yes || echo no" 2>/dev/null || echo no)
    info "kea4 socket: $v4_sock"
    info "kea6 socket: $v6_sock"

    if [[ "$v4_sock" != "yes" ]]; then
        echo "  [WARN] kea-dhcp4 control socket not found — check: $OPNSENSE_HOST:/var/log/kea/"
    fi
    if [[ "$v6_sock" != "yes" ]]; then
        echo "  [WARN] kea-dhcp6 control socket not found — check: $OPNSENSE_HOST:/var/log/kea/"
    fi

    # ── Step 6: Start plugin daemon ───────────────────────────────────────────
    step "[6/6] Starting kea-unbound-ddns daemon"
    opn_sudo "/usr/local/sbin/configctl keaunbound restart 2>&1" || true
    sleep 4

    local daemon_status
    daemon_status=$(opn_sudo "/usr/local/sbin/pluginctl -s kea-unbound-ddns status 2>&1" || echo "unknown")
    if echo "$daemon_status" | grep -q "is running"; then
        info "kea-unbound-ddns: running  ✓"
    else
        echo "  [WARN] daemon not running: ${daemon_status}"
        info "Check preconditions: sudo /usr/local/opnsense/scripts/keaunbound/start.py"
    fi

    echo
    echo "  dev-opnsense configured."
}

# ── dev-dhcpclient setup ──────────────────────────────────────────────────────

setup_dhcpclient() {
    step "Configuring ${DHCPCLIENT_HOST}"
    check_key_auth "$DHCPCLIENT_HOST" "$DHCPCLIENT_USER" "$DHCPCLIENT_KEY"

    # Install isc-dhcp-client if missing
    info "Checking isc-dhcp-client..."
    if client_ssh "command -v dhclient" >/dev/null 2>&1; then
        info "dhclient already installed"
    else
        info "Installing isc-dhcp-client..."
        client_ssh "sudo apt-get update -qq && sudo apt-get install -y isc-dhcp-client"
    fi

    # Bring LAN interface up and persist with systemd-networkd
    info "Ensuring ${CLIENT_LAN_IF} is up..."
    client_ssh "sudo ip link set ${CLIENT_LAN_IF} up 2>/dev/null || true"

    local networkd_conf="/etc/systemd/network/10-chaos-${CLIENT_LAN_IF}.network"
    if client_ssh "test -f $networkd_conf" 2>/dev/null; then
        info "networkd config already present at $networkd_conf"
    else
        info "Writing $networkd_conf..."
        client_ssh "sudo tee $networkd_conf > /dev/null" <<EOF
[Match]
Name=${CLIENT_LAN_IF}

[Link]
RequiredForOnline=no

[Network]
DHCP=no
LinkLocalAddressing=ipv6
EOF
        client_ssh "sudo systemctl restart systemd-networkd 2>/dev/null || true"
        sleep 1
        client_ssh "sudo ip link set ${CLIENT_LAN_IF} up 2>/dev/null || true"
    fi

    info "dev-dhcpclient ready."
}

# ── Main ──────────────────────────────────────────────────────────────────────

echo "============================================================"
echo "CHAOS MONKEY — configure-chaos-env.sh"
echo "  opnsense:   ${OPNSENSE_HOST} (user: ${OPNSENSE_USER})"
echo "  dhcpclient: ${DHCPCLIENT_HOST} (user: ${DHCPCLIENT_USER})"
echo "  LAN interface: ${LAN_IF}    domain: ${DOMAIN}"
echo "  DHCPv4 subnet: ${V4_SUBNET}"
echo "  DHCPv6 subnet: ${V6_SUBNET}"
echo "============================================================"

[[ -f "$OPNSENSE_KEY" ]] || die "SSH key not found: $OPNSENSE_KEY"

if $SETUP_OPNSENSE; then
    setup_opnsense
fi

if $SETUP_DHCPCLIENT; then
    setup_dhcpclient
fi

echo
echo "============================================================"
echo "Setup complete."
echo
echo "Verify with:"
echo "  python3 tools/chaos_monkey.py --setup-only"
echo
echo "Run all scenarios:"
echo "  python3 tools/chaos_monkey.py --all"
echo
echo "After verifying, take VM snapshots of both boxes."
echo "============================================================"
