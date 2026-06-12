#!/bin/sh
# setup_dhcp6_testenv.sh -- configure DHCPv6 test environment on dev-opnsense
#
# Run from macOS:
#   sh tools/setup_dhcp6_testenv.sh
#
# What this does:
#   1. Adds fd00::1/64 to em1 (ULA test prefix)
#   2. Installs kea-dhcp6.conf with fd00::/64 subnet
#   3. Adds IPv6 reverse zone to kea-dhcp-ddns.conf
#   4. Starts kea-dhcp6
#   5. Prints commands to run on dev-dhcpclient to request a DHCPv6 lease

HOST=dev-opnsense.plhm.rgn.cm
USER=dev
PASS=dev

SSH="sshpass -p $PASS ssh -o PreferredAuthentications=password -o PubkeyAuthentication=no -o IdentityAgent=none -o StrictHostKeyChecking=no $USER@$HOST"
SCP="sshpass -p $PASS scp -o PreferredAuthentications=password -o PubkeyAuthentication=no -o IdentityAgent=none -o StrictHostKeyChecking=no"

set -e

echo "==> Uploading config files..."
$SCP /tmp/kea-dhcp6-test.conf $USER@$HOST:/tmp/
$SCP /tmp/kea-dhcp-ddns-v6.conf $USER@$HOST:/tmp/

echo "==> Applying configs on dev-opnsense..."
$SSH "echo $PASS | sudo -S sh -s" <<'REMOTE'
set -e

# 1. ULA address on em1
if ! ifconfig em1 | grep -q 'fd00::1'; then
    echo "  Adding fd00::1/64 to em1..."
    ifconfig em1 inet6 fd00::1 prefixlen 64 alias
else
    echo "  fd00::1/64 already on em1"
fi

# Persist across reboots via /etc/rc.conf.local (OPNsense style: use ifconfig_ but
# rc.conf is managed by OPNsense GUI — instead use a local script approach)
# For now just assign it; it won't survive a reboot but that's fine for testing.

# 2. Install DHCPv6 config
echo "  Installing kea-dhcp6.conf..."
cp /tmp/kea-dhcp6-test.conf /usr/local/etc/kea/kea-dhcp6.conf

# 3. Install updated D2 config
echo "  Installing kea-dhcp-ddns.conf (adding IPv6 reverse zone)..."
cp /tmp/kea-dhcp-ddns-v6.conf /usr/local/etc/kea/kea-dhcp-ddns.conf

# 4. Ensure /var/db/kea and /var/run/kea exist
mkdir -p /var/db/kea /var/run/kea

# 5. Enable dhcp6 in keactrl.conf
sed -i '' 's/^dhcp6=no$/dhcp6=yes/' /usr/local/etc/kea/keactrl.conf
grep dhcp6 /usr/local/etc/kea/keactrl.conf

# 6. Stop D2 and restart with updated config
echo "  Restarting kea-dhcp-ddns..."
pkill -f kea-dhcp-ddns || true
sleep 1
/usr/local/sbin/kea-dhcp-ddns -c /usr/local/etc/kea/kea-dhcp-ddns.conf &
sleep 1
echo "  D2 pid: $(pgrep kea-dhcp-ddns || echo 'not found')"

# 7. Start kea-dhcp6 (kill any stale instance first)
echo "  Starting kea-dhcp6..."
pkill -f kea-dhcp6 || true
sleep 1
/usr/local/sbin/kea-dhcp6 -c /usr/local/etc/kea/kea-dhcp6.conf &
sleep 2
echo "  kea-dhcp6 pid: $(pgrep kea-dhcp6 || echo 'not found')"

# 8. Verify socket appeared
if [ -S /var/run/kea/kea6-ctrl-socket ]; then
    echo "  Control socket: OK"
else
    echo "  WARNING: control socket not found yet (give it a moment)"
fi

REMOTE

echo ""
echo "==> Setup complete."
echo ""
echo "==> Next: on dev-dhcpclient, run:"
echo ""
echo "    # Enable DHCPv6 on ens19 (send solicit):"
echo "    sudo dhclient -6 ens19"
echo "    # or with wide-dhcpv6:"
echo "    sudo dhcp6c -c /etc/wide-dhcpv6/dhcp6c.conf ens19"
echo ""
echo "==> Verify on dev-opnsense:"
echo "    echo dev | sudo -S cat /var/db/kea/kea-leases6.csv"
echo "    echo dev | sudo -S /usr/local/sbin/unbound-control list_local_data"
