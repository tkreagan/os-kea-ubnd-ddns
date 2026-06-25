#!/bin/sh
# uninstall.sh — Remove kea-ubnd-ddns plugin state and configuration.
#
# Stops the daemon, removes the KeaUbnd section from config.xml, and
# cleans up runtime directories.  Installed files tracked by the package
# are removed by pkg(8) itself -- run this before or alongside pkg delete.
#
# Usage:
#   sh /usr/local/opnsense/scripts/keaubnd/uninstall.sh [--purge-logs]
#
#   --purge-logs  Also delete /var/log/keaubnd/ (logs are kept by default).
#
# Exit codes: 0 = clean, 1 = error (config.xml write failure).

set -e

PURGE_LOGS=0
for _arg in "$@"; do
    case "$_arg" in
        --purge-logs) PURGE_LOGS=1 ;;
        --help|-h)
            sed -n '/^#/!q; s/^# \?//p' "$0" | head -14
            exit 0 ;;
        *)
            printf 'ERROR: unknown argument: %s\n' "$_arg" >&2
            exit 1 ;;
    esac
done

if [ "$(id -u)" != "0" ]; then
    echo "ERROR: must run as root" >&2
    exit 1
fi

# ── Stop daemon ───────────────────────────────────────────────────────────────
echo "==> Stopping kea-ubnd-ddns..."
SUPVR="/var/run/kea-ubnd-ddns.supervisor.pid"
if [ -f "$SUPVR" ]; then
    pkill -F "$SUPVR" 2>/dev/null || true
    sleep 2
fi
# Belt-and-suspenders: catch any orphaned child that respawned
pkill -f kea-ubnd-ddns.py 2>/dev/null || true
echo "    done"

# ── Remove d2 DDNS pointers from OPNsense Kea subnet config ──────────────────
# Clears ddns_dns_server / ddns_dns_port on any GUI-managed subnet that was
# pointing at our listener.  Manual-config services are left alone (conf file
# is hand-edited; we emit a warning instead).  Must run before the KeaUbnd
# section is removed so we can read our configured port.
echo "==> Removing d2 DDNS configuration targeting our listener..."
python3 - << 'PYEOF'
import xml.etree.ElementTree as ET, shutil, sys, os

CONFIG  = '/conf/config.xml'
BACKUP  = CONFIG + '.keaubnd-d2clean'
OUR_ADDR = '127.0.0.1'

try:
    shutil.copy2(CONFIG, BACKUP)
    tree = ET.parse(CONFIG)
    root = tree.getroot()

    our_port = '53535'
    ku = root.find('OPNsense/KeaUbnd/general')
    if ku is not None:
        p = (ku.findtext('port') or '').strip()
        if p:
            our_port = p

    changed      = 0
    manual_noted = []

    for service, tag in [('dhcp4', 'subnet4'), ('dhcp6', 'subnet6')]:
        mc = (root.findtext(f'OPNsense/Kea/{service}/general/manual_config') or '').strip()
        if mc == '1':
            manual_noted.append((service, our_port))
            continue
        subnets = root.find(f'OPNsense/Kea/{service}/subnets')
        if subnets is None:
            continue
        for subnet in subnets.findall(tag):
            addr_el = subnet.find('ddns_dns_server')
            port_el = subnet.find('ddns_dns_port')
            if addr_el is None or port_el is None:
                continue
            if (addr_el.text or '').strip() == OUR_ADDR and \
               (port_el.text or '').strip() == our_port:
                addr_el.text = ''
                port_el.text = ''
                changed += 1

    if changed:
        tree.write(CONFIG, xml_declaration=True, encoding='UTF-8')
        print(f'    Cleared DDNS server pointer from {changed} subnet(s)')
    else:
        print('    No matching subnet pointers found (already clean or no GUI-managed subnets)')

    for svc, port in manual_noted:
        print(f'    NOTE: {svc} uses manual config — remove the {OUR_ADDR}:{port}')
        print(f'          dns-server entry from forward zones in kea-dhcp-ddns.conf manually')

    os.remove(BACKUP)
except Exception as e:
    print(f'ERROR: {e}', file=sys.stderr)
    if os.path.exists(BACKUP):
        shutil.copy2(BACKUP, CONFIG)
        print('    config.xml restored from backup', file=sys.stderr)
    sys.exit(1)
PYEOF

# Regenerate kea-dhcp-ddns.conf from the updated model and restart d2.
# This causes a brief DHCP service interruption; acceptable during uninstall.
echo "==> Reloading Kea configuration (brief DHCP interruption)..."
/usr/local/sbin/configctl template reload OPNsense/Kea >/dev/null 2>&1 || true
/usr/local/sbin/configctl kea restart >/dev/null 2>&1 \
    && echo "    done" \
    || echo "    WARNING: Kea restart failed — restart Kea manually after removing the plugin"

# ── Remove KeaUbnd from config.xml ─────────────────────────────────────────
echo "==> Cleaning config.xml..."
python3 - << 'PYEOF'
import xml.etree.ElementTree as ET, shutil, sys, os

CONFIG = '/conf/config.xml'
BACKUP = CONFIG + '.keaubnd-preremove'

try:
    shutil.copy2(CONFIG, BACKUP)
    tree = ET.parse(CONFIG)
    root = tree.getroot()
    opnsense = root.find('OPNsense')
    if opnsense is not None:
        ku = opnsense.find('KeaUbnd')
        if ku is not None:
            opnsense.remove(ku)
            tree.write(CONFIG, xml_declaration=True, encoding='UTF-8')
            print('    KeaUbnd section removed from config.xml')
        else:
            print('    config.xml: no KeaUbnd section found (already clean)')
    os.remove(BACKUP)
except Exception as e:
    print(f'ERROR writing config.xml: {e}', file=sys.stderr)
    if os.path.exists(BACKUP):
        shutil.copy2(BACKUP, CONFIG)
        print('    config.xml restored from backup', file=sys.stderr)
    sys.exit(1)
PYEOF

# ── Remove runtime directory ──────────────────────────────────────────────────
echo "==> Removing runtime directory..."
rm -rf /var/run/keaubnd
echo "    done"

# ── Remove log directory (optional) ──────────────────────────────────────────
if [ "$PURGE_LOGS" -eq 1 ]; then
    echo "==> Removing log directory..."
    rm -rf /var/log/keaubnd
    echo "    done"
else
    if [ -d /var/log/keaubnd ]; then
        echo "    Logs preserved at /var/log/keaubnd/"
        echo "    To remove: rm -rf /var/log/keaubnd"
    fi
fi

echo "==> Done."
echo
echo "Remove installed package files with:"
echo "  pkg delete os-kea-ubnd-ddns"
