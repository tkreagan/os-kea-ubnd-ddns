#!/bin/sh
# uninstall.sh — Remove kea-unbound plugin state and configuration.
#
# Stops the daemon, removes the KeaUnbound section from config.xml, and
# cleans up runtime directories.  Installed files tracked by the package
# are removed by pkg(8) itself -- run this before or alongside pkg delete.
#
# Usage:
#   sh /usr/local/opnsense/scripts/keaunbound/uninstall.sh [--purge-logs]
#
#   --purge-logs  Also delete /var/log/keaunbound/ (logs are kept by default).
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
echo "==> Stopping kea-unbound-ddns..."
SUPVR="/var/run/kea-unbound-ddns.supervisor.pid"
if [ -f "$SUPVR" ]; then
    pkill -F "$SUPVR" 2>/dev/null || true
    sleep 2
fi
# Belt-and-suspenders: catch any orphaned child that respawned
pkill -f kea-unbound-ddns.py 2>/dev/null || true
echo "    done"

# ── Remove KeaUnbound from config.xml ─────────────────────────────────────────
echo "==> Cleaning config.xml..."
python3 - << 'PYEOF'
import xml.etree.ElementTree as ET, shutil, sys, os

CONFIG = '/conf/config.xml'
BACKUP = CONFIG + '.keaunbound-preremove'

try:
    shutil.copy2(CONFIG, BACKUP)
    tree = ET.parse(CONFIG)
    root = tree.getroot()
    opnsense = root.find('OPNsense')
    if opnsense is not None:
        ku = opnsense.find('KeaUnbound')
        if ku is not None:
            opnsense.remove(ku)
            tree.write(CONFIG, xml_declaration=True, encoding='UTF-8')
            print('    KeaUnbound section removed from config.xml')
        else:
            print('    config.xml: no KeaUnbound section found (already clean)')
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
rm -rf /var/run/keaunbound
echo "    done"

# ── Remove log directory (optional) ──────────────────────────────────────────
if [ "$PURGE_LOGS" -eq 1 ]; then
    echo "==> Removing log directory..."
    rm -rf /var/log/keaunbound
    echo "    done"
else
    if [ -d /var/log/keaunbound ]; then
        echo "    Logs preserved at /var/log/keaunbound/"
        echo "    To remove: rm -rf /var/log/keaunbound"
    fi
fi

echo "==> Done."
echo
echo "Remove installed package files with:"
echo "  pkg delete os-kea-unbound"
