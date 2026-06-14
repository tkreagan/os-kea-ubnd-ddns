#!/bin/sh
# build_package.sh — Build os-kea-ubnd-ddns-VERSION.pkg on the OPNsense box.
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
# Output: ./os-kea-ubnd-ddns-VERSION.pkg  (on macOS, downloaded from the box)
#         /tmp/os-kea-ubnd-ddns-VERSION.pkg  (on the OPNsense box itself)
#
# Environment (read from tools/.env on macOS; not needed on FreeBSD):
#   OPNSENSE_HOST      defaults to DEV_OPNSENSE_HOST or dev-opnsense.plhm.rgn.cm
#   OPNSENSE_SSH_USER  defaults to DEV_OPNSENSE_SSH_USER or del
#   OPNSENSE_SSH_KEY   defaults to DEV_OPNSENSE_SSH_KEY or ~/.ssh/del_rgn.cm.private

set -e

REPO="$(cd "$(dirname "$0")" && pwd)"

# ── Read version from Makefile ────────────────────────────────────────────────
VERSION=$(grep '^PLUGIN_VERSION' "$REPO/Makefile" | awk '{print $NF}')
PKGNAME="os-kea-ubnd-ddns"
# pkg(8) uses .pkg (zstd) on FreeBSD 14+, .txz on older versions
OUTFILE_REMOTE="/tmp/${PKGNAME}-${VERSION}.pkg"
OUTFILE_LOCAL="${REPO}/${PKGNAME}-${VERSION}.pkg"

# ── Build on FreeBSD (OPNsense box) ──────────────────────────────────────────
_build_on_box() {
    STAGE=$(mktemp -d -t keaubnd-pkg)
    trap "rm -rf $STAGE" EXIT

    # ── Stage files ───────────────────────────────────────────────────────────
    mkdir -p \
        "$STAGE/usr/local/sbin" \
        "$STAGE/usr/local/opnsense/scripts/keaubnd/lib" \
        "$STAGE/usr/local/etc/inc/plugins.inc.d" \
        "$STAGE/usr/local/opnsense/service/conf/actions.d" \
        "$STAGE/usr/local/opnsense/service/templates/OPNsense/Syslog/local"

    install -m 755 src/sbin/kea-ubnd-ddns.py \
        "$STAGE/usr/local/sbin/kea-ubnd-ddns.py"
    install -m 755 src/sbin/kea-ubnd-logwatch.py \
        "$STAGE/usr/local/sbin/kea-ubnd-logwatch.py"

    for f in start.py stop.py kea-sync.py local-data-audit.py local-data-clean.py; do
        install -m 755 "src/opnsense/scripts/keaubnd/$f" \
            "$STAGE/usr/local/opnsense/scripts/keaubnd/$f"
    done
    install -m 755 src/opnsense/scripts/keaubnd/uninstall.sh \
        "$STAGE/usr/local/opnsense/scripts/keaubnd/uninstall.sh"

    for f in __init__.py keaubnd_sync.py kea_transport.py \
              consistency_sm.py pid_watch.py preconditions.py logwatch.py; do
        install -m 644 "src/opnsense/scripts/keaubnd/lib/$f" \
            "$STAGE/usr/local/opnsense/scripts/keaubnd/lib/$f"
    done

    install -m 644 src/etc/inc/plugins.inc.d/keaubnd.inc \
        "$STAGE/usr/local/etc/inc/plugins.inc.d/keaubnd.inc"
    install -m 644 \
        src/opnsense/service/conf/actions.d/actions_keaubnd.conf \
        "$STAGE/usr/local/opnsense/service/conf/actions.d/actions_keaubnd.conf"
    install -m 644 \
        src/opnsense/service/templates/OPNsense/Syslog/local/keaubnd.conf \
        "$STAGE/usr/local/opnsense/service/templates/OPNsense/Syslog/local/keaubnd.conf"

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
    # Use Python to generate the manifest with embedded lifecycle scripts so we
    # avoid shell heredoc nesting conflicts.  Scripts are JSON-encoded strings
    # (the format pkg(8) uses internally, confirmed from live package inspection).
    #
    # pre-deinstall: calls our installed uninstall.sh while files are still present
    #   — handles daemon stop and config.xml cleanup.
    # post-deinstall: removes runtime dirs and restarts configd after pkg deletes files.
    export STAGE PKGNAME VERSION
    python3 - << 'PYEOF'
import hashlib, json, os

stage   = os.environ['STAGE']
pkgname = os.environ['PKGNAME']
version = os.environ['VERSION']

# Build files: section — pkg create -M requires explicit file list with checksums
files_lines = []
for root, dirs, fnames in os.walk(stage):
    dirs[:] = sorted(d for d in dirs if not d.startswith('+'))
    for fname in sorted(fnames):
        if fname.startswith('+'):
            continue
        fpath = os.path.join(root, fname)
        rel = fpath[len(stage):]  # e.g. /usr/local/sbin/kea-ubnd-ddns.py
        sha = hashlib.sha256(open(fpath, 'rb').read()).hexdigest()
        files_lines.append(f'  {rel}: "sha256:{sha}"')
files_section = 'files: {\n' + '\n'.join(files_lines) + '\n}' if files_lines else ''

pre_deinstall = json.dumps(
    "#!/bin/sh\n"
    "# Stop daemon and clean config while installed files are still present.\n"
    "/usr/local/opnsense/scripts/keaubnd/uninstall.sh 2>/dev/null || true\n"
)

post_deinstall = json.dumps(
    "#!/bin/sh\n"
    "# Remove runtime state left after pkg deletes installed files.\n"
    "rm -rf /var/run/keaubnd\n"
    "service configd restart >/dev/null 2>&1 || true\n"
    "printf 'kea-ubnd-ddns removed.\\n"
    "Log files (if any) are preserved at /var/log/keaubnd/\\n"
    "To purge: rm -rf /var/log/keaubnd\\n'\n"
)

manifest = f"""name: {pkgname}
version: "{version}"
origin: opnsense-plugins/{pkgname}
comment: Kea DHCP to Unbound DNS registration (DDNS bridge)
www: https://github.com/tkreagan/os-kea-ubnd-ddns
maintainer: tk@rgn.ltd
prefix: /usr/local
desc: <<EOD
Automatically registers Kea DHCP leases and static reservations in Unbound DNS.
Runs an RFC 2136 DNS UPDATE stub listener for kea-dhcp-ddns, plus on-demand
synchronisation scripts and a scheduled stale-record cleanup.
EOD
deps: {{
  py313-dnspython: {{origin: "net/py-dnspython", version: "2.8"}}
}}
scripts: {{
  pre-deinstall: {pre_deinstall};
  post-deinstall: {post_deinstall};
}}
{files_section}
"""

with open(stage + '/+MANIFEST', 'w') as f:
    f.write(manifest)
print(f"    +MANIFEST written ({len(files_lines)} files, lifecycle scripts)")
PYEOF

    # ── Build package ─────────────────────────────────────────────────────────
    pkg create -M "$STAGE/+MANIFEST" -r "$STAGE" -o /tmp/

    # Detect actual output file (FreeBSD 14+ uses .pkg/zstd; older used .txz)
    ACTUAL_OUT=$(ls /tmp/${PKGNAME}-${VERSION}.pkg /tmp/${PKGNAME}-${VERSION}.txz 2>/dev/null | head -1)
    if [ -z "$ACTUAL_OUT" ]; then
        echo "ERROR: pkg create produced no output file in /tmp/" >&2
        exit 1
    fi
    OUTFILE_REMOTE="$ACTUAL_OUT"

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
        -czf /tmp/keaubnd-build.tar.gz \
        -C "$REPO" \
        Makefile pkg-descr src build_package.sh

    echo "==> Uploading to ${HOST}..."
    SSH_AUTH_SOCK="" scp $SSH_OPTS /tmp/keaubnd-build.tar.gz "${REMOTE}:/tmp/"

    echo "==> Building package on ${HOST}..."
    # shellcheck disable=SC2087
    SSH_AUTH_SOCK="" ssh $SSH_OPTS "$REMOTE" 'sh -s' << 'REMOTE_HEREDOC'
set -e
cd /tmp
rm -rf keaubnd-build && mkdir keaubnd-build
tar --no-xattrs --no-acls --no-fflags \
    -xzf /tmp/keaubnd-build.tar.gz -C /tmp/keaubnd-build
cd /tmp/keaubnd-build
sudo -n sh build_package.sh
rm -rf /tmp/keaubnd-build /tmp/keaubnd-build.tar.gz
REMOTE_HEREDOC

    echo "==> Downloading package..."
    # Detect actual remote filename (.pkg on FreeBSD 14+, .txz on older)
    REMOTE_FILE=$(SSH_AUTH_SOCK="" ssh $SSH_OPTS "$REMOTE" \
        "ls /tmp/${PKGNAME}-${VERSION}.pkg /tmp/${PKGNAME}-${VERSION}.txz 2>/dev/null | head -1")
    if [ -z "$REMOTE_FILE" ]; then
        echo "ERROR: Cannot find built package on ${HOST}" >&2
        exit 1
    fi
    EXT="${REMOTE_FILE##*.}"
    OUTFILE_LOCAL="${REPO}/${PKGNAME}-${VERSION}.${EXT}"
    SSH_AUTH_SOCK="" scp $SSH_OPTS "${REMOTE}:${REMOTE_FILE}" "$OUTFILE_LOCAL"
    echo "Package: ${OUTFILE_LOCAL}"
}

# ── Dispatch ──────────────────────────────────────────────────────────────────
if [ "$(uname)" = "FreeBSD" ]; then
    _build_on_box
else
    _build_remotely
fi
