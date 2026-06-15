#!/usr/bin/env bash
# build-release.sh — Build a distributable os-kea-ubnd-ddns package for release.
#
# Rolls back dev-opnsense to its latest clean snapshot, builds the .txz
# package on that box using pkg(8), downloads it locally, and prints the
# git push commands to publish source to both remotes.
#
# The .txz is gitignored — only source is committed and pushed.
#
# Usage:
#   bash tools/setup/build-release.sh [--skip-rollback]
#
#   --skip-rollback  Skip the snapshot rollback step. Use when you want to
#                    rebuild the package without resetting the VM state.
#
# Requires tools/.env with PROXMOX_API_TOKEN (unless --skip-rollback).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

step() { echo; echo "==> $*"; }
info() { echo "    $*"; }
die()  { echo "ERROR: $*" >&2; exit 1; }

# ── Load .env ─────────────────────────────────────────────────────────────────
ENV_FILE="${ENV_FILE:-$REPO_ROOT/tools/.env}"
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
OPN_HOST="${DEV_OPNSENSE_HOST:-dev-opnsense.plhm.rgn.cm}"

VERSION=$(grep '^PLUGIN_VERSION' "$REPO_ROOT/Makefile" | awk '{print $NF}')
# pkg(8) uses .pkg on FreeBSD 14+; detect whichever exists after build
PKGFILE=""

# ── Parse args ────────────────────────────────────────────────────────────────
SKIP_ROLLBACK=0
for arg in "$@"; do
    case "$arg" in
        --skip-rollback) SKIP_ROLLBACK=1 ;;
        --help|-h)
            sed -n '/^#/!q; s/^# \?//p' "$0" | head -16
            exit 0 ;;
        *) die "Unknown argument: $arg" ;;
    esac
done

echo
echo "============================================================"
echo "  os-kea-ubnd-ddns release build v${VERSION}"
echo "============================================================"

# ── 1. Rollback to clean snapshot ─────────────────────────────────────────────
if [[ "$SKIP_ROLLBACK" -eq 0 ]]; then
    step "Rolling back dev-opnsense (VM ${VM_OPN}) to latest snapshot"
    ENV_FILE="$ENV_FILE" bash "$SCRIPT_DIR/rollback-vm.sh" \
        "$VM_OPN" "$OPN_HOST" --latest
else
    step "Skipping snapshot rollback (--skip-rollback)"
fi

# ── 2. Build package ──────────────────────────────────────────────────────────
step "Building package on ${OPN_HOST}"
bash "$REPO_ROOT/build_package.sh"

# ── 3. Verify local package ───────────────────────────────────────────────────
step "Verifying package"
# Detect whichever format pkg(8) produced (.pkg on FreeBSD 14+, .txz on older)
PKGFILE=$(ls "${REPO_ROOT}/os-kea-ubnd-ddns-${VERSION}".pkg \
              "${REPO_ROOT}/os-kea-ubnd-ddns-${VERSION}".txz 2>/dev/null | head -1 || true)
[[ -n "$PKGFILE" && -f "$PKGFILE" ]] || die "Package not found after build (looked for .pkg and .txz)"
SUM=$(shasum -a 256 "$PKGFILE" | awk '{print $1}')
info "$(basename "$PKGFILE")"
info "sha256: ${SUM}"

# ── 4. Check for uncommitted source changes ───────────────────────────────────
step "Git status"
cd "$REPO_ROOT"
if ! git diff --quiet HEAD -- src/ Makefile pkg-descr build_package.sh tools/setup/; then
    info "Uncommitted changes present:"
    git diff --stat HEAD -- src/ Makefile pkg-descr build_package.sh tools/setup/
    echo
    info "Commit source changes before pushing."
else
    info "Source tree is clean."
fi

BRANCH=$(git rev-parse --abbrev-ref HEAD)
AHEAD_ORIGIN=$(git rev-list --count origin/"$BRANCH"..HEAD 2>/dev/null || echo "?")
AHEAD_GITHUB=$(git rev-list --count github/"$BRANCH"..HEAD 2>/dev/null || echo "?")
info "Branch: ${BRANCH}  (${AHEAD_ORIGIN} commits ahead of origin, ${AHEAD_GITHUB} ahead of github)"

# ── 5. Summary ────────────────────────────────────────────────────────────────
echo
echo "============================================================"
echo "  Package:  $(basename "$PKGFILE")"
echo "  sha256:   ${SUM}"
echo
echo "  To publish source:"
echo "    git push origin ${BRANCH}"
echo "    git push github ${BRANCH}"
echo
echo "  To install on production:"
PROD="${PROD_HOST:-orbison.plhm.rgn.cm}"
PROD_USER="${PROD_SSH_USER:-root}"
echo "    scp $(basename "$PKGFILE") ${PROD_USER}@${PROD}:/tmp/"
echo "    ssh ${PROD} 'sudo pkg add /tmp/$(basename "$PKGFILE")'"
echo "============================================================"
