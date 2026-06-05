#!/bin/sh
# Lint checks for os-kea-unbound.
# Run from repo root: sh tests/lint/run_lint.sh
# Requires: ruff (pip install ruff), php, xmllint
set -e

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
ERRORS=0

fail() { echo "FAIL: $1"; ERRORS=$((ERRORS + 1)); }
pass() { echo "ok:   $1"; }

# ── macOS artifact check (must be first — catches the ._General.xml failure) ──
echo "==> no macOS AppleDouble sidecars in src/:"
SIDECARS=$(find "$REPO/src" -name '._*' 2>/dev/null)
if [ -n "$SIDECARS" ]; then
    echo "$SIDECARS"
    fail "AppleDouble sidecar files in src/ — delete them and re-tar with COPYFILE_DISABLE=1"
else
    pass "no AppleDouble sidecars"
fi

echo "==> no .DS_Store in src/:"
DS=$(find "$REPO/src" -name '.DS_Store' 2>/dev/null)
if [ -n "$DS" ]; then
    echo "$DS"
    fail ".DS_Store files in src/"
else
    pass "no .DS_Store"
fi

echo "==> no __pycache__ or .pyc in src/:"
PYC=$(find "$REPO/src" \( -name '__pycache__' -o -name '*.pyc' \) 2>/dev/null)
if [ -n "$PYC" ]; then
    echo "$PYC"
    fail "__pycache__ or .pyc files in src/ (these get packaged)"
else
    pass "no compiled Python artifacts"
fi

echo "==> model XML filenames are plain (no leading ._):"
BAD_XML=$(find "$REPO/src/opnsense/mvc/app/models" -name '*.xml' 2>/dev/null \
    | awk -F/ '{if ($NF ~ /^\._/) print}')
if [ -n "$BAD_XML" ]; then
    echo "$BAD_XML"
    fail "._*.xml model files found — OPNsense ConfigMaintenance::loadModels() will crash"
else
    pass "model XML filenames OK"
fi

# ── Python — PEP 8 / style ────────────────────────────────────────────────────
if command -v ruff > /dev/null 2>&1; then
    echo "==> ruff"
    ruff check "$REPO/src/opnsense/scripts/keaunbound/" \
               "$REPO/src/sbin/" && pass "ruff" || fail "ruff found issues"
else
    echo "SKIP: ruff not installed (pip install ruff)"
fi

# ── Python — no bare except ───────────────────────────────────────────────────
echo "==> no bare except:"
if grep -rn "^except:$" \
        "$REPO/src/opnsense/scripts/keaunbound/" \
        "$REPO/src/sbin/" 2>/dev/null; then
    fail "bare except: found"
else
    pass "no bare except"
fi

# ── Python — no mwexec() ─────────────────────────────────────────────────────
echo "==> no mwexec():"
if grep -rn "mwexec(" \
        "$REPO/src/opnsense/scripts/keaunbound/" \
        "$REPO/src/sbin/" \
        "$REPO/src/etc/inc/" 2>/dev/null; then
    fail "mwexec() found (use mwexecf() or exec())"
else
    pass "no mwexec()"
fi

# ── Python — syslog tag must be kea-ub ────────────────────────────────────────
echo "==> syslog tag kea-ub:"
BAD=$(grep -rn "openlog" \
        "$REPO/src/opnsense/scripts/keaunbound/" \
        "$REPO/src/sbin/" 2>/dev/null | grep -v "kea-ub" || true)
if [ -n "$BAD" ]; then
    echo "$BAD"
    fail "openlog() call without kea-ub tag"
else
    pass "syslog tag kea-ub"
fi

# ── Python — SPDX headers ────────────────────────────────────────────────────
echo "==> SPDX headers:"
MISSING=$(find "$REPO/src/opnsense/scripts/keaunbound/" "$REPO/src/sbin/" \
    -name "*.py" ! -name "__init__.py" \
    | xargs grep -L "SPDX-License-Identifier" 2>/dev/null || true)
if [ -n "$MISSING" ]; then
    echo "$MISSING"
    fail "SPDX header missing"
else
    pass "SPDX headers present"
fi

# ── PHP — syntax check ────────────────────────────────────────────────────────
echo "==> php -l:"
PHP_ERR=0
for f in $(find "$REPO/src/opnsense/mvc/app/" -name "*.php" 2>/dev/null); do
    php -l "$f" > /dev/null 2>&1 || { echo "  FAIL: $f"; PHP_ERR=1; }
done
for f in $(find "$REPO/src/etc/inc/" -name "*.inc" 2>/dev/null); do
    php -l "$f" > /dev/null 2>&1 || { echo "  FAIL: $f"; PHP_ERR=1; }
done
[ "$PHP_ERR" -eq 0 ] && pass "php -l" || fail "PHP syntax errors found"

# ── PHP — no require_once in MVC controllers ─────────────────────────────────
echo "==> no require_once in MVC:"
if grep -rn "require_once" "$REPO/src/opnsense/mvc/app/controllers/" 2>/dev/null; then
    fail "require_once in MVC controller (use OPNsense MVC patterns)"
else
    pass "no require_once in MVC"
fi

# ── Configd actions format ────────────────────────────────────────────────────
echo "==> configd actions type=script_output:"
ACTIONS="$REPO/src/opnsense/service/conf/actions.d/actions_keaunbound.conf"
if [ -f "$ACTIONS" ]; then
    BAD=$(grep "^type:" "$ACTIONS" | grep -v "script_output" || true)
    if [ -n "$BAD" ]; then
        echo "$BAD"
        fail "configd action uses deprecated type (not script_output)"
    else
        pass "configd actions type=script_output"
    fi
else
    fail "actions_keaunbound.conf not found"
fi

# ── XML models well-formed ────────────────────────────────────────────────────
echo "==> XML well-formed:"
XML_ERR=0
for f in $(find "$REPO/src/opnsense/mvc/" -name "*.xml" 2>/dev/null); do
    xmllint --noout "$f" 2>/dev/null || { echo "  FAIL: $f"; XML_ERR=1; }
done
[ "$XML_ERR" -eq 0 ] && pass "XML well-formed" || fail "XML parse errors"

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
if [ "$ERRORS" -eq 0 ]; then
    echo "All lint checks passed."
    exit 0
else
    echo "$ERRORS lint check(s) failed."
    exit 1
fi
