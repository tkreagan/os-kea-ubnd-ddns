#!/bin/sh
# Deploy to orbison and run integration tests.
# Requires: OPNSENSE_HOST, OPNSENSE_API_KEY, OPNSENSE_API_SECRET in environment
# or tests/.env file.
set -e

REPO="$(cd "$(dirname "$0")/.." && pwd)"

# Load .env if present
if [ -f "$REPO/tests/.env" ]; then
    # shellcheck disable=SC1090
    set -a && . "$REPO/tests/.env" && set +a
fi

if [ -z "$OPNSENSE_HOST" ]; then
    echo "ERROR: OPNSENSE_HOST is not set. Copy tests/.env.example to tests/.env and fill it in."
    exit 1
fi

SSH_USER="${OPNSENSE_SSH_USER:-tkr}"

echo "==> Building tarball..."
cd "$REPO"
COPYFILE_DISABLE=1 tar \
    --exclude='__pycache__' \
    --exclude='.DS_Store' \
    --exclude='._*' \
    --exclude='*.pyc' \
    -czf /tmp/keaunbound-full.tar.gz \
    -C src .

echo "==> Uploading to $OPNSENSE_HOST..."
scp -o ConnectTimeout=10 /tmp/keaunbound-full.tar.gz \
    "$SSH_USER@$OPNSENSE_HOST:/tmp/"

echo "==> Extracting on $OPNSENSE_HOST..."
ssh -o ConnectTimeout=20 "$SSH_USER@$OPNSENSE_HOST" 'sh -s' <<'EOF'
sudo -n tar --no-xattrs --no-acls --no-fflags \
    -xzf /tmp/keaunbound-full.tar.gz -C /usr/local
sudo -n /usr/local/sbin/pluginctl -s webgui restart
EOF

echo "==> Running integration tests..."
cd "$REPO"
python3 -m pytest tests/integration/ -v --tb=short -m integration "$@"
