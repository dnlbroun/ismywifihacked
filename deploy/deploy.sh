#!/usr/bin/env bash
# Deploy the current working tree to the server. Run from the repo root on your laptop:
#   deploy/deploy.sh <admin-user>@<server>
set -euo pipefail
TARGET="${1:?usage: deploy/deploy.sh user@host}"
cd "$(dirname "$0")/.."

# Ship exactly what's tested: refuse if the lockfile is out of date.
uv lock --check

rsync -az --delete \
  --exclude .git --exclude .venv --exclude data/ --exclude '__pycache__' \
  --exclude .mypy_cache --exclude .ruff_cache --exclude .pytest_cache --exclude tests/ \
  ./ "${TARGET}:/tmp/netcheck-release/"

ssh "${TARGET}" sudo bash -s <<'REMOTE'
set -euo pipefail
install -d -m 755 /opt/netcheck/app
rsync -a --delete --exclude .venv /tmp/netcheck-release/ /opt/netcheck/app/
rm -rf /tmp/netcheck-release
chown -R root:root /opt/netcheck/app
cd /opt/netcheck/app
# Python and the venv live under /opt so sandboxed services (ProtectHome) can run them.
UV_PYTHON_INSTALL_DIR=/opt/netcheck/python UV_CACHE_DIR=/opt/netcheck/uv-cache \
  /usr/local/bin/uv sync --locked --no-dev --python 3.12
chmod -R go-w /opt/netcheck

if [ ! -s /var/lib/netcheck/asn/ip2asn-combined.tsv.gz ]; then
  /opt/netcheck/app/scripts/fetch-asn-db.sh /var/lib/netcheck/asn
fi

install -m 644 deploy/systemd/*.service deploy/systemd/*.timer /etc/systemd/system/
install -m 644 deploy/Caddyfile /etc/caddy/Caddyfile
caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile >/dev/null
systemctl daemon-reload
systemctl enable --now netcheck-asn-update.timer netcheck-health.timer
systemctl enable netcheck-dns netcheck-web caddy
systemctl restart netcheck-dns netcheck-web caddy
sleep 3
systemctl --no-pager --lines=0 status netcheck-dns netcheck-web caddy | grep -E "●|Active:"
REMOTE
