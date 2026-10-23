#!/usr/bin/env bash
# One-time server setup for Debian 13. Run as root: bash harden.sh <admin-user>
# Idempotent: safe to re-run.
#
# Does NOT disable root SSH login: do that with lock-root-ssh.sh only after you've
# confirmed you can log in as the admin user (avoids locking yourself out).
set -euo pipefail

ADMIN="${1:?usage: harden.sh <admin-user>}"
UV_VERSION="0.11.8"

export DEBIAN_FRONTEND=noninteractive

echo "== packages"
apt-get update -q
apt-get upgrade -yq
apt-get install -yq ufw unattended-upgrades apt-listchanges curl gpg rsync \
  debian-keyring debian-archive-keyring apt-transport-https sqlite3

echo "== automatic security updates"
cat > /etc/apt/apt.conf.d/20auto-upgrades <<'CONF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
CONF
systemctl enable --now unattended-upgrades

echo "== Caddy (official apt repo)"
if [ ! -f /usr/share/keyrings/caddy-stable-archive-keyring.gpg ]; then
  curl -1sLf --proto '=https' 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' \
    | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
  curl -1sLf --proto '=https' 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' \
    > /etc/apt/sources.list.d/caddy-stable.list
  apt-get update -q
fi
apt-get install -yq caddy

echo "== uv ${UV_VERSION} (system-wide, outside /root so sandboxed services can use it)"
if ! /usr/local/bin/uv --version 2>/dev/null | grep -q "${UV_VERSION}"; then
  curl -LsSf --proto '=https' "https://astral.sh/uv/${UV_VERSION}/install.sh" \
    | env UV_INSTALL_DIR=/usr/local/bin UV_NO_MODIFY_PATH=1 sh
fi

echo "== admin user ${ADMIN} (key-only, passwordless sudo)"
if ! id "${ADMIN}" >/dev/null 2>&1; then
  adduser --disabled-password --gecos "" "${ADMIN}"
fi
usermod -aG sudo "${ADMIN}"
install -d -m 700 -o "${ADMIN}" -g "${ADMIN}" "/home/${ADMIN}/.ssh"
install -m 600 -o "${ADMIN}" -g "${ADMIN}" /root/.ssh/authorized_keys "/home/${ADMIN}/.ssh/authorized_keys"
echo "${ADMIN} ALL=(ALL) NOPASSWD:ALL" > "/etc/sudoers.d/90-${ADMIN}"
chmod 440 "/etc/sudoers.d/90-${ADMIN}"
visudo -cq

echo "== ssh: key-only (root login is disabled separately by lock-root-ssh.sh)"
cat > /etc/ssh/sshd_config.d/10-hardening.conf <<'CONF'
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
X11Forwarding no
AllowAgentForwarding no
CONF
sshd -t
systemctl reload ssh

echo "== stop systemd-resolved listening publicly (LLMNR/mDNS)"
install -d /etc/systemd/resolved.conf.d
cat > /etc/systemd/resolved.conf.d/10-no-llmnr.conf <<'CONF'
[Resolve]
LLMNR=no
MulticastDNS=no
CONF
systemctl restart systemd-resolved

echo "== firewall: only 22, 53, 80, 443 inbound"
ufw --force reset >/dev/null
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp
ufw allow 53
ufw allow 80/tcp
ufw allow 443
ufw --force enable

echo "== service users and directories"
for u in netcheck-web netcheck-dns; do
  id "$u" >/dev/null 2>&1 || adduser --system --group --no-create-home --home /nonexistent "$u"
done
install -d -m 755 -o root -g root /opt/netcheck /var/lib/netcheck /var/lib/netcheck/asn
install -d -m 750 -o root -g root /etc/netcheck
if [ ! -f /etc/netcheck/netcheck.env ]; then
  install -m 600 -o root -g root /dev/null /etc/netcheck/netcheck.env
  echo "!! fill in /etc/netcheck/netcheck.env (see deploy/netcheck.env.example)"
fi

echo "done. Next: confirm 'ssh ${ADMIN}@<server>' works, then run lock-root-ssh.sh"
