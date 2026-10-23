#!/usr/bin/env bash
# Disable root SSH login. Run only after confirming the admin user can log in and sudo.
set -euo pipefail
echo "PermitRootLogin no" > /etc/ssh/sshd_config.d/05-no-root.conf
sed -i 's/^PermitRootLogin yes/#PermitRootLogin yes  # overridden by sshd_config.d/' /etc/ssh/sshd_config
sshd -t
systemctl reload ssh
echo "root SSH login disabled"
