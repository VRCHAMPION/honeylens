#!/bin/sh
# Move the REAL admin SSH daemon from port 22 to a high port (22022), so Cowrie
# can take port 22. STATUS: UNVERIFIED on a real cloud VM.
#
#   sudo sh deploy/move-admin-ssh.sh 22022
#
# SAFETY: keep your current SSH session open until you have logged in on the
# new port in a SECOND terminal. Reach the new port over Tailscale or a cloud
# bastion; a public rule from your own IP only is a fallback (DEPLOY_CLOUD.md step 7).
set -eu
PORT="${1:-22022}"
case "$PORT" in ''|*[!0-9]*) echo "port must be a number"; exit 1;; esac
CONF=/etc/ssh/sshd_config.d/10-honeylens-admin.conf
cat > "$CONF" <<CFG
# HoneyLens: real admin SSH on port $PORT, keys only (reach it over Tailscale/bastion).
Port $PORT
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin no
MaxAuthTries 3
CFG
sshd -t   # validate config before restarting
# Ubuntu 22.04+/24.04 uses socket activation; update the socket too if present.
if systemctl list-unit-files | grep -q '^ssh.socket'; then
  mkdir -p /etc/systemd/system/ssh.socket.d
  printf '[Socket]\nListenStream=\nListenStream=%s\n' "$PORT" > /etc/systemd/system/ssh.socket.d/override.conf
  systemctl daemon-reload
  systemctl restart ssh.socket
fi
systemctl restart ssh 2>/dev/null || systemctl restart sshd
echo "Admin SSH now on port $PORT. Test in a NEW terminal: ssh -p $PORT <user>@<vm-ip>"
