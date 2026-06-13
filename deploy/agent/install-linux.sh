#!/usr/bin/env sh
# Install agent DeusWatch sebagai service systemd.
#   sudo ./install-linux.sh [path-biner-agent]
set -e
BIN="${1:-./deuswatch-agent}"
HERE="$(dirname "$0")"

if [ "$(id -u)" -ne 0 ]; then
  echo "Jalankan sebagai root (sudo)." >&2
  exit 1
fi

install -m 0755 "$BIN" /usr/local/bin/deuswatch-agent
mkdir -p /etc/deuswatch/certs /var/lib/deuswatch
[ -f /etc/deuswatch/agent.env ] || install -m 0644 "$HERE/agent.env.example" /etc/deuswatch/agent.env
install -m 0644 "$HERE/deuswatch-agent.service" /etc/systemd/system/deuswatch-agent.service

systemctl daemon-reload
systemctl enable --now deuswatch-agent

echo "Agent terpasang. Edit /etc/deuswatch/agent.env, lalu:"
echo "  systemctl restart deuswatch-agent && systemctl status deuswatch-agent"
