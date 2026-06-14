#!/usr/bin/env sh
# Install the DeusWatch agent as a systemd service.
#   sudo ./install-linux.sh [agent-binary-path]
set -e
BIN="${1:-./deuswatch-agent}"
HERE="$(dirname "$0")"

if [ "$(id -u)" -ne 0 ]; then
  echo "Run as root (sudo)." >&2
  exit 1
fi

install -m 0755 "$BIN" /usr/local/bin/deuswatch-agent
mkdir -p /etc/deuswatch/certs /var/lib/deuswatch
[ -f /etc/deuswatch/agent.env ] || install -m 0644 "$HERE/agent.env.example" /etc/deuswatch/agent.env
install -m 0644 "$HERE/deuswatch-agent.service" /etc/systemd/system/deuswatch-agent.service

systemctl daemon-reload
systemctl enable --now deuswatch-agent

echo "Agent installed. Edit /etc/deuswatch/agent.env, then:"
echo "  systemctl restart deuswatch-agent && systemctl status deuswatch-agent"
