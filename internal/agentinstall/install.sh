#!/bin/sh
# DeusWatch agent one-line installer (Linux). Run via:
#   curl -fsSL http://MANAGER:8080/api/agent/install.sh | sudo MANAGER=<ip> TOKEN=<token> NAME=<name> sh
set -e

[ -n "$MANAGER" ] || { echo "DeusWatch: MANAGER is required" >&2; exit 1; }
[ -n "$TOKEN" ]   || { echo "DeusWatch: TOKEN is required" >&2; exit 1; }
NAME="${NAME:-$(hostname)}"
API_PORT="${API_PORT:-8080}"
GW_PORT="${GW_PORT:-8443}"
API="http://$MANAGER:$API_PORT"
GW="https://$MANAGER:$GW_PORT"

echo "DeusWatch: installing agent '$NAME' -> $GW"

# Best-effort: allow outbound to the manager through a local firewall.
if command -v ufw >/dev/null 2>&1; then
  ufw allow out "$API_PORT"/tcp >/dev/null 2>&1 || true
  ufw allow out "$GW_PORT"/tcp  >/dev/null 2>&1 || true
fi
if command -v firewall-cmd >/dev/null 2>&1; then
  firewall-cmd --permanent --add-port="$GW_PORT"/tcp >/dev/null 2>&1 || true
  firewall-cmd --reload >/dev/null 2>&1 || true
fi

# Stop any already-running agent first, so overwriting its binary can't fail with
# "text file busy" / curl error 23 (makes re-install idempotent).
systemctl stop deuswatch-agent 2>/dev/null || true

# Detect arch and download the matching binary from the manager.
case "$(uname -m)" in
  x86_64)        ARCH=amd64 ;;
  aarch64|arm64) ARCH=arm64 ;;
  *)             ARCH=amd64 ;;
esac
# Download to a temp file then move it into place atomically: never write directly over
# the running executable (that's what triggers ETXTBSY / curl (23) on re-install).
curl -fsSL "$API/api/agent/binary/linux/$ARCH" -o /usr/local/bin/deuswatch-agent.new
chmod +x /usr/local/bin/deuswatch-agent.new
mv -f /usr/local/bin/deuswatch-agent.new /usr/local/bin/deuswatch-agent
mkdir -p /etc/deuswatch/certs /var/lib/deuswatch/buffer

# Enroll: exchange the one-time token for a unique client certificate.
/usr/local/bin/deuswatch-agent -enroll -token "$TOKEN" -name "$NAME" -manager "$API" -out /etc/deuswatch/certs

# Config + systemd service (auto-start, restart on failure).
cat >/etc/deuswatch/agent.env <<EOF
GATEWAY_URL=$GW
CERT_DIR=/etc/deuswatch/certs
BUFFER_DIR=/var/lib/deuswatch/buffer
EOF

cat >/etc/systemd/system/deuswatch-agent.service <<'UNIT'
[Unit]
Description=DeusWatch Agent
After=network-online.target
Wants=network-online.target

[Service]
EnvironmentFile=/etc/deuswatch/agent.env
ExecStart=/usr/local/bin/deuswatch-agent
Restart=always
RestartSec=5
SupplementaryGroups=adm systemd-journal

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable --now deuswatch-agent
echo "DeusWatch: agent '$NAME' installed & started (systemctl status deuswatch-agent)"
