#!/bin/sh
# DeusWatch agent one-line installer (macOS). Run via:
#   curl -fsSL http://MANAGER:8080/api/agent/install-macos.sh | sudo MANAGER=<ip> TOKEN=<token> NAME=<name> sh
#
# Separate from install.sh rather than branching inside it: macOS has no systemd and no
# journald, the paths differ, and a single script with two service managers in it is the kind
# of thing that breaks both.
set -e

[ -n "$MANAGER" ] || { echo "DeusWatch: MANAGER is required" >&2; exit 1; }
[ -n "$TOKEN" ]   || { echo "DeusWatch: TOKEN is required" >&2; exit 1; }
NAME="${NAME:-$(hostname -s)}"
API_PORT="${API_PORT:-8080}"
GW_PORT="${GW_PORT:-8443}"
API="http://$MANAGER:$API_PORT"
GW="https://$MANAGER:$GW_PORT"
LABEL="com.deuswatch.agent"
PLIST="/Library/LaunchDaemons/$LABEL.plist"

[ "$(id -u)" = "0" ] || { echo "DeusWatch: run this with sudo" >&2; exit 1; }

echo "DeusWatch: installing agent '$NAME' -> $GW"

# Stop any already-running agent first, so overwriting its binary cannot fail with
# "text file busy" (makes re-install idempotent).
launchctl bootout "system/$LABEL" 2>/dev/null || true

case "$(uname -m)" in
  x86_64)        ARCH=amd64 ;;
  arm64|aarch64) ARCH=arm64 ;;
  *)             ARCH=arm64 ;;
esac

mkdir -p /usr/local/bin /etc/deuswatch/certs /var/lib/deuswatch/buffer /var/log/deuswatch

# Download to a temp file then move it into place atomically: never write directly over the
# running executable.
curl -fsSL "$API/api/agent/binary/darwin/$ARCH" -o /usr/local/bin/deuswatch-agent.new
chmod +x /usr/local/bin/deuswatch-agent.new
mv -f /usr/local/bin/deuswatch-agent.new /usr/local/bin/deuswatch-agent

# Enroll: exchange the one-time token for a unique client certificate.
/usr/local/bin/deuswatch-agent -enroll -token "$TOKEN" -name "$NAME" -manager "$API" -out /etc/deuswatch/certs

cat >"$PLIST" <<PL
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>$LABEL</string>
  <key>ProgramArguments</key><array><string>/usr/local/bin/deuswatch-agent</string></array>
  <key>EnvironmentVariables</key><dict>
    <key>GATEWAY_URL</key><string>$GW</string>
    <key>CERT_DIR</key><string>/etc/deuswatch/certs</string>
    <key>BUFFER_DIR</key><string>/var/lib/deuswatch/buffer</string>
  </dict>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardOutPath</key><string>/var/log/deuswatch/agent.log</string>
  <key>StandardErrorPath</key><string>/var/log/deuswatch/agent.log</string>
</dict>
</plist>
PL
chmod 644 "$PLIST"
chown root:wheel "$PLIST"

launchctl bootstrap system "$PLIST"
launchctl enable "system/$LABEL"
echo "DeusWatch: agent '$NAME' installed & started (launchctl print system/$LABEL)"
echo "DeusWatch: note, give /usr/local/bin/deuswatch-agent Full Disk Access in System Settings"
echo "           -> Privacy & Security if you want it to read protected paths."
