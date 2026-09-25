#!/bin/bash
# =============================================================================
# Install Mina Local Daemon as a systemd service (Linux)
# =============================================================================
# Profiles:
#   low-spec (default) — tuned for weak laptops (Bay Trail-class low-spec):
#       MemoryMax=100M  MemoryHigh=80M  MemorySwapMax=0
#       CPUWeight=20    Nice=10         IOSchedulingClass=idle
#       OOMPolicy=continue (a killed child never takes the daemon down)
#   normal             — no resource caps (MINA_PROFILE=normal)
#
# Usage:
#   sudo MINA_PROFILE=low-spec bash install_service.sh          # system service
#   sudo MINA_PROFILE=low-spec bash install_service.sh --user   # user service (GUI-friendly)
#
# Overridable knobs (env):
#   MINA_MEMORY_MAX=100M   MINA_MEMORY_HIGH=80M   MINA_CPU_WEIGHT=20
#   MINA_NICE=10           MINA_POLKIT=1 (install power polkit rule, system mode)
#   MINA_DAEMON_PORT=8765
# =============================================================================
set -e

DAEMON_DIR="$(cd "$(dirname "$0")" && pwd)"
DAEMON_PATH="$DAEMON_DIR/mina_daemon.py"
PROFILE="${MINA_PROFILE:-low-spec}"
PORT="${MINA_DAEMON_PORT:-8765}"

MEMORY_MAX="${MINA_MEMORY_MAX:-100M}"
MEMORY_HIGH="${MINA_MEMORY_HIGH:-80M}"
CPU_WEIGHT="${MINA_CPU_WEIGHT:-20}"
NICE="${MINA_NICE:-10}"
POLKIT="${MINA_POLKIT:-1}"
INSTALL_POLKIT_RULE=0

SERVICE_MODE="system"
if [ "$1" = "--user" ]; then
  SERVICE_MODE="user"
fi

# ── Source environment if .env exists ────────────────────────────
ENV_FILE="$DAEMON_DIR/../.env"
if [ -f "$ENV_FILE" ]; then
  # shellcheck disable=SC1090
  source "$ENV_FILE"
fi

if [ -z "$MINA_API_KEY" ] || [ -z "$MINA_HMAC_SECRET" ]; then
  echo "ERROR: Set MINA_API_KEY and MINA_HMAC_SECRET in $ENV_FILE"
  exit 1
fi

# ── Resource-limit block (low-spec profile) ──────────────────────
if [ "$PROFILE" = "low-spec" ]; then
  RESOURCE_BLOCK="
# ── Resource limits (low-spec profile — low-spec class hardware) ──
MemoryAccounting=yes
MemoryHigh=${MEMORY_HIGH}
MemoryMax=${MEMORY_MAX}
MemorySwapMax=0
CPUWeight=${CPU_WEIGHT}
Nice=${NICE}
IOSchedulingClass=idle
IOSchedulingPriority=7
OOMPolicy=continue
# Hard CPU ceiling (uncomment to throttle bursts further):
#CPUQuota=25%"
  echo "✓ Profile: low-spec (RAM max ${MEMORY_MAX}, nice ${NICE}, cpu weight ${CPU_WEIGHT})"
else
  RESOURCE_BLOCK=""
  echo "✓ Profile: normal (no resource caps)"
fi

COMMON_BLOCK="Type=simple
WorkingDirectory=$DAEMON_DIR
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=mina-daemon"

UNIT_LIMITS="StartLimitIntervalSec=60
StartLimitBurst=5"

# ═════════════════════════════════════════════════════════════════
# USER SERVICE MODE — runs in the desktop session (GUI actions work,
# loginctl/polkit see an active session). Requires: loginctl
# enable-linger $USER  (so it starts at boot without login).
# ═════════════════════════════════════════════════════════════════
if [ "$SERVICE_MODE" = "user" ]; then
  if [ "$EUID" -eq 0 ]; then
    echo "ERROR: --user mode must run WITHOUT sudo (as the desktop user)."
    exit 1
  fi
  UNIT_DIR="$HOME/.config/systemd/user"
  SERVICE_FILE="$UNIT_DIR/mina-daemon.service"
  ENV_TARGET="$HOME/.mina/mina.env"
  mkdir -p "$UNIT_DIR" "$HOME/.mina"
  umask 077
  cat > "$ENV_TARGET" << ENVEOF
MINA_API_KEY=$MINA_API_KEY
MINA_HMAC_SECRET=$MINA_HMAC_SECRET
MINA_DAEMON_PORT=$PORT
ENVEOF
  chmod 600 "$ENV_TARGET"
  cat > "$SERVICE_FILE" << EOF
[Unit]
Description=Mina Local Daemon — Remote Device Control (user session)
After=network.target
$UNIT_LIMITS

[Service]
$COMMON_BLOCK
EnvironmentFile=$ENV_TARGET
ExecStart=/usr/bin/python3 $DAEMON_PATH --host 127.0.0.1 --port $PORT
$RESOURCE_BLOCK

[Install]
WantedBy=default.target
EOF
  systemctl --user daemon-reload
  systemctl --user enable --now mina-daemon
  echo "✓ Mina daemon installed as USER service and started"
  echo "  Status: systemctl --user status mina-daemon"
  echo "  Logs:   journalctl --user -u mina-daemon -f"
  echo "  Boot persistence: loginctl enable-linger $USER"
  exit 0
fi

# ═════════════════════════════════════════════════════════════════
# SYSTEM SERVICE MODE (default)
# ═════════════════════════════════════════════════════════════════
if [ "$EUID" -ne 0 ]; then
  echo "Please run as root: sudo bash install_service.sh"
  exit 1
fi

SERVICE_FILE="/etc/systemd/system/mina-daemon.service"
ENV_TARGET="/etc/mina/mina.env"

# Secrets live in a root-only file, NOT in the unit (systemctl cat stays clean)
mkdir -p /etc/mina
umask 077
cat > "$ENV_TARGET" << ENVEOF
MINA_API_KEY=$MINA_API_KEY
MINA_HMAC_SECRET=$MINA_HMAC_SECRET
MINA_DAEMON_PORT=$PORT
ENVEOF
chmod 600 "$ENV_TARGET"
chown root:root "$ENV_TARGET"

cat > "$SERVICE_FILE" << EOF
[Unit]
Description=Mina Local Daemon — Remote Device Control
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=60
StartLimitBurst=5

[Service]
$COMMON_BLOCK
User=${SUDO_USER:-root}
EnvironmentFile=$ENV_TARGET
ExecStart=/usr/bin/python3 $DAEMON_PATH --host 127.0.0.1 --port $PORT
$RESOURCE_BLOCK
# GUI actions from a system service need the desktop session's env —
# uncomment and adjust if you want open_app/open_url/dashboard to render:
#Environment=DISPLAY=:0
#Environment=XDG_RUNTIME_DIR=/run/user/1000
#Environment=DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus

[Install]
WantedBy=multi-user.target
EOF

# ── Optional: polkit rule so power actions work from the service ─
# Without it, logind may require an interactive admin auth for
# poweroff/reboot/suspend when the user session is not active.
if [ "$POLKIT" = "1" ] && [ -n "$SUDO_USER" ]; then
  RULE_FILE="/etc/polkit-1/rules.d/49-mina-power.rules"
  cat > "$RULE_FILE" << EOF
// Mina daemon power management — allow $SUDO_USER without interactive auth
polkit.addRule(function(action, subject) {
    if ((action.id == "org.freedesktop.login1.power-off" ||
         action.id == "org.freedesktop.login1.reboot" ||
         action.id == "org.freedesktop.login1.suspend" ||
         action.id == "org.freedesktop.login1.hibernate" ||
         action.id == "org.freedesktop.login1.power-off-multiple-sessions" ||
         action.id == "org.freedesktop.login1.reboot-multiple-sessions") &&
        subject.user == "$SUDO_USER") {
        return polkit.Result.YES;
    }
});
EOF
  INSTALL_POLKIT_RULE=1
  echo "✓ polkit rule installed: $RULE_FILE (user: $SUDO_USER)"
fi

# ── Verify unit syntax before starting ───────────────────────────
if command -v systemd-analyze >/dev/null 2>&1; then
  if systemd-analyze verify "$SERVICE_FILE" 2>/dev/null; then
    echo "✓ systemd-analyze verify: unit OK"
  else
    echo "WARN: systemd-analyze verify reported issues — check $SERVICE_FILE"
  fi
fi

systemctl daemon-reload
systemctl enable mina-daemon
systemctl start mina-daemon
sleep 1
if systemctl is-active --quiet mina-daemon; then
  echo "✓ Mina daemon installed and started"
else
  echo "✗ Daemon failed to start — check: journalctl -u mina-daemon -n 50"
  exit 1
fi

echo
echo "  Status:  systemctl status mina-daemon"
echo "  Logs:    journalctl -u mina-daemon -f"
echo "  Memory:  systemctl show mina-daemon -p MemoryMax -p MemoryHigh -p CPUWeight -p Nice"
echo "  Runtime: systemd-cgtop -1 --order=memory | grep mina"
echo "  Env:     $ENV_TARGET (chmod 600)"
[ "$INSTALL_POLKIT_RULE" = "1" ] && echo "  Polkit:  /etc/polkit-1/rules.d/49-mina-power.rules"
