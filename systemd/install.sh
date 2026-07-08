#!/usr/bin/env bash
# Installs the systemd-based deployment (an alternative to Docker, see
# README) onto a systemd host: creates the shared group and service
# users, state/config directories, a Python venv, environment file
# templates, and the unit files - then reloads systemd so
# `systemctl enable --now network-traffic-analyzer network-traffic-dashboard`
# is all that's left.
#
# Run from within a checkout of this repo: sudo systemd/install.sh
#
# Idempotent: safe to re-run (e.g. after `git pull`) to pick up code or
# dependency changes - it never overwrites an existing env file, and
# skips already-created users/groups.
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
    echo "Run as root (sudo $0)" >&2
    exit 1
fi

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
APP_DIR="/opt/network-traffic-analyzer"
STATE_DIR="/var/lib/network-traffic-analyzer"
CONFIG_DIR="/etc/network-traffic-analyzer"

for cmd in python3 tcpdump; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "Warning: '$cmd' not found on PATH - install it before starting the capture service." >&2
    fi
done

echo "==> Creating group and service users"
getent group nettraffic >/dev/null || groupadd --system nettraffic
# -g nettraffic sets each user's *primary* group only as a sane default;
# the unit files' Group=nettraffic is what actually matters at runtime.
id -u netanalyzer >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin -g nettraffic netanalyzer
id -u netdashboard >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin -g nettraffic netdashboard

echo "==> Installing application code to $APP_DIR"
mkdir -p "$APP_DIR"
if command -v rsync >/dev/null 2>&1; then
    rsync -a --delete \
        --exclude '.git' --exclude 'venv' --exclude 'reports' --exclude 'data' \
        "$REPO_DIR"/ "$APP_DIR"/
else
    # reports/, data/, and venv/ are gitignored so a clean clone won't
    # have them, but a plain cp can't exclude them if present anyway.
    cp -a "$REPO_DIR"/. "$APP_DIR"/
fi

echo "==> Creating state and config directories"
mkdir -p "$STATE_DIR/reports" "$STATE_DIR/state" "$CONFIG_DIR"
# Capture writes reports; dashboard only needs to read them, via shared
# nettraffic group membership (same pattern as the Docker deployment).
chown netanalyzer:nettraffic "$STATE_DIR/reports"
chmod 0770 "$STATE_DIR/reports"
# Dashboard writes state (allowlist rules, resolved alerts, device names);
# capture only needs to read it, same reasoning in reverse.
chown netdashboard:nettraffic "$STATE_DIR/state"
chmod 0770 "$STATE_DIR/state"

echo "==> Setting up Python virtual environment"
if [ ! -d "$APP_DIR/venv" ]; then
    python3 -m venv "$APP_DIR/venv"
fi
"$APP_DIR/venv/bin/pip" install --quiet --upgrade pip
"$APP_DIR/venv/bin/pip" install --quiet \
    -r "$APP_DIR/requirements.txt" \
    -r "$APP_DIR/requirements-dashboard.txt"
chown -R root:nettraffic "$APP_DIR"
chmod -R o-rwx "$APP_DIR"

echo "==> Installing environment file templates"
if [ ! -f "$CONFIG_DIR/capture.env" ]; then
    install -m 0640 -o root -g nettraffic "$REPO_DIR/systemd/capture.env.example" "$CONFIG_DIR/capture.env"
    echo "    wrote $CONFIG_DIR/capture.env - edit it (set IFACE) before starting"
fi
if [ ! -f "$CONFIG_DIR/dashboard.env" ]; then
    install -m 0640 -o root -g nettraffic "$REPO_DIR/systemd/dashboard.env.example" "$CONFIG_DIR/dashboard.env"
    echo "    wrote $CONFIG_DIR/dashboard.env - set DASHBOARD_PASSWORD before starting"
fi

echo "==> Installing systemd unit files"
install -m 0644 "$REPO_DIR/systemd/network-traffic-analyzer.service" /etc/systemd/system/
install -m 0644 "$REPO_DIR/systemd/network-traffic-dashboard.service" /etc/systemd/system/
systemctl daemon-reload

cat <<EOF

Install complete. Next steps:
  1. Edit $CONFIG_DIR/capture.env (set IFACE) and $CONFIG_DIR/dashboard.env (set DASHBOARD_PASSWORD).
  2. sudo systemctl enable --now network-traffic-analyzer network-traffic-dashboard
  3. sudo systemctl status network-traffic-analyzer network-traffic-dashboard
  4. journalctl -u network-traffic-analyzer -f   # tail capture logs
     journalctl -u network-traffic-dashboard -f  # tail dashboard logs
EOF
