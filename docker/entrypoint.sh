#!/usr/bin/env bash
# Scheduled capture loop for running network_monitor.py unattended.
#
# Runs one capture per cycle into its own timestamped directory under
# REPORTS_ROOT, keeps a "latest" symlink pointing at the newest run, and
# prunes old run directories beyond RETENTION_RUNS so disk usage stays
# bounded on a long-lived home-server deployment.
#
# Shared verbatim between the Docker and systemd deployments (see the
# "Home Server Deployment (systemd, no Docker)" section of the README) -
# only APP_DIR differs between them (/app in the capture container's
# image, wherever the repo is checked out for systemd), so there's
# exactly one place this loop's logic lives.
set -euo pipefail

APP_DIR="${APP_DIR:-/app}"
REPORTS_ROOT="${REPORTS_ROOT:-/data/reports}"
CAPTURE_DURATION="${CAPTURE_DURATION:-300}"
INTERVAL_SECONDS="${INTERVAL_SECONDS:-3600}"
RETENTION_RUNS="${RETENTION_RUNS:-24}"
IFACE="${IFACE:-}"
CAPTURE_FILTER="${CAPTURE_FILTER:-}"
CAPTURE_PCAP="${CAPTURE_PCAP:-false}"
RESOLVE_HOSTNAMES="${RESOLVE_HOSTNAMES:-true}"
GEOIP_ENABLED="${GEOIP_ENABLED:-false}"
THREAT_INTEL_ENABLED="${THREAT_INTEL_ENABLED:-false}"

mkdir -p "$REPORTS_ROOT"

while true; do
    run_start=$(date +%s)
    run_id=$(date -u +%Y%m%dT%H%M%SZ)
    run_dir="$REPORTS_ROOT/$run_id"
    mkdir -p "$run_dir"

    args=(-t "$CAPTURE_DURATION" --html --csv --alerts --summary)
    if [ -n "$IFACE" ]; then
        args+=(-i "$IFACE")
    fi
    if [ -n "$CAPTURE_FILTER" ]; then
        args+=(-f "$CAPTURE_FILTER")
    fi
    if [ "$CAPTURE_PCAP" = "true" ]; then
        args+=(--pcap)
    fi
    if [ "$RESOLVE_HOSTNAMES" != "true" ]; then
        args+=(--no-hostnames)
    fi
    if [ "$GEOIP_ENABLED" = "true" ]; then
        args+=(--geoip)
    fi
    if [ "$THREAT_INTEL_ENABLED" = "true" ]; then
        args+=(--threat-intel)
    fi

    echo "[$(date -u +%FT%TZ)] starting capture run $run_id (${CAPTURE_DURATION}s)"
    if ! (cd "$run_dir" && python3 "$APP_DIR/network_monitor.py" "${args[@]}"); then
        echo "[$(date -u +%FT%TZ)] capture run $run_id failed" >&2
    fi

    # A quiet interval (no packets captured) leaves run_dir empty, since
    # network_monitor.py skips writing reports when nothing was captured.
    # Don't repoint "latest" at an empty directory in that case.
    if [ -f "$run_dir/traffic_analysis.json" ]; then
        ln -sfn "$run_dir" "$REPORTS_ROOT/latest"
    else
        echo "[$(date -u +%FT%TZ)] run $run_id captured no packets; leaving 'latest' unchanged"
        rmdir "$run_dir" 2>/dev/null || true
    fi

    mapfile -t old_runs < <(
        find "$REPORTS_ROOT" -mindepth 1 -maxdepth 1 -type d -printf '%T@ %p\n' \
            | sort -rn \
            | tail -n +$((RETENTION_RUNS + 1)) \
            | cut -d' ' -f2-
    )
    for d in "${old_runs[@]:-}"; do
        [ -n "$d" ] && rm -rf "$d"
    done

    elapsed=$(( $(date +%s) - run_start ))
    sleep_for=$(( INTERVAL_SECONDS - elapsed ))
    if [ "$sleep_for" -lt 5 ]; then
        sleep_for=5
    fi
    echo "[$(date -u +%FT%TZ)] sleeping ${sleep_for}s until next capture"
    sleep "$sleep_for"
done
