#!/usr/bin/env python3
"""
Dashboard web app.

Read-only Flask app that mounts the same reports/ volume the capture
container writes to and serves a live-updating dashboard plus a browser
for past runs. Never touches packet capture: no NET_RAW/NET_ADMIN needed.
"""

import hmac
import json
import os
import re
import secrets
import sys
import time
from collections import Counter
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit

from flask import Flask, abort, jsonify, redirect, render_template, request, send_from_directory, session, url_for

import alert_playbooks
import alert_rules
import device_names

SEEN_DEVICES_RUN_LIMIT = 20
DEVICE_TREND_RUN_LIMIT = 20
DEVICE_TREND_TOP_N = 5

REPORTS_ROOT = os.path.realpath(os.environ.get("REPORTS_ROOT", "/data/reports"))
LIVE_STALE_SECONDS = 5
VALID_ALERT_TYPES = {
    "PORT_SCAN",
    "HIGH_CONNECTION_RATE",
    "SUSPICIOUS_PORT",
    "LARGE_PACKET",
    "UNUSUAL_PROTOCOL_RATIO",
    "PRIVATE_TO_PUBLIC",
    "NEW_DEVICE",
    "THREAT_INTEL_MATCH",
}

RUN_ID_RE = re.compile(r"^\d{8}T\d{6}Z$")
MAX_NOTE_LENGTH = 500

# The dashboard can silently suppress security alerts (allowlist) and
# exposes raw packet captures, so - unlike the read-only report files it
# serves - it refuses to run without a login gate. No insecure default.
DASHBOARD_PASSWORD = os.environ.get("DASHBOARD_PASSWORD")
if not DASHBOARD_PASSWORD:
    sys.exit(
        "DASHBOARD_PASSWORD is not set. The dashboard can suppress security "
        "alerts (allowlist) and serves packet captures, so it refuses to "
        "start without a login password. Set DASHBOARD_PASSWORD in your "
        ".env file."
    )

app = Flask(__name__)

# Off by default: trusting X-Forwarded-* headers when nothing is actually
# stripping/setting them at the network edge would let any client spoof
# its own source IP (defeating the login throttle) or scheme. Set this
# only when the dashboard genuinely sits behind a reverse proxy that
# terminates TLS and sets these headers itself - see the README's
# "TLS / Reverse Proxy" section.
BEHIND_TLS_PROXY = os.environ.get("DASHBOARD_BEHIND_TLS_PROXY", "").strip().lower() in ("1", "true", "yes")
if BEHIND_TLS_PROXY:
    from werkzeug.middleware.proxy_fix import ProxyFix

    # x_for/x_proto/x_host=1: trust exactly one hop (the proxy in front),
    # not an arbitrary chain - matches the single-reverse-proxy topology
    # this is documented for.
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

_secret_key = os.environ.get("DASHBOARD_SECRET_KEY")
if not _secret_key:
    print(
        "WARNING: DASHBOARD_SECRET_KEY is not set - using a random key for "
        "this process, so everyone will be logged out on restart. Set "
        "DASHBOARD_SECRET_KEY in your .env file to keep sessions across "
        "restarts.",
        file=sys.stderr,
    )
    _secret_key = secrets.token_hex(32)
app.secret_key = _secret_key

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    # Only marked Secure when a TLS-terminating proxy is confirmed to be
    # in front (see BEHIND_TLS_PROXY above) - otherwise the dashboard's
    # own plain-HTTP listener would never be able to set the cookie at
    # all, since browsers drop a Secure cookie set over a non-HTTPS
    # connection.
    SESSION_COOKIE_SECURE=BEHIND_TLS_PROXY,
    PERMANENT_SESSION_LIFETIME=timedelta(days=30),
    # Every request body this app handles is a small JSON object (a device
    # name, a rule, a resolution note) - a few hundred bytes at most. 64KB
    # is generous headroom over that while still refusing multi-MB bodies
    # (Flask returns 413 automatically for anything over this).
    MAX_CONTENT_LENGTH=64 * 1024,
)

# Brute-force throttle: an escalating per-IP wait that doubles with each
# consecutive failed attempt (1s, 2s, 4s, ... capped) and resets on a
# successful login. A flat per-second ceiling caps naive guessing at a
# fixed rate forever; escalating backoff instead makes a sustained
# attempt increasingly expensive. Not a substitute for a real rate
# limiter, but cheap and adds no dependency.
_LOGIN_BACKOFF_BASE_SECONDS = 1
_LOGIN_BACKOFF_MAX_SECONDS = 30
# Bounds memory even if an attacker cycles through many distinct source
# IPs (e.g. a wide IPv6 range) - without a cap this dict would otherwise
# grow by one entry per never-before-seen IP forever.
_LOGIN_ATTEMPT_MAX_TRACKED = 10000
_login_attempts = {}  # client_ip -> {"failures": int, "last_attempt": monotonic seconds}


def _evict_oldest_login_attempt_if_full(client_ip):
    """Drop the oldest-tracked client IP before adding a new one past the
    cap (same eviction approach as detector.py's per-IP tracking dicts)."""
    if client_ip not in _login_attempts and len(_login_attempts) >= _LOGIN_ATTEMPT_MAX_TRACKED:
        del _login_attempts[next(iter(_login_attempts))]


def _login_backoff_seconds(failures):
    """Wait required before the next attempt, given this many consecutive
    failures so far - doubles each time, capped so a long streak doesn't
    produce an absurd wait."""
    return min(_LOGIN_BACKOFF_BASE_SECONDS * (2 ** failures), _LOGIN_BACKOFF_MAX_SECONDS)


def _safe_next_path(path):
    """Only allow redirecting to a same-site relative path after login -
    guards against an open-redirect via a crafted ?next= value."""
    if not path or not path.startswith("/") or path.startswith("//"):
        return None
    if urlsplit(path).netloc:
        return None
    return path


@app.before_request
def _require_login():
    if request.endpoint in ("login", "static"):
        return
    if session.get("authenticated"):
        return
    if request.path.startswith("/api/"):
        abort(401)
    return redirect(url_for("login", next=request.path))


@app.after_request
def _security_headers(response):
    # Belt-and-braces against embedding this app in another page's iframe
    # (clickjacking/UI-redress) - frame-ancestors below is the modern
    # equivalent, kept alongside for browsers that only honor this header.
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"

    # Neither this dashboard nor anything it serves has a legitimate
    # reason to be opened as a popup from another origin, or to have its
    # responses embedded/read cross-origin - both are purely defensive
    # (window-reference tricks, Spectre-class cross-origin side-channel
    # reads) since a single-origin dashboard has nothing to gain from
    # allowing either.
    response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    response.headers["Cross-Origin-Resource-Policy"] = "same-origin"

    # Only sent once a TLS-terminating proxy is confirmed to be in front
    # (see BEHIND_TLS_PROXY above) - sending it on a plain-HTTP-only
    # deployment would have browsers refuse to connect over HTTP at all
    # on the next visit, with no way back short of clearing HSTS state.
    # Once it is safe to send, this closes a real gap the proxy alone
    # doesn't: without it, a network attacker can silently downgrade a
    # later visit back to plain HTTP (SSL stripping) since the browser
    # has no standing instruction to always use HTTPS for this origin.
    if BEHIND_TLS_PROXY:
        response.headers["Strict-Transport-Security"] = "max-age=31536000"

    # Skipped for the per-run HTML report: it loads Chart.js from a CDN
    # (with an SRI hash pin) rather than this app's own vendored copy, and
    # is meant to keep working if downloaded and opened standalone outside
    # the dashboard. Every other response is this app's own pages/API,
    # which never need a third-party origin for anything.
    if request.endpoint != "api_run_html":
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "connect-src 'self'; "
            "frame-ancestors 'none'; "
            "base-uri 'self'; "
            "form-action 'self'"
        )
    return response


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        client_ip = request.remote_addr or "unknown"
        entry = _login_attempts.get(client_ip)
        if entry:
            wait = _login_backoff_seconds(entry["failures"]) - (time.monotonic() - entry["last_attempt"])
            if wait > 0:
                time.sleep(wait)
        _evict_oldest_login_attempt_if_full(client_ip)
        entry = _login_attempts.setdefault(client_ip, {"failures": 0, "last_attempt": 0.0})
        entry["last_attempt"] = time.monotonic()

        if hmac.compare_digest(request.form.get("password", ""), DASHBOARD_PASSWORD):
            _login_attempts.pop(client_ip, None)
            session.clear()
            session["authenticated"] = True
            session.permanent = True
            return redirect(_safe_next_path(request.form.get("next")) or url_for("index"))
        entry["failures"] += 1
        error = "Incorrect password."

    return render_template("login.html", error=error, next=_safe_next_path(request.args.get("next")) or "")


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("login"))


def safe_run_dir(run_id):
    """Validate run_id and resolve it to a directory inside REPORTS_ROOT.

    run_id is attacker-controlled (comes from the URL), and gets joined
    into a filesystem path, so both a format check and a containment
    check are needed - the format check alone wouldn't catch a symlink
    planted inside REPORTS_ROOT.
    """
    if not RUN_ID_RE.match(run_id):
        abort(404)

    resolved = os.path.realpath(os.path.join(REPORTS_ROOT, run_id))
    if os.path.commonpath([resolved, REPORTS_ROOT]) != REPORTS_ROOT or not os.path.isdir(resolved):
        abort(404)

    return resolved


def read_json(path):
    try:
        with open(path) as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return None


def list_run_ids():
    """All run directories under REPORTS_ROOT, newest first.

    Timestamp-formatted names (YYYYMMDDTHHMMSSZ) sort correctly as
    plain strings, so no need to parse them.
    """
    try:
        entries = os.listdir(REPORTS_ROOT)
    except OSError:
        return []
    return sorted(
        (e for e in entries if RUN_ID_RE.match(e) and os.path.isdir(os.path.join(REPORTS_ROOT, e))),
        reverse=True,
    )


def run_summary(run_id):
    run_dir = os.path.join(REPORTS_ROOT, run_id)
    analysis = read_json(os.path.join(run_dir, "traffic_analysis.json"))
    if analysis is None:
        return None

    alerts_data = read_json(os.path.join(run_dir, "security_alerts.json"))
    alert_list = alerts_data.get("alerts", []) if alerts_data else []
    closed = alert_rules.closed_keys(alert_rules.load_state()["resolved"])
    unresolved_count = sum(1 for i in range(len(alert_list)) if f"{run_id}:{i}" not in closed)

    return {
        "run_id": run_id,
        "analysis_time": analysis.get("analysis_time"),
        "duration_seconds": analysis.get("duration_seconds", 0),
        "total_packets": analysis.get("total_packets", 0),
        # .get() with a default: runs captured before this field existed
        # won't have it in their stored traffic_analysis.json.
        "interface": analysis.get("interface", "default"),
        "packets_per_second": analysis.get("packets_per_second", 0),
        "protocol_stats": analysis.get("protocol_stats", {}),
        "alert_count": len(alert_list),
        "unresolved_count": unresolved_count,
        "has_html": os.path.isfile(os.path.join(run_dir, "traffic_report.html")),
        "has_csv": os.path.isfile(os.path.join(run_dir, "traffic_data.csv")),
        "has_pcap": os.path.isfile(os.path.join(run_dir, "traffic_capture.pcap")),
    }


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/live")
def api_live():
    run_ids = list_run_ids()

    if run_ids:
        current_dir = os.path.join(REPORTS_ROOT, run_ids[0])
        live_status = read_json(os.path.join(current_dir, "live_status.json"))
        if live_status:
            try:
                updated_at = datetime.fromisoformat(live_status["updated_at"])
                if updated_at.tzinfo is None:
                    updated_at = updated_at.replace(tzinfo=timezone.utc)
                age = (datetime.now(timezone.utc) - updated_at).total_seconds()
            except (KeyError, ValueError):
                age = None

            if age is not None and age < LIVE_STALE_SECONDS:
                # live_status itself carries a "status": "running" field
                # (see analyzer.export_live_snapshot) - spread it first so
                # our "live" status always wins, not the other way around.
                return jsonify({"run_id": run_ids[0], **live_status, "status": "live"})

    latest_link = os.path.join(REPORTS_ROOT, "latest")
    if os.path.islink(latest_link) or os.path.isdir(latest_link):
        latest_run_id = os.path.basename(os.path.realpath(latest_link))
        summary = run_summary(latest_run_id)
        if summary:
            return jsonify({"status": "idle", **summary})

    return jsonify({"status": "no_data"})


@app.route("/api/runs")
def api_runs():
    summaries = [run_summary(rid) for rid in list_run_ids()]
    return jsonify([s for s in summaries if s])


@app.route("/api/runs/<run_id>")
def api_run_detail(run_id):
    run_dir = safe_run_dir(run_id)

    analysis = read_json(os.path.join(run_dir, "traffic_analysis.json"))
    if analysis is None:
        abort(404)

    alerts_data = read_json(os.path.join(run_dir, "security_alerts.json"))
    alert_list = alerts_data.get("alerts", []) if alerts_data else []
    resolved_by_key = alert_rules.resolved_by_key(alert_rules.load_state()["resolved"])

    annotated_alerts = []
    for i, alert in enumerate(alert_list):
        alert_key = f"{run_id}:{i}"
        entry = resolved_by_key.get(alert_key)
        annotated_alerts.append({
            **alert,
            "alert_key": alert_key,
            "resolved": entry is not None,
            "outcome": entry.get("outcome") if entry else None,
            "resolution_note": entry.get("note") if entry else None,
            "firewall_suggestions": alert_playbooks.firewall_suggestions(alert),
        })

    return jsonify(
        {
            "run_id": run_id,
            "analysis": analysis,
            "alerts": annotated_alerts,
            "has_html": os.path.isfile(os.path.join(run_dir, "traffic_report.html")),
            "has_csv": os.path.isfile(os.path.join(run_dir, "traffic_data.csv")),
            "has_pcap": os.path.isfile(os.path.join(run_dir, "traffic_capture.pcap")),
        }
    )


def alert_count(run_dir):
    """Number of alerts recorded for a run - the valid range for an
    alerts/<index>/resolve|unresolve call against it."""
    alerts_data = read_json(os.path.join(run_dir, "security_alerts.json"))
    return len(alerts_data.get("alerts", [])) if alerts_data else 0


@app.route("/api/rules", methods=["GET", "POST"])
def api_rules():
    if request.method == "GET":
        return jsonify(alert_rules.load_state()["allowlist"])

    body = request.get_json(silent=True) or {}
    alert_type = body.get("alert_type")
    if alert_type not in VALID_ALERT_TYPES:
        abort(400)

    destination_port = body.get("destination_port")
    if destination_port is not None:
        try:
            destination_port = int(destination_port)
        except (TypeError, ValueError):
            abort(400)

    source_ip = body.get("source_ip") or None
    if source_ip is not None and not device_names.is_valid_ip(source_ip):
        abort(400)

    note = (body.get("note") or "")[:MAX_NOTE_LENGTH]

    rule = alert_rules.add_rule(
        alert_type=alert_type,
        source_ip=source_ip,
        destination_port=destination_port,
        note=note,
    )
    return jsonify(rule), 201


@app.route("/api/rules/<rule_id>", methods=["DELETE"])
def api_rule_delete(rule_id):
    if not alert_rules.remove_rule(rule_id):
        abort(404)
    return "", 204


@app.route("/api/runs/<run_id>/alerts/<int:index>/resolve", methods=["POST"])
def api_alert_resolve(run_id, index):
    run_dir = safe_run_dir(run_id)  # validates run_id, 404s on bad/unknown runs
    if not (0 <= index < alert_count(run_dir)):
        abort(404)
    body = request.get_json(silent=True) or {}
    outcome = body.get("outcome")
    if outcome is not None and outcome not in alert_rules.OUTCOMES:
        abort(400)
    note = (body.get("note") or "")[:MAX_NOTE_LENGTH]
    resolved = alert_rules.mark_resolved(f"{run_id}:{index}", note=note, outcome=outcome)
    return jsonify(resolved)


@app.route("/api/runs/<run_id>/alerts/<int:index>/unresolve", methods=["POST"])
def api_alert_unresolve(run_id, index):
    run_dir = safe_run_dir(run_id)
    if not (0 <= index < alert_count(run_dir)):
        abort(404)
    alert_rules.unmark_resolved(f"{run_id}:{index}")
    return "", 204


@app.route("/api/playbooks")
def api_playbooks():
    return jsonify(alert_playbooks.PLAYBOOKS)


@app.route("/api/devices", methods=["GET", "POST"])
def api_devices():
    if request.method == "GET":
        return jsonify(device_names.load_names())

    body = request.get_json(silent=True) or {}
    ip = body.get("ip", "")
    if not device_names.is_valid_ip(ip):
        abort(400)
    mac = (body.get("mac") or "").strip() or None
    if mac and not device_names.is_valid_mac(mac):
        abort(400)
    names = device_names.set_name(ip, body.get("name", ""), mac=mac)
    return jsonify(names)


@app.route("/api/devices/<ip>", methods=["DELETE"])
def api_device_delete(ip):
    if not device_names.is_valid_ip(ip):
        abort(400)
    mac = (request.args.get("mac") or "").strip() or None
    device_names.remove_name(ip, mac=mac)
    return "", 204


@app.route("/api/seen-devices")
def api_seen_devices():
    """Every IP seen across recent runs, with its best reverse-DNS
    suggestion and current manual name - the worklist for naming devices.

    Newest run wins for the hostname suggestion; packet counts are summed
    across the scanned runs so the busiest devices sort to the top.
    """
    names = device_names.load_names()
    mac_names = device_names.load_mac_names()
    seen = {}  # ip -> {"packet_count": int, "hostname": str|None, "geoip": dict|None, "mac_info": dict|None}

    for run_id in list_run_ids()[:SEEN_DEVICES_RUN_LIMIT]:
        analysis = read_json(os.path.join(REPORTS_ROOT, run_id, "traffic_analysis.json"))
        if not analysis:
            continue
        hostnames = analysis.get("hostnames", {})
        geo = analysis.get("geoip", {})
        mac_info = analysis.get("mac_info", {})
        for ip, count in analysis.get("top_ips", {}).items():
            entry = seen.setdefault(
                ip, {"packet_count": 0, "hostname": None, "geoip": None, "mac_info": None}
            )
            entry["packet_count"] += count
            # Runs are newest-first, so only fill each field if not already set.
            if entry["hostname"] is None and hostnames.get(ip):
                entry["hostname"] = hostnames[ip]
            if entry["geoip"] is None and geo.get(ip):
                entry["geoip"] = geo[ip]
            if entry["mac_info"] is None and mac_info.get(ip):
                entry["mac_info"] = mac_info[ip]

    # Include manually-named IPs even if they weren't in the scanned runs.
    for ip in names:
        seen.setdefault(ip, {"packet_count": 0, "hostname": None, "geoip": None, "mac_info": None})

    devices = [
        {
            "ip": ip,
            "packet_count": v["packet_count"],
            "hostname": v["hostname"],
            "geoip": v["geoip"],
            "mac_info": v["mac_info"],
            # Prefers the MAC-keyed name (survives this IP being reassigned
            # to a different device later) over the IP-keyed one.
            "name": device_names.resolve_name(
                ip, (v["mac_info"] or {}).get("mac"), names=names, mac_names=mac_names
            ),
        }
        for ip, v in seen.items()
    ]
    devices.sort(key=lambda d: d["packet_count"], reverse=True)
    return jsonify(devices)


@app.route("/api/device-trend")
def api_device_trend():
    """Per-device packet counts across the last N completed runs, for the
    devices with the most total traffic in that window.

    The aggregate trend chart (see /api/runs) shows overall packets/sec
    per run, but not who's actually generating it - this powers a
    per-device breakdown of the same time window.
    """
    run_ids = list(reversed(list_run_ids()[:DEVICE_TREND_RUN_LIMIT]))  # oldest -> newest
    names = device_names.load_names()
    mac_names = device_names.load_mac_names()

    runs = []
    per_run_top_ips = []
    totals = Counter()
    labels_by_ip = {}

    for run_id in run_ids:
        analysis = read_json(os.path.join(REPORTS_ROOT, run_id, "traffic_analysis.json"))
        if not analysis:
            continue
        top_ips = analysis.get("top_ips", {})
        hostnames = analysis.get("hostnames", {})
        mac_info = analysis.get("mac_info", {})

        runs.append({"run_id": run_id, "analysis_time": analysis.get("analysis_time")})
        per_run_top_ips.append(top_ips)

        for ip, count in top_ips.items():
            totals[ip] += count
            if ip not in labels_by_ip:
                mac = (mac_info.get(ip) or {}).get("mac")
                vendor = (mac_info.get(ip) or {}).get("vendor")
                resolved_name = device_names.resolve_name(ip, mac, names=names, mac_names=mac_names)
                labels_by_ip[ip] = resolved_name or hostnames.get(ip) or vendor or ip

    top_devices = [ip for ip, _ in totals.most_common(DEVICE_TREND_TOP_N)]

    return jsonify({
        "runs": runs,
        "devices": [
            {
                "ip": ip,
                "label": labels_by_ip[ip],
                # 0 for a run where this device wasn't in that run's
                # top_ips (top 20 only) - not necessarily silent, just
                # not among the busiest that run.
                "packet_counts": [top_ips.get(ip, 0) for top_ips in per_run_top_ips],
            }
            for ip in top_devices
        ],
    })


@app.route("/api/runs/<run_id>/report.html")
def api_run_html(run_id):
    run_dir = safe_run_dir(run_id)
    if not os.path.isfile(os.path.join(run_dir, "traffic_report.html")):
        abort(404)
    return send_from_directory(run_dir, "traffic_report.html")


@app.route("/api/runs/<run_id>/traffic_data.csv")
def api_run_csv(run_id):
    run_dir = safe_run_dir(run_id)
    if not os.path.isfile(os.path.join(run_dir, "traffic_data.csv")):
        abort(404)
    return send_from_directory(run_dir, "traffic_data.csv", as_attachment=True)


@app.route("/api/runs/<run_id>/traffic_capture.pcap")
def api_run_pcap(run_id):
    run_dir = safe_run_dir(run_id)
    if not os.path.isfile(os.path.join(run_dir, "traffic_capture.pcap")):
        abort(404)
    return send_from_directory(run_dir, "traffic_capture.pcap", as_attachment=True)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8080)))
