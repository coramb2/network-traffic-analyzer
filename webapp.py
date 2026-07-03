#!/usr/bin/env python3
"""
Dashboard web app.

Read-only Flask app that mounts the same reports/ volume the capture
container writes to and serves a live-updating dashboard plus a browser
for past runs. Never touches packet capture: no NET_RAW/NET_ADMIN needed.
"""

import json
import os
import re
from datetime import datetime, timezone

from flask import Flask, abort, jsonify, render_template, send_from_directory

REPORTS_ROOT = os.path.realpath(os.environ.get("REPORTS_ROOT", "/data/reports"))
LIVE_STALE_SECONDS = 5

RUN_ID_RE = re.compile(r"^\d{8}T\d{6}Z$")

app = Flask(__name__)


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

    alerts = read_json(os.path.join(run_dir, "security_alerts.json"))

    return {
        "run_id": run_id,
        "analysis_time": analysis.get("analysis_time"),
        "duration_seconds": analysis.get("duration_seconds", 0),
        "total_packets": analysis.get("total_packets", 0),
        "protocol_stats": analysis.get("protocol_stats", {}),
        "alert_count": alerts.get("total_alerts", 0) if alerts else 0,
        "has_html": os.path.isfile(os.path.join(run_dir, "traffic_report.html")),
        "has_csv": os.path.isfile(os.path.join(run_dir, "traffic_data.csv")),
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
                return jsonify({"status": "live", "run_id": run_ids[0], **live_status})

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

    alerts = read_json(os.path.join(run_dir, "security_alerts.json"))

    return jsonify(
        {
            "run_id": run_id,
            "analysis": analysis,
            "alerts": alerts.get("alerts", []) if alerts else [],
            "has_html": os.path.isfile(os.path.join(run_dir, "traffic_report.html")),
            "has_csv": os.path.isfile(os.path.join(run_dir, "traffic_data.csv")),
        }
    )


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


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8080)))
