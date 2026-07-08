import importlib
import json
from datetime import datetime, timedelta, timezone

import pytest


@pytest.fixture
def app_ctx(tmp_path, monkeypatch):
    monkeypatch.setenv("ALERT_STATE_PATH", str(tmp_path / "alert_state.json"))
    monkeypatch.setenv("DEVICE_NAMES_PATH", str(tmp_path / "device_names.json"))
    reports_root = tmp_path / "reports"
    reports_root.mkdir()
    monkeypatch.setenv("REPORTS_ROOT", str(reports_root))
    monkeypatch.setenv("DASHBOARD_PASSWORD", "test-password")

    import webapp
    importlib.reload(webapp)
    webapp.app.config["TESTING"] = True
    return webapp, reports_root


@pytest.fixture
def client(app_ctx):
    webapp, _ = app_ctx
    with webapp.app.test_client() as c:
        # Every route except /login and static assets requires a session
        # since the dashboard-auth feature landed - log straight in rather
        # than going through the login form/throttle.
        with c.session_transaction() as sess:
            sess["authenticated"] = True
        yield c


def make_run(reports_root, run_id, packets=42, alerts=None, extra_analysis=None):
    run_dir = reports_root / run_id
    run_dir.mkdir()
    analysis = {
        "analysis_time": datetime.now(timezone.utc).isoformat(),
        "duration_seconds": 60,
        "total_packets": packets,
        "protocol_stats": {"TCP": packets},
        "top_ips": {"192.168.1.5": packets},
        "top_ports": {"443": packets},
        "hostnames": {},
        "recent_packets": [],
    }
    if extra_analysis:
        analysis.update(extra_analysis)
    (run_dir / "traffic_analysis.json").write_text(json.dumps(analysis))
    if alerts is not None:
        (run_dir / "security_alerts.json").write_text(
            json.dumps({"total_alerts": len(alerts), "alerts": alerts})
        )
    return run_dir


def test_api_runs_includes_interface_and_pps_when_present(app_ctx, client):
    _, reports_root = app_ctx
    make_run(reports_root, "20260101T000000Z", extra_analysis={"interface": "eth0", "packets_per_second": 3.7})

    resp = client.get("/api/runs")
    run = resp.get_json()[0]
    assert run["interface"] == "eth0"
    assert run["packets_per_second"] == 3.7


def test_api_runs_defaults_interface_and_pps_for_older_runs(app_ctx, client):
    """Regression: interface/packets_per_second were only ever tracked
    live, never persisted into traffic_analysis.json, so completed runs
    (and every run captured before this field existed) need a graceful
    default rather than a KeyError."""
    _, reports_root = app_ctx
    make_run(reports_root, "20260101T000000Z")  # no interface/pps in the raw analysis

    resp = client.get("/api/runs")
    run = resp.get_json()[0]
    assert run["interface"] == "default"
    assert run["packets_per_second"] == 0


def test_api_runs_empty_when_no_runs(client):
    resp = client.get("/api/runs")
    assert resp.status_code == 200
    assert resp.get_json() == []


def test_api_runs_lists_runs_newest_first(app_ctx, client):
    _, reports_root = app_ctx
    make_run(reports_root, "20260101T000000Z", packets=10)
    make_run(reports_root, "20260102T000000Z", packets=20)

    resp = client.get("/api/runs")
    run_ids = [r["run_id"] for r in resp.get_json()]
    assert run_ids == ["20260102T000000Z", "20260101T000000Z"]


def test_api_runs_skips_directories_without_analysis(app_ctx, client):
    _, reports_root = app_ctx
    (reports_root / "20260101T000000Z").mkdir()  # empty - a quiet capture cycle
    make_run(reports_root, "20260102T000000Z")

    resp = client.get("/api/runs")
    run_ids = [r["run_id"] for r in resp.get_json()]
    assert run_ids == ["20260102T000000Z"]


def test_api_run_detail_404_for_unknown_run(client):
    resp = client.get("/api/runs/20260101T000000Z")
    assert resp.status_code == 404


@pytest.mark.parametrize("malicious_id", [
    "../../etc/passwd",
    "..%2f..%2fetc%2fpasswd",
    "20260101T000000Z/../../etc",
    "/etc/passwd",
    "not-a-timestamp",
])
def test_api_run_detail_rejects_non_conforming_run_ids(client, malicious_id):
    resp = client.get(f"/api/runs/{malicious_id}")
    assert resp.status_code == 404


def test_api_run_detail_rejects_symlink_escape(app_ctx, client):
    _, reports_root = app_ctx
    outside = reports_root.parent / "outside"
    outside.mkdir()
    (outside / "traffic_analysis.json").write_text(json.dumps({"total_packets": 1}))
    (reports_root / "20260101T000000Z").symlink_to(outside)

    resp = client.get("/api/runs/20260101T000000Z")
    assert resp.status_code == 404


def test_api_run_detail_annotates_alerts_with_firewall_suggestions(app_ctx, client):
    _, reports_root = app_ctx
    alerts = [{"type": "SUSPICIOUS_PORT", "severity": "MEDIUM", "source_ip": "10.0.0.5",
               "destination_port": 3389, "description": "x", "details": "y"}]
    make_run(reports_root, "20260101T000000Z", alerts=alerts)

    resp = client.get("/api/runs/20260101T000000Z")
    body = resp.get_json()
    assert len(body["alerts"]) == 1
    assert body["alerts"][0]["resolved"] is False
    assert body["alerts"][0]["firewall_suggestions"]  # non-empty, has source_ip+port


def test_api_run_detail_reflects_resolved_alerts(app_ctx, client):
    webapp, reports_root = app_ctx
    alerts = [{"type": "SUSPICIOUS_PORT", "severity": "MEDIUM", "description": "x", "details": "y"}]
    make_run(reports_root, "20260101T000000Z", alerts=alerts)

    import alert_rules
    alert_rules.mark_resolved("20260101T000000Z:0", note="handled", outcome="benign")

    resp = client.get("/api/runs/20260101T000000Z")
    alert = resp.get_json()["alerts"][0]
    assert alert["resolved"] is True
    assert alert["outcome"] == "benign"


def test_api_live_no_data(client):
    resp = client.get("/api/live")
    assert resp.get_json()["status"] == "no_data"


def test_api_live_reports_live_when_snapshot_fresh(app_ctx, client):
    _, reports_root = app_ctx
    run_dir = make_run(reports_root, "20260101T000000Z")
    (run_dir / "live_status.json").write_text(json.dumps({
        "status": "running",
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "packet_count": 5,
    }))

    resp = client.get("/api/live")
    body = resp.get_json()
    assert body["status"] == "live"
    assert body["packet_count"] == 5


def test_api_live_falls_back_to_idle_when_snapshot_stale(app_ctx, client):
    _, reports_root = app_ctx
    run_dir = make_run(reports_root, "20260101T000000Z", packets=99)
    stale_time = datetime.now(timezone.utc) - timedelta(seconds=30)
    (run_dir / "live_status.json").write_text(json.dumps({
        "status": "running",
        "updated_at": stale_time.isoformat(),
        "packet_count": 5,
    }))
    (reports_root / "latest").symlink_to(run_dir)

    resp = client.get("/api/live")
    body = resp.get_json()
    assert body["status"] == "idle"
    assert body["total_packets"] == 99


def test_api_run_html_404_when_missing(app_ctx, client):
    _, reports_root = app_ctx
    make_run(reports_root, "20260101T000000Z")
    resp = client.get("/api/runs/20260101T000000Z/report.html")
    assert resp.status_code == 404


def test_api_run_html_serves_file_when_present(app_ctx, client):
    _, reports_root = app_ctx
    run_dir = make_run(reports_root, "20260101T000000Z")
    (run_dir / "traffic_report.html").write_text("<html>report</html>")

    resp = client.get("/api/runs/20260101T000000Z/report.html")
    assert resp.status_code == 200
    assert b"report" in resp.data


def test_api_run_csv_and_pcap_reject_path_traversal(client):
    resp = client.get("/api/runs/../../etc/traffic_data.csv")
    assert resp.status_code == 404
    resp = client.get("/api/runs/../../etc/traffic_capture.pcap")
    assert resp.status_code == 404


def test_api_playbooks_returns_known_alert_types(client):
    resp = client.get("/api/playbooks")
    body = resp.get_json()
    assert "PORT_SCAN" in body
    assert "title" in body["PORT_SCAN"]
