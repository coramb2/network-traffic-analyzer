import importlib
import json

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


def make_run_with_ips(reports_root, run_id, top_ips, hostnames=None, geoip=None):
    run_dir = reports_root / run_id
    run_dir.mkdir()
    (run_dir / "traffic_analysis.json").write_text(json.dumps({
        "total_packets": sum(top_ips.values()),
        "top_ips": top_ips,
        "hostnames": hostnames or {},
        "geoip": geoip or {},
    }))


def test_get_devices_empty_by_default(client):
    resp = client.get("/api/devices")
    assert resp.get_json() == {}


def test_post_device_sets_name(client):
    resp = client.post("/api/devices", json={"ip": "192.168.1.50", "name": "Cora's Laptop"})
    assert resp.status_code == 200
    assert resp.get_json()["192.168.1.50"] == "Cora's Laptop"

    resp = client.get("/api/devices")
    assert resp.get_json()["192.168.1.50"] == "Cora's Laptop"


def test_post_device_rejects_invalid_ip(client):
    resp = client.post("/api/devices", json={"ip": "<script>alert(1)</script>", "name": "x"})
    assert resp.status_code == 400


def test_delete_device_removes_name(client):
    client.post("/api/devices", json={"ip": "192.168.1.50", "name": "Thing"})
    resp = client.delete("/api/devices/192.168.1.50")
    assert resp.status_code == 204
    assert client.get("/api/devices").get_json() == {}


def test_delete_device_rejects_invalid_ip(client):
    resp = client.delete("/api/devices/not-an-ip")
    assert resp.status_code == 400


def test_seen_devices_aggregates_across_runs(app_ctx, client):
    _, reports_root = app_ctx
    make_run_with_ips(reports_root, "20260101T000000Z", {"192.168.1.5": 10}, hostnames={"192.168.1.5": "old-host"})
    make_run_with_ips(reports_root, "20260102T000000Z", {"192.168.1.5": 20}, hostnames={"192.168.1.5": "new-host"})

    resp = client.get("/api/seen-devices")
    devices = {d["ip"]: d for d in resp.get_json()}
    assert devices["192.168.1.5"]["packet_count"] == 30  # summed across runs
    assert devices["192.168.1.5"]["hostname"] == "new-host"  # newest run wins


def test_seen_devices_sorted_busiest_first(app_ctx, client):
    _, reports_root = app_ctx
    make_run_with_ips(reports_root, "20260101T000000Z", {"192.168.1.1": 5, "192.168.1.2": 50})

    resp = client.get("/api/seen-devices")
    ips_in_order = [d["ip"] for d in resp.get_json()]
    assert ips_in_order == ["192.168.1.2", "192.168.1.1"]


def test_seen_devices_includes_manually_named_ip_even_if_unseen(client):
    client.post("/api/devices", json={"ip": "192.168.1.99", "name": "Ghost Device"})
    resp = client.get("/api/seen-devices")
    devices = {d["ip"]: d for d in resp.get_json()}
    assert devices["192.168.1.99"]["name"] == "Ghost Device"
    assert devices["192.168.1.99"]["packet_count"] == 0


def test_seen_devices_includes_geoip_newest_run_wins(app_ctx, client):
    _, reports_root = app_ctx
    old_geo = {"country_code": "US", "org": "Old ISP"}
    new_geo = {"country_code": "US", "org": "New ISP"}
    make_run_with_ips(reports_root, "20260101T000000Z", {"8.8.8.8": 10}, geoip={"8.8.8.8": old_geo})
    make_run_with_ips(reports_root, "20260102T000000Z", {"8.8.8.8": 20}, geoip={"8.8.8.8": new_geo})

    resp = client.get("/api/seen-devices")
    devices = {d["ip"]: d for d in resp.get_json()}
    assert devices["8.8.8.8"]["geoip"]["org"] == "New ISP"


def test_seen_devices_geoip_null_for_private_ips(app_ctx, client):
    _, reports_root = app_ctx
    make_run_with_ips(reports_root, "20260101T000000Z", {"192.168.1.5": 10})  # no geoip entry for it

    resp = client.get("/api/seen-devices")
    devices = {d["ip"]: d for d in resp.get_json()}
    assert devices["192.168.1.5"]["geoip"] is None
