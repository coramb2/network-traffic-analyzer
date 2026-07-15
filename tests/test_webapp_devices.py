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


def make_run_with_ips(reports_root, run_id, top_ips, hostnames=None, geoip=None, mac_info=None):
    run_dir = reports_root / run_id
    run_dir.mkdir()
    (run_dir / "traffic_analysis.json").write_text(json.dumps({
        "total_packets": sum(top_ips.values()),
        "top_ips": top_ips,
        "hostnames": hostnames or {},
        "geoip": geoip or {},
        "mac_info": mac_info or {},
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


def test_seen_devices_includes_mac_info_newest_run_wins(app_ctx, client):
    _, reports_root = app_ctx
    old_mac = {"mac": "aa:aa:aa:aa:aa:aa", "vendor": "Old Vendor"}
    new_mac = {"mac": "bb:bb:bb:bb:bb:bb", "vendor": "New Vendor"}
    make_run_with_ips(reports_root, "20260101T000000Z", {"192.168.1.5": 10}, mac_info={"192.168.1.5": old_mac})
    make_run_with_ips(reports_root, "20260102T000000Z", {"192.168.1.5": 20}, mac_info={"192.168.1.5": new_mac})

    resp = client.get("/api/seen-devices")
    devices = {d["ip"]: d for d in resp.get_json()}
    assert devices["192.168.1.5"]["mac_info"]["vendor"] == "New Vendor"


def test_seen_devices_mac_info_null_when_no_ethernet_layer_seen(app_ctx, client):
    _, reports_root = app_ctx
    make_run_with_ips(reports_root, "20260101T000000Z", {"192.168.1.5": 10})  # no mac_info entry

    resp = client.get("/api/seen-devices")
    devices = {d["ip"]: d for d in resp.get_json()}
    assert devices["192.168.1.5"]["mac_info"] is None


# --- /api/device-trend -----------------------------------------------------

def test_device_trend_empty_when_no_runs(client):
    resp = client.get("/api/device-trend")
    body = resp.get_json()
    assert body == {"runs": [], "devices": []}


def test_device_trend_returns_runs_oldest_first(app_ctx, client):
    _, reports_root = app_ctx
    make_run_with_ips(reports_root, "20260101T000000Z", {"192.168.1.5": 10})
    make_run_with_ips(reports_root, "20260102T000000Z", {"192.168.1.5": 20})

    resp = client.get("/api/device-trend")
    run_ids = [r["run_id"] for r in resp.get_json()["runs"]]
    assert run_ids == ["20260101T000000Z", "20260102T000000Z"]


def test_device_trend_selects_top_n_by_total_traffic(app_ctx, client):
    _, reports_root = app_ctx
    # 6 distinct devices; only the busiest 5 (DEVICE_TREND_TOP_N) should appear.
    top_ips = {f"192.168.1.{i}": (i + 1) * 10 for i in range(6)}
    make_run_with_ips(reports_root, "20260101T000000Z", top_ips)

    resp = client.get("/api/device-trend")
    devices = resp.get_json()["devices"]
    assert len(devices) == 5
    assert "192.168.1.0" not in [d["ip"] for d in devices]  # the least-busy one, dropped


def test_device_trend_sorted_busiest_total_first(app_ctx, client):
    _, reports_root = app_ctx
    make_run_with_ips(reports_root, "20260101T000000Z", {"192.168.1.1": 5, "192.168.1.2": 50})

    resp = client.get("/api/device-trend")
    ips_in_order = [d["ip"] for d in resp.get_json()["devices"]]
    assert ips_in_order == ["192.168.1.2", "192.168.1.1"]


def test_device_trend_fills_zero_for_runs_device_missing_from(app_ctx, client):
    _, reports_root = app_ctx
    make_run_with_ips(reports_root, "20260101T000000Z", {"192.168.1.5": 10})
    make_run_with_ips(reports_root, "20260102T000000Z", {"192.168.1.5": 20, "192.168.1.6": 5})

    resp = client.get("/api/device-trend")
    devices = {d["ip"]: d for d in resp.get_json()["devices"]}
    # 192.168.1.6 didn't appear in the first (older) run at all.
    assert devices["192.168.1.6"]["packet_counts"] == [0, 5]
    assert devices["192.168.1.5"]["packet_counts"] == [10, 20]


def test_device_trend_label_prefers_manual_name(app_ctx, client):
    _, reports_root = app_ctx
    make_run_with_ips(reports_root, "20260101T000000Z", {"192.168.1.5": 10},
                       hostnames={"192.168.1.5": "some-host"})
    client.post("/api/devices", json={"ip": "192.168.1.5", "name": "Cora's Laptop"})

    resp = client.get("/api/device-trend")
    devices = {d["ip"]: d for d in resp.get_json()["devices"]}
    assert devices["192.168.1.5"]["label"] == "Cora's Laptop"


def test_device_trend_label_falls_back_to_hostname_then_vendor_then_ip(app_ctx, client):
    _, reports_root = app_ctx
    make_run_with_ips(reports_root, "20260101T000000Z", {
        "192.168.1.5": 10,
        "192.168.1.6": 5,
        "192.168.1.7": 3,
    }, hostnames={"192.168.1.5": "nas.local"},
       mac_info={"192.168.1.6": {"mac": "aa:bb:cc:dd:ee:ff", "vendor": "Raspberry Pi Foundation"}})

    resp = client.get("/api/device-trend")
    devices = {d["ip"]: d for d in resp.get_json()["devices"]}
    assert devices["192.168.1.5"]["label"] == "nas.local"
    assert devices["192.168.1.6"]["label"] == "Raspberry Pi Foundation"
    assert devices["192.168.1.7"]["label"] == "192.168.1.7"


def test_device_trend_label_uses_earliest_run_seen(app_ctx, client):
    """Once a label is picked for a device it doesn't get overwritten by a
    later run's (potentially missing) hostname - first-seen sticks, unlike
    /api/seen-devices where the newest run wins for hostname suggestions."""
    _, reports_root = app_ctx
    make_run_with_ips(reports_root, "20260101T000000Z", {"192.168.1.5": 10},
                       hostnames={"192.168.1.5": "old-host"})
    make_run_with_ips(reports_root, "20260102T000000Z", {"192.168.1.5": 20})

    resp = client.get("/api/device-trend")
    devices = {d["ip"]: d for d in resp.get_json()["devices"]}
    assert devices["192.168.1.5"]["label"] == "old-host"


def test_device_trend_ignores_runs_with_missing_analysis_file(app_ctx, client):
    _, reports_root = app_ctx
    make_run_with_ips(reports_root, "20260101T000000Z", {"192.168.1.5": 10})
    (reports_root / "20260102T000000Z").mkdir()  # run dir with no traffic_analysis.json

    resp = client.get("/api/device-trend")
    body = resp.get_json()
    assert len(body["runs"]) == 1
    assert body["devices"][0]["packet_counts"] == [10]


# --- MAC-keyed naming survives a DHCP-style IP change -----------------------

def test_post_device_with_mac_stores_mac_keyed_name(client):
    resp = client.post("/api/devices", json={
        "ip": "192.168.1.50", "name": "Cora's Laptop", "mac": "aa:bb:cc:dd:ee:ff",
    })
    assert resp.status_code == 200

    import device_names
    assert device_names.load_mac_names()["aa:bb:cc:dd:ee:ff"] == "Cora's Laptop"


def test_seen_devices_name_survives_ip_change_via_mac(app_ctx, client):
    """The actual DHCP-survival scenario end-to-end: a device is named
    while at one IP, then reappears (with the same MAC) at a different IP
    in a later run - the name should still show up there."""
    _, reports_root = app_ctx
    old_mac = {"mac": "aa:bb:cc:dd:ee:ff", "vendor": "Acme Corp"}
    make_run_with_ips(reports_root, "20260101T000000Z", {"192.168.1.50": 10}, mac_info={"192.168.1.50": old_mac})
    client.post("/api/devices", json={"ip": "192.168.1.50", "name": "Cora's Laptop", "mac": "aa:bb:cc:dd:ee:ff"})

    # Same device, new IP from a lease renewal - nobody re-named it.
    new_mac = {"mac": "aa:bb:cc:dd:ee:ff", "vendor": "Acme Corp"}
    make_run_with_ips(reports_root, "20260102T000000Z", {"192.168.1.77": 15}, mac_info={"192.168.1.77": new_mac})

    resp = client.get("/api/seen-devices")
    devices = {d["ip"]: d for d in resp.get_json()}
    assert devices["192.168.1.77"]["name"] == "Cora's Laptop"


def test_device_trend_label_survives_ip_change_via_mac(app_ctx, client):
    _, reports_root = app_ctx
    mac_info = {"mac": "aa:bb:cc:dd:ee:ff", "vendor": "Acme Corp"}
    make_run_with_ips(reports_root, "20260101T000000Z", {"192.168.1.50": 10}, mac_info={"192.168.1.50": mac_info})
    client.post("/api/devices", json={"ip": "192.168.1.50", "name": "Cora's Laptop", "mac": "aa:bb:cc:dd:ee:ff"})
    make_run_with_ips(reports_root, "20260102T000000Z", {"192.168.1.77": 15}, mac_info={"192.168.1.77": mac_info})

    resp = client.get("/api/device-trend")
    devices = {d["ip"]: d for d in resp.get_json()["devices"]}
    assert devices["192.168.1.77"]["label"] == "Cora's Laptop"


def test_delete_device_with_mac_query_param_clears_mac_name(client):
    client.post("/api/devices", json={"ip": "192.168.1.50", "name": "Thing", "mac": "aa:bb:cc:dd:ee:ff"})
    resp = client.delete("/api/devices/192.168.1.50?mac=aa:bb:cc:dd:ee:ff")
    assert resp.status_code == 204

    import device_names
    assert device_names.load_mac_names() == {}
