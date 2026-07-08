"""Tests for the /api/rules allowlist endpoint, added alongside the fix for
a stored-XSS + missing-validation bug: source_ip was accepted unvalidated
and rendered unescaped by the dashboard frontend."""

import importlib

import pytest


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("ALERT_STATE_PATH", str(tmp_path / "alert_state.json"))
    monkeypatch.setenv("DEVICE_NAMES_PATH", str(tmp_path / "device_names.json"))
    monkeypatch.setenv("REPORTS_ROOT", str(tmp_path / "reports"))
    (tmp_path / "reports").mkdir()

    import webapp
    importlib.reload(webapp)
    webapp.app.config["TESTING"] = True
    with webapp.app.test_client() as c:
        yield c


def test_add_rule_valid(client):
    resp = client.post("/api/rules", json={
        "alert_type": "PORT_SCAN",
        "source_ip": "192.168.1.50",
        "note": "my own nmap scanner",
    })
    assert resp.status_code == 201
    body = resp.get_json()
    assert body["source_ip"] == "192.168.1.50"
    assert body["note"] == "my own nmap scanner"
    assert "id" in body


def test_add_rule_rejects_invalid_alert_type(client):
    resp = client.post("/api/rules", json={"alert_type": "NOT_A_REAL_TYPE"})
    assert resp.status_code == 400


def test_add_rule_rejects_non_ip_source_ip(client):
    """The bug: source_ip previously went straight into storage (and later
    unescaped into the dashboard DOM) with no format check at all."""
    resp = client.post("/api/rules", json={
        "alert_type": "PORT_SCAN",
        "source_ip": "<img src=x onerror=alert(1)>",
    })
    assert resp.status_code == 400


def test_add_rule_rejects_invalid_destination_port(client):
    resp = client.post("/api/rules", json={
        "alert_type": "PORT_SCAN",
        "destination_port": "not-a-port",
    })
    assert resp.status_code == 400


def test_add_rule_truncates_long_note(client):
    resp = client.post("/api/rules", json={
        "alert_type": "PORT_SCAN",
        "note": "x" * 10_000,
    })
    assert resp.status_code == 201
    assert len(resp.get_json()["note"]) == 500


def test_rule_round_trips_through_get(client):
    add_resp = client.post("/api/rules", json={"alert_type": "SUSPICIOUS_PORT", "note": "hello"})
    rule_id = add_resp.get_json()["id"]

    list_resp = client.get("/api/rules")
    assert list_resp.status_code == 200
    ids = [r["id"] for r in list_resp.get_json()]
    assert rule_id in ids


def test_delete_rule(client):
    add_resp = client.post("/api/rules", json={"alert_type": "SUSPICIOUS_PORT"})
    rule_id = add_resp.get_json()["id"]

    del_resp = client.delete(f"/api/rules/{rule_id}")
    assert del_resp.status_code == 204

    list_resp = client.get("/api/rules")
    ids = [r["id"] for r in list_resp.get_json()]
    assert rule_id not in ids


def test_delete_unknown_rule_404s(client):
    resp = client.delete("/api/rules/does-not-exist")
    assert resp.status_code == 404
