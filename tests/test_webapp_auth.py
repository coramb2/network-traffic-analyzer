"""Tests for the dashboard's login gate.

Before this, webapp.py had no authentication at all: anyone who could
reach the dashboard port could allowlist (silently suppress) security
alerts, delete devices, or download PCAP captures.
"""

import importlib

import pytest


def _fresh_webapp(monkeypatch, tmp_path, password="s3cret", secret_key="test-key"):
    monkeypatch.setenv("ALERT_STATE_PATH", str(tmp_path / "alert_state.json"))
    monkeypatch.setenv("DEVICE_NAMES_PATH", str(tmp_path / "device_names.json"))
    monkeypatch.setenv("REPORTS_ROOT", str(tmp_path / "reports"))
    (tmp_path / "reports").mkdir(exist_ok=True)
    if password is None:
        monkeypatch.delenv("DASHBOARD_PASSWORD", raising=False)
    else:
        monkeypatch.setenv("DASHBOARD_PASSWORD", password)
    if secret_key is None:
        monkeypatch.delenv("DASHBOARD_SECRET_KEY", raising=False)
    else:
        monkeypatch.setenv("DASHBOARD_SECRET_KEY", secret_key)

    import webapp
    importlib.reload(webapp)
    return webapp


@pytest.fixture
def webapp_module(tmp_path, monkeypatch):
    return _fresh_webapp(monkeypatch, tmp_path)


@pytest.fixture
def client(webapp_module):
    webapp_module.app.config["TESTING"] = True
    with webapp_module.app.test_client() as c:
        yield c


def test_refuses_to_start_without_password(tmp_path, monkeypatch):
    with pytest.raises(SystemExit):
        _fresh_webapp(monkeypatch, tmp_path, password=None)


def test_index_redirects_to_login_when_unauthenticated(client):
    resp = client.get("/", follow_redirects=False)
    assert resp.status_code in (301, 302, 303, 307, 308)
    assert "/login" in resp.headers["Location"]


def test_api_route_401s_when_unauthenticated(client):
    resp = client.get("/api/runs")
    assert resp.status_code == 401


def test_login_wrong_password_shows_error(client):
    resp = client.post("/login", data={"password": "wrong"})
    assert resp.status_code == 200
    assert b"Incorrect password" in resp.data


def test_login_correct_password_grants_access(client):
    resp = client.post("/login", data={"password": "s3cret"}, follow_redirects=False)
    assert resp.status_code in (302, 303)

    resp = client.get("/api/runs")
    assert resp.status_code == 200


def test_login_redirects_to_next_param(client):
    resp = client.post(
        "/login?next=/some/page",
        data={"password": "s3cret", "next": "/some/page"},
        follow_redirects=False,
    )
    assert resp.headers["Location"] == "/some/page"


def test_login_rejects_open_redirect(client):
    """A crafted next= pointing off-site must never be honored."""
    resp = client.post(
        "/login",
        data={"password": "s3cret", "next": "//evil.example.com/steal"},
        follow_redirects=False,
    )
    assert "evil.example.com" not in resp.headers["Location"]


def test_logout_clears_session(client):
    client.post("/login", data={"password": "s3cret"})
    assert client.get("/api/runs").status_code == 200

    client.post("/logout")
    assert client.get("/api/runs").status_code == 401


def test_login_page_itself_does_not_require_auth(client):
    resp = client.get("/login")
    assert resp.status_code == 200
