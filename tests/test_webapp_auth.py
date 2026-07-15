"""Tests for the dashboard's login gate.

Before this, webapp.py had no authentication at all: anyone who could
reach the dashboard port could allowlist (silently suppress) security
alerts, delete devices, or download PCAP captures.
"""

import importlib
import json

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


# --- security headers -------------------------------------------------

def test_security_headers_present_on_login_page(client):
    resp = client.get("/login")
    assert resp.headers["X-Frame-Options"] == "DENY"
    assert resp.headers["X-Content-Type-Options"] == "nosniff"
    assert "frame-ancestors 'none'" in resp.headers["Content-Security-Policy"]


def test_security_headers_present_on_api_response(client):
    client.post("/login", data={"password": "s3cret"})
    resp = client.get("/api/runs")
    assert resp.headers["X-Frame-Options"] == "DENY"
    assert resp.headers["X-Content-Type-Options"] == "nosniff"
    assert "Content-Security-Policy" in resp.headers


def test_csp_skipped_for_per_run_html_report(webapp_module, client, tmp_path):
    """The per-run report loads Chart.js from a CDN (with an SRI hash) -
    a blanket script-src 'self' CSP here would silently break its chart."""
    client.post("/login", data={"password": "s3cret"})
    reports_root = tmp_path / "reports"
    run_dir = reports_root / "20260101T000000Z"
    run_dir.mkdir()
    (run_dir / "traffic_report.html").write_text("<html>report</html>")

    resp = client.get("/api/runs/20260101T000000Z/report.html")
    assert resp.status_code == 200
    assert "Content-Security-Policy" not in resp.headers
    # Frame/MIME protections still apply even here.
    assert resp.headers["X-Frame-Options"] == "DENY"


# --- request size limit -------------------------------------------------

def test_oversized_request_body_rejected(client):
    client.post("/login", data={"password": "s3cret"})
    huge_body = json.dumps({"ip": "192.168.1.50", "name": "A" * 200_000})
    resp = client.post("/api/devices", data=huge_body, content_type="application/json")
    assert resp.status_code == 413


# --- login-attempt tracking dict is bounded -----------------------------

def test_login_attempt_tracking_dict_is_bounded(webapp_module):
    webapp_module._last_login_attempt.clear()
    cap = webapp_module._LOGIN_ATTEMPT_MAX_TRACKED
    for i in range(cap + 50):
        webapp_module._evict_oldest_login_attempt_if_full(f"10.0.{i // 256}.{i % 256}")
        webapp_module._last_login_attempt[f"10.0.{i // 256}.{i % 256}"] = i
    assert len(webapp_module._last_login_attempt) <= cap
