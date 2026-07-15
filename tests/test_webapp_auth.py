"""Tests for the dashboard's login gate.

Before this, webapp.py had no authentication at all: anyone who could
reach the dashboard port could allowlist (silently suppress) security
alerts, delete devices, or download PCAP captures.
"""

import importlib
import json

import pytest


def _fresh_webapp(monkeypatch, tmp_path, password="s3cret", secret_key="test-key", behind_tls_proxy=False):
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
    if behind_tls_proxy:
        monkeypatch.setenv("DASHBOARD_BEHIND_TLS_PROXY", "true")
    else:
        monkeypatch.delenv("DASHBOARD_BEHIND_TLS_PROXY", raising=False)

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


def test_cross_origin_policies_present_unconditionally(client):
    """Neither policy depends on whether this sits behind TLS - both are
    same-origin-only defaults a single-origin dashboard has no
    legitimate reason to relax, unlike Secure/HSTS which genuinely need
    HTTPS in place first."""
    resp = client.get("/login")
    assert resp.headers["Cross-Origin-Opener-Policy"] == "same-origin"
    assert resp.headers["Cross-Origin-Resource-Policy"] == "same-origin"


def test_hsts_absent_by_default(client):
    """Sending HSTS on a plain-HTTP-only deployment would have browsers
    refuse to connect over HTTP at all on the next visit - only safe
    once a TLS-terminating proxy is confirmed to be in front."""
    resp = client.get("/login")
    assert "Strict-Transport-Security" not in resp.headers


def test_hsts_present_when_behind_tls_proxy(tmp_path, monkeypatch):
    webapp_module = _fresh_webapp(monkeypatch, tmp_path, behind_tls_proxy=True)
    webapp_module.app.config["TESTING"] = True
    with webapp_module.app.test_client() as c:
        resp = c.get("/login")
    assert resp.headers["Strict-Transport-Security"] == "max-age=31536000"


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
    webapp_module._login_attempts.clear()
    cap = webapp_module._LOGIN_ATTEMPT_MAX_TRACKED
    for i in range(cap + 50):
        ip = f"10.0.{i // 256}.{i % 256}"
        webapp_module._evict_oldest_login_attempt_if_full(ip)
        webapp_module._login_attempts[ip] = {"failures": 0, "last_attempt": i}
    assert len(webapp_module._login_attempts) <= cap


# --- escalating login backoff -------------------------------------------

def test_login_backoff_seconds_doubles_per_consecutive_failure(webapp_module):
    assert webapp_module._login_backoff_seconds(0) == 1
    assert webapp_module._login_backoff_seconds(1) == 2
    assert webapp_module._login_backoff_seconds(2) == 4
    assert webapp_module._login_backoff_seconds(3) == 8


def test_login_backoff_seconds_caps_at_max(webapp_module):
    assert webapp_module._login_backoff_seconds(10) == webapp_module._LOGIN_BACKOFF_MAX_SECONDS


def test_failed_login_increments_failure_count(client, webapp_module):
    client.post("/login", data={"password": "wrong"})
    assert webapp_module._login_attempts["127.0.0.1"]["failures"] == 1

    # Backdate the last attempt so the next POST doesn't actually block
    # on the now-escalated backoff window - only the failure count (and
    # that it keeps climbing) is under test here.
    webapp_module._login_attempts["127.0.0.1"]["last_attempt"] -= 100
    client.post("/login", data={"password": "wrong"})
    assert webapp_module._login_attempts["127.0.0.1"]["failures"] == 2


def test_successful_login_resets_failure_count(client, webapp_module):
    client.post("/login", data={"password": "wrong"})
    assert "127.0.0.1" in webapp_module._login_attempts

    webapp_module._login_attempts["127.0.0.1"]["last_attempt"] -= 100
    client.post("/login", data={"password": "s3cret"})
    assert "127.0.0.1" not in webapp_module._login_attempts


def test_login_sleeps_for_escalated_backoff_after_a_failure(client, webapp_module, monkeypatch):
    client.post("/login", data={"password": "wrong"})  # first attempt: no prior entry, no sleep

    slept = []
    monkeypatch.setattr(webapp_module.time, "sleep", lambda seconds: slept.append(seconds))
    client.post("/login", data={"password": "wrong"})

    assert slept
    assert slept[0] == pytest.approx(2, abs=0.5)


# --- reverse-proxy / TLS support -----------------------------------------

def test_session_cookie_not_secure_by_default(webapp_module):
    """Without a confirmed TLS-terminating proxy in front, marking the
    cookie Secure would break plain-HTTP setups entirely (browsers drop
    a Secure cookie set over a non-HTTPS connection)."""
    assert webapp_module.app.config["SESSION_COOKIE_SECURE"] is False


def test_session_cookie_secure_when_behind_tls_proxy(tmp_path, monkeypatch):
    webapp_module = _fresh_webapp(monkeypatch, tmp_path, behind_tls_proxy=True)
    assert webapp_module.app.config["SESSION_COOKIE_SECURE"] is True


def test_proxy_fix_not_applied_by_default(webapp_module, client):
    """Without opting in, a spoofed X-Forwarded-For must not change what
    the app sees as the client's IP - otherwise a client could pick any
    IP it likes and dodge the per-IP login throttle entirely."""
    resp = client.post(
        "/login",
        data={"password": "wrong"},
        headers={"X-Forwarded-For": "203.0.113.9"},
        environ_overrides={"REMOTE_ADDR": "10.0.0.5"},
    )
    assert resp.status_code == 200
    assert "10.0.0.5" in webapp_module._login_attempts
    assert "203.0.113.9" not in webapp_module._login_attempts


def test_proxy_fix_applied_when_behind_tls_proxy(tmp_path, monkeypatch):
    webapp_module = _fresh_webapp(monkeypatch, tmp_path, behind_tls_proxy=True)
    webapp_module.app.config["TESTING"] = True
    with webapp_module.app.test_client() as c:
        resp = c.post(
            "/login",
            data={"password": "wrong"},
            headers={"X-Forwarded-For": "203.0.113.9"},
            environ_overrides={"REMOTE_ADDR": "127.0.0.1"},  # the trusted proxy hop
        )
    assert resp.status_code == 200
    assert "203.0.113.9" in webapp_module._login_attempts
