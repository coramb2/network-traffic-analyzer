"""Browser-driven regression tests for the dashboard frontend.

Unlike the rest of the suite (which drives webapp.py through Flask's
in-process test client), these actually launch a real browser against a
live HTTP server and exercise templates/index.html's JS - Chart.js
rendering, the escaping discipline, the device-trend chart's color
assignment. Nothing else in this repo re-checks that JS on a change;
every prior verification of it was a one-off manual Playwright session
(see the PRs for the device-trend chart and the dashboard pentest).

Requires a browser installed for Playwright (`playwright install
chromium`) - see tests/conftest.py for how this sandbox's pre-installed
Chromium is wired in without needing that step here.
"""
import importlib
import json
import os
import socket
import threading
import time

import pytest

pytest.importorskip("playwright")

DASHBOARD_PASSWORD = "TestPass123!"


def _free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="module")
def dashboard_server(tmp_path_factory):
    """A real, live instance of the dashboard for the whole module - tests
    share it (like a live deployment would be shared by multiple users),
    so each test uses its own run IDs/IPs to avoid colliding with others.
    """
    reports_root = tmp_path_factory.mktemp("reports")
    state_dir = tmp_path_factory.mktemp("state")

    env_overrides = {
        "REPORTS_ROOT": str(reports_root),
        "ALERT_STATE_PATH": str(state_dir / "alert_state.json"),
        "DEVICE_NAMES_PATH": str(state_dir / "device_names.json"),
        "DASHBOARD_PASSWORD": DASHBOARD_PASSWORD,
        "DASHBOARD_SECRET_KEY": "test-secret-key-not-for-production",
    }
    previous = {k: os.environ.get(k) for k in env_overrides}
    os.environ.update(env_overrides)

    import webapp
    importlib.reload(webapp)

    port = _free_port()
    thread = threading.Thread(
        target=lambda: webapp.app.run(host="127.0.0.1", port=port, use_reloader=False),
        daemon=True,
    )
    thread.start()

    for _ in range(50):
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                break
        except OSError:
            time.sleep(0.1)
    else:
        raise RuntimeError("dashboard server did not start in time")

    yield f"http://127.0.0.1:{port}", reports_root

    for key, value in previous.items():
        if value is None:
            os.environ.pop(key, None)
        else:
            os.environ[key] = value


def make_run(reports_root, run_id, top_ips, hostnames=None, geoip=None, mac_info=None, alerts=None):
    run_dir = reports_root / run_id
    run_dir.mkdir()
    (run_dir / "traffic_analysis.json").write_text(json.dumps({
        "analysis_time": "2026-01-01T00:00:00",
        "total_packets": sum(top_ips.values()),
        "duration_seconds": 5,
        "interface": "eth0",
        "packets_per_second": 1.0,
        "protocol_stats": {"TCP": sum(top_ips.values())},
        "top_ips": top_ips,
        "top_ports": {"443": sum(top_ips.values())},
        "hostnames": hostnames or {},
        "geoip": geoip or {},
        "mac_info": mac_info or {},
    }))
    if alerts is not None:
        (run_dir / "security_alerts.json").write_text(json.dumps({
            "generated_at": "2026-01-01T00:00:00",
            "total_alerts": len(alerts),
            "alerts": alerts,
        }))
    return run_dir


def login(page, base_url):
    page.goto(f"{base_url}/login")
    page.fill('input[name="password"]', DASHBOARD_PASSWORD)
    page.click('button[type="submit"]')
    page.wait_for_url(f"{base_url}/")


# --- login flow / auth gate ------------------------------------------------

def test_unauthenticated_visit_redirects_to_login(page, dashboard_server):
    base_url, _ = dashboard_server
    # goto() already follows the redirect chain and settles on the final
    # URL before returning, so there's no further navigation left to wait
    # for - check the URL it landed on directly.
    page.goto(f"{base_url}/")
    assert page.url.startswith(f"{base_url}/login")


def test_wrong_password_shows_error(page, dashboard_server):
    base_url, _ = dashboard_server
    page.goto(f"{base_url}/login")
    page.fill('input[name="password"]', "not-the-password")
    page.click('button[type="submit"]')
    assert page.get_by_text("Incorrect password").is_visible()


def test_correct_password_reaches_dashboard(page, dashboard_server):
    base_url, _ = dashboard_server
    login(page, base_url)
    assert page.url == f"{base_url}/"
    assert page.get_by_text("Network Traffic Dashboard").is_visible()


# --- XSS escaping regression (see the dashboard pentest) --------------------

def test_xss_payloads_render_as_inert_text_not_executed(page, dashboard_server):
    base_url, reports_root = dashboard_server
    payload = "<img src=x onerror=alert('xss')>"
    make_run(
        reports_root, "20260201T000000Z", {"10.10.10.10": 5},
        hostnames={"10.10.10.10": payload},
        geoip={"10.10.10.10": {"country_code": payload, "org": payload}},
        mac_info={"10.10.10.10": {"mac": "aa:bb:cc:dd:ee:ff", "vendor": payload}},
        alerts=[{
            "type": "PORT_SCAN", "severity": "HIGH", "timestamp": "2026-02-01T00:00:00",
            "source_ip": "10.10.10.10",
            "description": f"Possible port scan detected from 10.10.10.10 {payload}",
            "details": payload,
        }],
    )

    dialogs = []
    page.on("dialog", lambda d: (dialogs.append(d.message), d.dismiss()))

    login(page, base_url)
    page.evaluate("showRunDetail('20260201T000000Z')")
    page.wait_for_timeout(500)

    assert dialogs == []
    assert page.locator('img[src="x"]').count() == 0
    # The payload should still be visible as literal, harmless text.
    assert page.get_by_text("onerror=alert").first.is_visible()


def test_xss_payload_in_device_name_not_executed(page, dashboard_server):
    base_url, _ = dashboard_server
    payload = "<img src=x onerror=alert('xss')>"

    dialogs = []
    page.on("dialog", lambda d: (dialogs.append(d.message), d.dismiss()))

    login(page, base_url)
    page.evaluate(
        """(payload) => fetch('/api/devices', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ip: '10.10.10.11', name: payload}),
        })""",
        payload,
    )
    page.evaluate("loadDevices()")
    page.wait_for_timeout(500)

    assert dialogs == []
    assert page.locator('img[src="x"]').count() == 0


# --- device-trend chart color stability (see the device-trend chart PR) ----

def test_device_trend_chart_color_stable_across_churn(page, dashboard_server):
    base_url, reports_root = dashboard_server
    mac_a = {"mac": "aa:aa:aa:aa:aa:aa", "vendor": "Vendor A"}
    mac_b = {"mac": "bb:bb:bb:bb:bb:bb", "vendor": "Vendor B"}
    mac_c = {"mac": "cc:cc:cc:cc:cc:cc", "vendor": "Vendor C"}

    # Two runs of its own up front - the chart only renders with >= 2, and
    # this test must not depend on another test in this module having
    # left a run behind (the server/reports dir is shared across the
    # whole module, but each test's own assertions shouldn't be).
    make_run(reports_root, "20260301T000000Z", {
        "10.20.30.1": 100, "10.20.30.2": 80, "10.20.30.3": 60, "10.20.30.4": 40, "10.20.30.5": 20,
    }, mac_info={
        "10.20.30.1": mac_a, "10.20.30.2": mac_b, "10.20.30.3": mac_c,
    })
    make_run(reports_root, "20260301T120000Z", {
        "10.20.30.1": 95, "10.20.30.2": 85, "10.20.30.3": 55, "10.20.30.4": 45, "10.20.30.5": 15,
    }, mac_info={
        "10.20.30.1": mac_a, "10.20.30.2": mac_b, "10.20.30.3": mac_c,
    })

    login(page, base_url)
    page.evaluate("loadRuns()")
    page.wait_for_timeout(500)

    colors_before = page.evaluate("""() => {
        const chart = Chart.getChart(document.getElementById('deviceTrendChart'));
        return Object.fromEntries(chart.data.datasets.map(d => [d.label, d.borderColor]));
    }""")
    assert len(colors_before) == 5

    # New run: the least-busy device (10.20.30.5) drops out of the top 5,
    # a brand-new device (10.20.30.6) takes its place, and the busiest
    # device's rank changes (it's no longer #1) - the surviving devices
    # should keep their exact colors regardless.
    make_run(reports_root, "20260302T000000Z", {
        "10.20.30.1": 90, "10.20.30.2": 95, "10.20.30.3": 60, "10.20.30.4": 40, "10.20.30.6": 200,
    }, mac_info={"10.20.30.1": mac_a, "10.20.30.2": mac_b, "10.20.30.3": mac_c})

    page.evaluate("loadRuns()")
    page.wait_for_timeout(500)

    colors_after = page.evaluate("""() => {
        const chart = Chart.getChart(document.getElementById('deviceTrendChart'));
        return Object.fromEntries(chart.data.datasets.map(d => [d.label, d.borderColor]));
    }""")

    survivors = set(colors_before) & set(colors_after)
    assert len(survivors) >= 4  # everything except the one that dropped out
    for label in survivors:
        assert colors_after[label] == colors_before[label], (
            f"{label} changed color across a churn refresh: "
            f"{colors_before[label]} -> {colors_after[label]}"
        )
