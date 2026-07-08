import smtplib
import urllib.error

import pytest

import notifications


def make_alert(severity="MEDIUM", alert_type="SUSPICIOUS_PORT", description="test alert"):
    return {"severity": severity, "type": alert_type, "description": description}


# --- filter_by_severity -----------------------------------------------

def test_filter_by_severity_includes_at_or_above_threshold():
    alerts = [make_alert("HIGH"), make_alert("MEDIUM"), make_alert("LOW")]
    result = notifications.filter_by_severity(alerts, "MEDIUM")
    severities = [a["severity"] for a in result]
    assert severities == ["HIGH", "MEDIUM"]


def test_filter_by_severity_high_only():
    alerts = [make_alert("HIGH"), make_alert("MEDIUM"), make_alert("LOW")]
    result = notifications.filter_by_severity(alerts, "HIGH")
    assert [a["severity"] for a in result] == ["HIGH"]


def test_filter_by_severity_low_includes_everything():
    alerts = [make_alert("LOW"), make_alert("HIGH"), make_alert("MEDIUM")]
    result = notifications.filter_by_severity(alerts, "LOW")
    assert len(result) == 3
    assert result[0]["severity"] == "HIGH"  # sorted HIGH-first regardless of input order


# --- build_digest -------------------------------------------------------

def test_build_digest_empty_alerts_returns_none():
    assert notifications.build_digest([]) is None


def test_build_digest_includes_counts_and_examples():
    alerts = [make_alert("HIGH", "PORT_SCAN", "scan 1"), make_alert("MEDIUM", "SUSPICIOUS_PORT", "rdp hit")]
    digest = notifications.build_digest(alerts, run_id="20260101T000000Z")
    assert "2 security alerts" in digest["title"]
    assert "1 HIGH" in digest["title"]
    assert "1 MEDIUM" in digest["title"]
    assert "20260101T000000Z" in digest["text"]
    assert "scan 1" in digest["text"]
    assert "rdp hit" in digest["text"]


def test_build_digest_singular_alert_count_wording():
    digest = notifications.build_digest([make_alert()])
    assert "1 security alert (" in digest["title"]
    assert "1 security alerts" not in digest["title"]


def test_build_digest_truncates_examples_and_notes_remainder():
    alerts = [make_alert(description=f"alert {i}") for i in range(8)]
    digest = notifications.build_digest(alerts, max_examples=3)
    assert "alert 0" in digest["text"]
    assert "... and 5 more" in digest["text"]


def test_build_digest_includes_dashboard_url_when_given():
    digest = notifications.build_digest([make_alert()], dashboard_url="http://nas.local:8080")
    assert "http://nas.local:8080" in digest["text"]


def test_build_digest_omits_dashboard_url_when_not_given():
    digest = notifications.build_digest([make_alert()])
    assert "Dashboard:" not in digest["text"]


# --- send_webhook ---------------------------------------------------------

class FakeResponse:
    def __init__(self, status):
        self.status = status

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def test_send_webhook_success(monkeypatch):
    monkeypatch.setattr(notifications.urllib.request, "urlopen", lambda req, timeout: FakeResponse(200))
    digest = {"title": "t", "text": "body"}
    assert notifications.send_webhook("http://example.com/hook", digest) is True


def test_send_webhook_non_2xx_is_failure(monkeypatch):
    monkeypatch.setattr(notifications.urllib.request, "urlopen", lambda req, timeout: FakeResponse(500))
    digest = {"title": "t", "text": "body"}
    assert notifications.send_webhook("http://example.com/hook", digest) is False


def test_send_webhook_network_error_is_failure(monkeypatch):
    def raise_error(req, timeout):
        raise urllib.error.URLError("connection refused")

    monkeypatch.setattr(notifications.urllib.request, "urlopen", raise_error)
    digest = {"title": "t", "text": "body"}
    assert notifications.send_webhook("http://example.com/hook", digest) is False


def test_send_webhook_payload_contains_digest_text(monkeypatch):
    captured = {}

    def fake_urlopen(req, timeout):
        captured["data"] = req.data
        captured["headers"] = req.headers
        return FakeResponse(200)

    monkeypatch.setattr(notifications.urllib.request, "urlopen", fake_urlopen)
    notifications.send_webhook("http://example.com/hook", {"title": "t", "text": "hello world"})
    assert b"hello world" in captured["data"]


# --- send_email -----------------------------------------------------------

class FakeSMTP:
    instances = []

    def __init__(self, host, port, timeout=None):
        self.host = host
        self.port = port
        self.started_tls = False
        self.logged_in = None
        self.sent_message = None
        FakeSMTP.instances.append(self)

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def starttls(self):
        self.started_tls = True

    def login(self, user, password):
        self.logged_in = (user, password)

    def send_message(self, msg):
        self.sent_message = msg


@pytest.fixture(autouse=True)
def reset_fake_smtp():
    FakeSMTP.instances = []
    yield


def test_send_email_success(monkeypatch):
    monkeypatch.setattr(notifications.smtplib, "SMTP", FakeSMTP)
    config = {"host": "smtp.example.com", "port": 587, "from_addr": "a@x.com", "to_addrs": "b@x.com"}
    digest = {"title": "Alert!", "text": "body text"}

    assert notifications.send_email(config, digest) is True
    sent = FakeSMTP.instances[0].sent_message
    assert sent["Subject"] == "Alert!"
    assert sent["To"] == "b@x.com"


def test_send_email_multiple_recipients(monkeypatch):
    monkeypatch.setattr(notifications.smtplib, "SMTP", FakeSMTP)
    config = {"host": "smtp.example.com", "from_addr": "a@x.com", "to_addrs": "b@x.com, c@x.com"}
    notifications.send_email(config, {"title": "t", "text": "b"})
    assert FakeSMTP.instances[0].sent_message["To"] == "b@x.com, c@x.com"


def test_send_email_no_recipients_is_failure(monkeypatch):
    monkeypatch.setattr(notifications.smtplib, "SMTP", FakeSMTP)
    config = {"host": "smtp.example.com", "from_addr": "a@x.com", "to_addrs": ""}
    assert notifications.send_email(config, {"title": "t", "text": "b"}) is False
    assert FakeSMTP.instances == []


def test_send_email_logs_in_when_credentials_given(monkeypatch):
    monkeypatch.setattr(notifications.smtplib, "SMTP", FakeSMTP)
    config = {
        "host": "smtp.example.com", "from_addr": "a@x.com", "to_addrs": "b@x.com",
        "user": "a@x.com", "password": "secret", "use_tls": True,
    }
    notifications.send_email(config, {"title": "t", "text": "b"})
    instance = FakeSMTP.instances[0]
    assert instance.started_tls is True
    assert instance.logged_in == ("a@x.com", "secret")


def test_send_email_smtp_failure_returns_false(monkeypatch):
    class FailingSMTP(FakeSMTP):
        def send_message(self, msg):
            raise smtplib.SMTPException("auth failed")

    monkeypatch.setattr(notifications.smtplib, "SMTP", FailingSMTP)
    config = {"host": "smtp.example.com", "from_addr": "a@x.com", "to_addrs": "b@x.com"}
    assert notifications.send_email(config, {"title": "t", "text": "b"}) is False


# --- config_from_env --------------------------------------------------

def test_config_from_env_empty_by_default():
    config = notifications.config_from_env(env={})
    assert config["webhook_url"] is None
    assert config["smtp"] is None
    assert config["min_severity"] == "LOW"


def test_config_from_env_webhook_only():
    config = notifications.config_from_env(env={"ALERT_WEBHOOK_URL": "http://example.com/hook"})
    assert config["webhook_url"] == "http://example.com/hook"
    assert config["smtp"] is None


def test_config_from_env_smtp_requires_host_and_to():
    # Missing SMTP_TO - not enough to enable email.
    config = notifications.config_from_env(env={"SMTP_HOST": "smtp.example.com"})
    assert config["smtp"] is None


def test_config_from_env_smtp_full():
    env = {
        "SMTP_HOST": "smtp.example.com",
        "SMTP_PORT": "465",
        "SMTP_USER": "user@example.com",
        "SMTP_PASSWORD": "hunter2",
        "SMTP_TO": "alerts@example.com",
        "SMTP_USE_TLS": "false",
    }
    config = notifications.config_from_env(env=env)
    assert config["smtp"]["host"] == "smtp.example.com"
    assert config["smtp"]["port"] == 465
    assert config["smtp"]["use_tls"] is False
    assert config["smtp"]["from_addr"] == "user@example.com"  # falls back to SMTP_USER


def test_config_from_env_min_severity_uppercased():
    config = notifications.config_from_env(env={"ALERT_NOTIFY_MIN_SEVERITY": "high"})
    assert config["min_severity"] == "HIGH"


# --- notify_alerts (integration of the above) --------------------------

def test_notify_alerts_no_channels_configured(monkeypatch):
    results = notifications.notify_alerts([make_alert("HIGH")], {"min_severity": "LOW"})
    assert results == {"webhook": None, "email": None}


def test_notify_alerts_no_alerts_meet_threshold(monkeypatch):
    sent = {"called": False}
    monkeypatch.setattr(notifications, "send_webhook", lambda *a, **k: sent.update(called=True))
    config = {"webhook_url": "http://example.com/hook", "min_severity": "HIGH"}
    results = notifications.notify_alerts([make_alert("LOW")], config)
    assert results == {"webhook": None, "email": None}
    assert sent["called"] is False


def test_notify_alerts_calls_webhook_and_not_email_when_only_webhook_configured(monkeypatch):
    monkeypatch.setattr(notifications, "send_webhook", lambda *a, **k: True)
    config = {"webhook_url": "http://example.com/hook", "smtp": None, "min_severity": "LOW"}
    results = notifications.notify_alerts([make_alert("HIGH")], config)
    assert results == {"webhook": True, "email": None}


def test_notify_alerts_calls_both_channels_when_both_configured(monkeypatch):
    monkeypatch.setattr(notifications, "send_webhook", lambda *a, **k: True)
    monkeypatch.setattr(notifications, "send_email", lambda *a, **k: False)
    config = {
        "webhook_url": "http://example.com/hook",
        "smtp": {"host": "smtp.example.com", "from_addr": "a@x.com", "to_addrs": "b@x.com"},
        "min_severity": "LOW",
    }
    results = notifications.notify_alerts([make_alert("HIGH")], config)
    assert results == {"webhook": True, "email": False}


def test_notify_alerts_passes_run_id_into_digest(monkeypatch):
    captured = {}

    def fake_send_webhook(url, digest, **kwargs):
        captured["digest"] = digest
        return True

    monkeypatch.setattr(notifications, "send_webhook", fake_send_webhook)
    config = {"webhook_url": "http://example.com/hook", "min_severity": "LOW"}
    notifications.notify_alerts([make_alert("HIGH")], config, run_id="20260101T000000Z")
    assert "20260101T000000Z" in captured["digest"]["text"]
