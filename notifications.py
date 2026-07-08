#!/usr/bin/env python3
"""
Alert notifications: webhook + email digest for a completed capture run.

Every alert type in this project (SUSPICIOUS_PORT, PORT_SCAN, etc.) is
only computed in a batch once a capture window ends - see detector.py -
so "real-time" here means "as soon as a run finishes", not per-packet.
That's still a real gap without this module: the only other way to learn
about a new alert is to happen to open the dashboard.

Best-effort and non-fatal by design: a notification failure (bad SMTP
creds, webhook host down, DNS failure) must never break capture/report
generation, so every send function catches its own errors and returns
whether it succeeded rather than raising.
"""

import json
import os
import smtplib
import urllib.error
import urllib.request
from collections import Counter
from email.message import EmailMessage

SEVERITY_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
DEFAULT_MIN_SEVERITY = "LOW"


def _severity_rank(severity):
    return SEVERITY_ORDER.get(severity, len(SEVERITY_ORDER))


def filter_by_severity(alerts, min_severity):
    """Alerts at or above min_severity (HIGH is "above" LOW), HIGH first."""
    threshold = _severity_rank(min_severity)
    filtered = [a for a in alerts if _severity_rank(a.get("severity")) <= threshold]
    return sorted(filtered, key=lambda a: _severity_rank(a.get("severity")))


def build_digest(alerts, run_id=None, dashboard_url=None, max_examples=5):
    """Build a {title, text} digest for a batch of alerts from one run.
    text is plain text, suitable for both a webhook payload and an email
    body. Returns None for an empty alert list - nothing to send."""
    if not alerts:
        return None

    by_severity = Counter(a.get("severity", "UNKNOWN") for a in alerts)
    by_type = Counter(a.get("type", "UNKNOWN") for a in alerts)

    severity_summary = ", ".join(
        f"{n} {sev}" for sev, n in sorted(by_severity.items(), key=lambda kv: _severity_rank(kv[0]))
    )
    title = f"{len(alerts)} security alert{'s' if len(alerts) != 1 else ''} ({severity_summary})"

    lines = [title, ""]
    if run_id:
        lines.append(f"Run: {run_id}")
    lines.append("By type: " + ", ".join(f"{t} x{n}" for t, n in by_type.most_common()))
    lines.append("")
    lines.append("Examples:")
    ranked = sorted(alerts, key=lambda a: _severity_rank(a.get("severity")))
    for alert in ranked[:max_examples]:
        lines.append(f"  [{alert.get('severity')}] {alert.get('description')}")
    if len(alerts) > max_examples:
        lines.append(f"  ... and {len(alerts) - max_examples} more")
    if dashboard_url:
        lines.append("")
        lines.append(f"Dashboard: {dashboard_url}")

    return {"title": title, "text": "\n".join(lines)}


def send_webhook(url, digest, timeout=5):
    """POST a {"text": ...} JSON payload - directly compatible with Slack/
    Discord/Mattermost incoming webhooks, and simple enough for a generic
    receiver to just read the "text" field."""
    payload = json.dumps({"text": digest["text"]}).encode("utf-8")
    req = urllib.request.Request(
        url, data=payload, headers={"Content-Type": "application/json"}, method="POST"
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return 200 <= resp.status < 300
    except (urllib.error.URLError, OSError, ValueError):
        return False


def send_email(smtp_config, digest, timeout=10):
    """smtp_config: {host, port, user, password, from_addr, to_addrs, use_tls}.
    to_addrs is a comma-separated string of one or more recipients."""
    to_addrs = [a.strip() for a in smtp_config["to_addrs"].split(",") if a.strip()]
    if not to_addrs:
        return False

    msg = EmailMessage()
    msg["Subject"] = digest["title"]
    msg["From"] = smtp_config["from_addr"]
    msg["To"] = ", ".join(to_addrs)
    msg.set_content(digest["text"])

    try:
        with smtplib.SMTP(smtp_config["host"], smtp_config.get("port", 587), timeout=timeout) as server:
            if smtp_config.get("use_tls", True):
                server.starttls()
            if smtp_config.get("user"):
                server.login(smtp_config["user"], smtp_config.get("password", ""))
            server.send_message(msg)
        return True
    except (smtplib.SMTPException, OSError, TimeoutError):
        return False


def config_from_env(env=None):
    """Read notification config from environment variables.

    Both channels are opt-in: webhook_url/smtp are None unless the
    required variables are set, so notify_alerts() no-ops by default
    (matches this project's existing "off unless configured" pattern,
    e.g. CAPTURE_PCAP/RESOLVE_HOSTNAMES).
    """
    env = env if env is not None else os.environ

    smtp = None
    if env.get("SMTP_HOST") and env.get("SMTP_TO"):
        smtp = {
            "host": env["SMTP_HOST"],
            "port": int(env.get("SMTP_PORT", "587")),
            "user": env.get("SMTP_USER") or None,
            "password": env.get("SMTP_PASSWORD") or "",
            "from_addr": env.get("SMTP_FROM") or env.get("SMTP_USER") or "network-traffic-analyzer@localhost",
            "to_addrs": env["SMTP_TO"],
            "use_tls": env.get("SMTP_USE_TLS", "true").lower() != "false",
        }

    return {
        "webhook_url": env.get("ALERT_WEBHOOK_URL") or None,
        "smtp": smtp,
        "min_severity": env.get("ALERT_NOTIFY_MIN_SEVERITY", DEFAULT_MIN_SEVERITY).upper(),
        "dashboard_url": env.get("DASHBOARD_URL") or None,
    }


def notify_alerts(alerts, config, run_id=None):
    """Send a digest notification for alerts through every configured
    channel. Never raises - safe to call unconditionally after a capture
    completes, regardless of whether any channel is configured or working.

    Returns {"webhook": bool|None, "email": bool|None}; None means that
    channel wasn't configured, so it wasn't attempted.
    """
    results = {"webhook": None, "email": None}

    relevant = filter_by_severity(alerts, config.get("min_severity", DEFAULT_MIN_SEVERITY))
    if not relevant:
        return results

    digest = build_digest(relevant, run_id=run_id, dashboard_url=config.get("dashboard_url"))

    if config.get("webhook_url"):
        results["webhook"] = send_webhook(config["webhook_url"], digest)
    if config.get("smtp"):
        results["email"] = send_email(config["smtp"], digest)

    return results
