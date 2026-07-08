import pytest

import alert_playbooks


def test_get_playbook_returns_known_type():
    pb = alert_playbooks.get_playbook("PORT_SCAN")
    assert pb is not None
    assert set(pb.keys()) >= {"title", "what", "benign", "concerning", "steps"}


def test_get_playbook_returns_none_for_unknown_type():
    assert alert_playbooks.get_playbook("NOT_A_REAL_ALERT_TYPE") is None


@pytest.mark.parametrize("alert_type", list(alert_playbooks.PLAYBOOKS.keys()))
def test_every_playbook_has_nonempty_steps(alert_type):
    pb = alert_playbooks.PLAYBOOKS[alert_type]
    assert isinstance(pb["steps"], list) and len(pb["steps"]) > 0


def test_firewall_suggestions_empty_when_no_ip_or_port():
    assert alert_playbooks.firewall_suggestions({"type": "UNUSUAL_PROTOCOL_RATIO"}) == []


def test_firewall_suggestions_source_ip_only():
    suggestions = alert_playbooks.firewall_suggestions({"source_ip": "10.0.0.5"})
    labels = [s["label"] for s in suggestions]
    assert any("ufw" in l.lower() for l in labels)
    assert any("iptables" in l.lower() for l in labels)
    assert any("nftables" in l.lower() for l in labels)
    assert all("10.0.0.5" in s["command"] for s in suggestions if "block this source" in s["label"].lower())
    # No port-only or combined suggestions without a destination_port.
    assert not any("port" in s["label"].lower() and "source" not in s["label"].lower() for s in suggestions)


def test_firewall_suggestions_destination_port_only():
    suggestions = alert_playbooks.firewall_suggestions({"destination_port": 3389})
    assert any("3389" in s["command"] for s in suggestions)
    assert not any(s["label"].startswith("ufw - block this source IP") for s in suggestions)


def test_firewall_suggestions_both_ip_and_port_includes_combined_rule():
    suggestions = alert_playbooks.firewall_suggestions({"source_ip": "10.0.0.5", "destination_port": 3389})
    combined = [s for s in suggestions if "10.0.0.5" in s["command"] and "3389" in s["command"]]
    assert combined, "expected at least one suggestion scoping both IP and port together"


def test_firewall_suggestions_always_ends_with_plain_english_entry():
    suggestions = alert_playbooks.firewall_suggestions({"source_ip": "10.0.0.5"})
    assert suggestions[-1]["label"] == "Plain English"
    assert "10.0.0.5" in suggestions[-1]["command"]
