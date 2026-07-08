import pytest

import alert_rules


@pytest.fixture(autouse=True)
def state_file(tmp_path, monkeypatch):
    monkeypatch.setenv("ALERT_STATE_PATH", str(tmp_path / "alert_state.json"))
    return tmp_path / "alert_state.json"


def test_load_state_defaults_when_file_missing():
    state = alert_rules.load_state()
    assert state["allowlist"] == []
    assert state["resolved"] == []


def test_load_state_defaults_when_file_corrupt(state_file):
    state_file.write_text("{not valid json")
    state = alert_rules.load_state()
    assert state["allowlist"] == []
    assert state["resolved"] == []


def test_add_rule_persists_and_round_trips():
    rule = alert_rules.add_rule(alert_type="PORT_SCAN", source_ip="10.0.0.5", note="my scanner")
    assert rule["alert_type"] == "PORT_SCAN"
    assert rule["source_ip"] == "10.0.0.5"
    assert "id" in rule and "created_at" in rule

    reloaded = alert_rules.load_state()["allowlist"]
    assert len(reloaded) == 1
    assert reloaded[0]["id"] == rule["id"]


def test_remove_rule_by_id():
    rule = alert_rules.add_rule(alert_type="PORT_SCAN")
    assert alert_rules.remove_rule(rule["id"]) is True
    assert alert_rules.load_state()["allowlist"] == []


def test_remove_rule_unknown_id_returns_false():
    assert alert_rules.remove_rule("does-not-exist") is False


@pytest.mark.parametrize(
    "rule,alert,expected",
    [
        # Type-only rule matches any alert of that type regardless of IP/port.
        ({"alert_type": "PORT_SCAN"}, {"type": "PORT_SCAN", "source_ip": "1.2.3.4"}, True),
        ({"alert_type": "PORT_SCAN"}, {"type": "HIGH_CONNECTION_RATE", "source_ip": "1.2.3.4"}, False),
        # Type + source_ip must both match.
        (
            {"alert_type": "SUSPICIOUS_PORT", "source_ip": "10.0.0.5"},
            {"type": "SUSPICIOUS_PORT", "source_ip": "10.0.0.5"},
            True,
        ),
        (
            {"alert_type": "SUSPICIOUS_PORT", "source_ip": "10.0.0.5"},
            {"type": "SUSPICIOUS_PORT", "source_ip": "10.0.0.99"},
            False,
        ),
        # Type + destination_port must both match.
        (
            {"alert_type": "SUSPICIOUS_PORT", "destination_port": 3389},
            {"type": "SUSPICIOUS_PORT", "destination_port": 3389},
            True,
        ),
        (
            {"alert_type": "SUSPICIOUS_PORT", "destination_port": 3389},
            {"type": "SUSPICIOUS_PORT", "destination_port": 445},
            False,
        ),
        # All three constraints must match together.
        (
            {"alert_type": "SUSPICIOUS_PORT", "source_ip": "10.0.0.5", "destination_port": 3389},
            {"type": "SUSPICIOUS_PORT", "source_ip": "10.0.0.5", "destination_port": 3389},
            True,
        ),
        (
            {"alert_type": "SUSPICIOUS_PORT", "source_ip": "10.0.0.5", "destination_port": 3389},
            {"type": "SUSPICIOUS_PORT", "source_ip": "10.0.0.5", "destination_port": 445},
            False,
        ),
    ],
)
def test_rule_matches(rule, alert, expected):
    assert alert_rules.rule_matches(rule, alert) is expected


def test_is_allowlisted_true_when_any_rule_matches():
    rules = [{"alert_type": "PORT_SCAN"}, {"alert_type": "LARGE_PACKET"}]
    assert alert_rules.is_allowlisted({"type": "LARGE_PACKET"}, rules) is True


def test_is_allowlisted_false_when_no_rules_match():
    rules = [{"alert_type": "PORT_SCAN"}]
    assert alert_rules.is_allowlisted({"type": "LARGE_PACKET"}, rules) is False


def test_is_allowlisted_false_with_no_rules():
    assert alert_rules.is_allowlisted({"type": "PORT_SCAN"}, []) is False


def test_mark_resolved_then_unmark():
    resolved = alert_rules.mark_resolved("run1:0", note="handled", outcome="benign")
    assert any(r["alert_key"] == "run1:0" and r["outcome"] == "benign" for r in resolved)

    alert_rules.unmark_resolved("run1:0")
    assert alert_rules.load_state()["resolved"] == []


def test_mark_resolved_replaces_previous_entry_for_same_key():
    alert_rules.mark_resolved("run1:0", note="first", outcome="investigating")
    alert_rules.mark_resolved("run1:0", note="final", outcome="threat")

    resolved = alert_rules.load_state()["resolved"]
    matching = [r for r in resolved if r["alert_key"] == "run1:0"]
    assert len(matching) == 1
    assert matching[0]["outcome"] == "threat"
    assert matching[0]["note"] == "final"


def test_closed_keys_excludes_investigating_outcome():
    entries = [
        {"alert_key": "run1:0", "outcome": "investigating"},
        {"alert_key": "run1:1", "outcome": "benign"},
        {"alert_key": "run1:2", "outcome": None},
    ]
    closed = alert_rules.closed_keys(entries)
    assert closed == {"run1:1", "run1:2"}


def test_resolved_by_key_maps_key_to_entry():
    entries = [{"alert_key": "run1:0", "outcome": "benign"}]
    by_key = alert_rules.resolved_by_key(entries)
    assert by_key["run1:0"]["outcome"] == "benign"


def test_resolved_keys_includes_every_entry_regardless_of_outcome():
    entries = [
        {"alert_key": "run1:0", "outcome": "investigating"},
        {"alert_key": "run1:1", "outcome": "benign"},
    ]
    assert alert_rules.resolved_keys(entries) == {"run1:0", "run1:1"}
