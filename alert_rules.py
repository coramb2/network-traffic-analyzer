#!/usr/bin/env python3
"""
Shared alert-state store: an allowlist (suppresses matching alerts before
they're generated) and a resolved-set (per-alert acknowledgment).

Used by both containers against the same file, mounted read-only into the
capture container and read-write into the dashboard - only the dashboard
ever calls add_rule/remove_rule/mark_resolved/unmark_resolved.
"""

import json
import os
import uuid
from datetime import datetime, timezone


def _state_path():
    return os.environ.get("ALERT_STATE_PATH", "alert_state.json")


def load_state():
    try:
        with open(_state_path()) as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError):
        data = {}
    data.setdefault("allowlist", [])
    data.setdefault("resolved", [])
    return data


def save_state(data):
    """Write via a temp file + rename so a concurrent reader never sees a
    half-written file."""
    path = _state_path()
    tmp_path = f"{path}.tmp"
    with open(tmp_path, "w") as f:
        json.dump(data, f, indent=2)
    os.chmod(tmp_path, 0o640)
    os.replace(tmp_path, path)


def rule_matches(rule, alert):
    if rule.get("alert_type") != alert.get("type"):
        return False
    if rule.get("source_ip") and rule["source_ip"] != alert.get("source_ip"):
        return False
    if rule.get("destination_port") is not None and rule["destination_port"] != alert.get("destination_port"):
        return False
    return True


def is_allowlisted(alert, rules):
    return any(rule_matches(r, alert) for r in rules)


def add_rule(alert_type, source_ip=None, destination_port=None, note=""):
    data = load_state()
    rule = {
        "id": uuid.uuid4().hex[:12],
        "created_at": datetime.now(timezone.utc).isoformat(),
        "alert_type": alert_type,
        "source_ip": source_ip or None,
        "destination_port": destination_port,
        "note": note,
    }
    data["allowlist"].append(rule)
    save_state(data)
    return rule


def remove_rule(rule_id):
    data = load_state()
    before = len(data["allowlist"])
    data["allowlist"] = [r for r in data["allowlist"] if r["id"] != rule_id]
    save_state(data)
    return len(data["allowlist"]) != before


def mark_resolved(alert_key, note=""):
    data = load_state()
    if not any(r["alert_key"] == alert_key for r in data["resolved"]):
        data["resolved"].append(
            {
                "alert_key": alert_key,
                "resolved_at": datetime.now(timezone.utc).isoformat(),
                "note": note,
            }
        )
        save_state(data)
    return data["resolved"]


def unmark_resolved(alert_key):
    data = load_state()
    data["resolved"] = [r for r in data["resolved"] if r["alert_key"] != alert_key]
    save_state(data)


def resolved_keys(resolved_entries):
    return {r["alert_key"] for r in resolved_entries}
