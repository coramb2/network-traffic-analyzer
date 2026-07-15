#!/usr/bin/env python3
"""
Shared alert-state store: an allowlist (suppresses matching alerts before
they're generated) and a resolved-set (per-alert acknowledgment).

Used by both containers against the same file, mounted read-only into the
capture container and read-write into the dashboard - only the dashboard
ever calls add_rule/remove_rule/mark_resolved/unmark_resolved.
"""

import contextlib
import fcntl
import json
import os
import uuid
from datetime import datetime, timezone

# Structured outcomes recorded alongside a resolution. "investigating" is
# the one outcome that still counts as an open/unresolved alert (see
# webapp.run_summary) - it means work is in progress, not done.
OUTCOMES = {"known", "false_positive", "benign", "mitigated", "investigating", "threat"}
OPEN_OUTCOMES = {"investigating"}

# Both lists are loaded and fully JSON-parsed on nearly every dashboard
# API request (load_state()), so an unbounded list here isn't just disk
# usage - it's a per-request cost that grows forever. webapp.py validates
# that a resolve/unresolve call targets a real alert before it ever
# reaches mark_resolved, which is the actual fix for that path; these
# caps are defense in depth against any other route (present or future)
# growing either list without that same check. Both are far above what
# any real home network would ever legitimately need.
MAX_ALLOWLIST_RULES = 2000
MAX_RESOLVED_ENTRIES = 5000


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


@contextlib.contextmanager
def _locked():
    """Serializes a load_state()-modify-save_state() cycle across threads
    and processes via an OS-level advisory lock on a dedicated lock file.

    Without this, two concurrent writers race: both load the same
    pre-change state, both modify their own in-memory copy, and whichever
    calls save_state() last silently wins - the other's change is lost.
    Worse, both also race on save_state()'s fixed-name temp file, which
    can crash outright (one writer's os.replace() making the temp path
    disappear out from under the other's os.chmod()/os.replace()).
    Demonstrated concretely: 200 concurrent add_rule() calls with no
    locking left only 4 surviving rules, the rest either lost or crashed.

    The lock is a *separate* file from the state file on purpose:
    save_state()'s atomic rename swaps out the state file's underlying
    inode, which would silently invalidate an flock() held on that path
    for every write after the first (flock is per-inode, not per-path).

    Not exercised by the documented single-threaded default deployment
    (Werkzeug's dev server processes one request at a time unless
    threaded=True), but a real risk the moment anyone runs this behind a
    threaded dev server or a multi-worker WSGI server - a foreseeable
    step once someone hardens their deployment past the dev-server
    warning, exactly as the TLS-reverse-proxy setup already nudges
    toward.
    """
    fd = os.open(f"{_state_path()}.lock", os.O_CREAT | os.O_RDWR, 0o640)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


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
    with _locked():
        data = load_state()
        if len(data["allowlist"]) >= MAX_ALLOWLIST_RULES:
            data["allowlist"].pop(0)  # drop oldest
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
    with _locked():
        data = load_state()
        before = len(data["allowlist"])
        data["allowlist"] = [r for r in data["allowlist"] if r["id"] != rule_id]
        save_state(data)
    return len(data["allowlist"]) != before


def mark_resolved(alert_key, note="", outcome=None):
    with _locked():
        data = load_state()
        data["resolved"] = [r for r in data["resolved"] if r["alert_key"] != alert_key]
        if len(data["resolved"]) >= MAX_RESOLVED_ENTRIES:
            data["resolved"].pop(0)  # drop oldest
        data["resolved"].append(
            {
                "alert_key": alert_key,
                "resolved_at": datetime.now(timezone.utc).isoformat(),
                "note": note,
                "outcome": outcome,
            }
        )
        save_state(data)
    return data["resolved"]


def unmark_resolved(alert_key):
    with _locked():
        data = load_state()
        data["resolved"] = [r for r in data["resolved"] if r["alert_key"] != alert_key]
        save_state(data)


def resolved_keys(resolved_entries):
    return {r["alert_key"] for r in resolved_entries}


def closed_keys(resolved_entries):
    """Resolved alert keys that don't need to stay visible as open items.

    An alert resolved with outcome "investigating" is still in progress, so
    it's excluded here and continues to count toward unresolved_count.
    """
    return {r["alert_key"] for r in resolved_entries if r.get("outcome") not in OPEN_OUTCOMES}


def resolved_by_key(resolved_entries):
    return {r["alert_key"]: r for r in resolved_entries}
