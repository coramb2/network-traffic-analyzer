#!/usr/bin/env python3
"""
Persistent "have we ever seen this device before" store, used to flag a
brand-new device the moment it first shows up (Firewalla/UniFi-style "new
device on your network" alerts) rather than only after someone notices it
in the Devices panel.

Identity is keyed by MAC when we have one (it survives a DHCP lease
change, unlike an IP), falling back to IP for traffic where no Ethernet
layer was observed (see analyzer.py's ip_mac_map). This means a device
that changes IP but keeps its MAC is correctly recognized as already
known, while a device we've only ever seen via its IP will - unavoidably,
with no MAC to key on - look "new" again if its IP changes.

Entirely offline and local; no third-party lookups here, unlike geoip.py.
"""

import json
import os
from datetime import datetime, timezone


def _store_path():
    return os.environ.get("KNOWN_DEVICES_PATH", "known_devices.json")


def _identity_key(ip, mac):
    return f"mac:{mac.lower()}" if mac else f"ip:{ip}"


def _load():
    try:
        with open(_store_path()) as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError):
        return {}
    entries = data.get("entries", {})
    return entries if isinstance(entries, dict) else {}


def _save(entries):
    """Write via temp file + rename so a concurrent reader never sees a
    half-written file (same approach as the alert-state/geoip stores)."""
    path = _store_path()
    tmp_path = f"{path}.tmp"
    payload = {"updated_at": datetime.now(timezone.utc).isoformat(), "entries": entries}
    with open(tmp_path, "w") as f:
        json.dump(payload, f, indent=2)
    os.chmod(tmp_path, 0o640)
    os.replace(tmp_path, path)


def record_and_diff(devices):
    """Record every device seen this run, returning the ones never seen
    in any previous run.

    devices: iterable of {"ip": str, "mac": str|None}. Order doesn't
    matter; duplicates (same identity key appearing twice) are collapsed.

    Returns a list of {"ip", "mac"} dicts for devices whose identity key
    (MAC if known, else IP) wasn't already in the store - in the same
    shape as the input, so callers can build alerts directly from it.

    Note this means the very first run against a fresh store reports
    every device as "new" - there's no history to compare against yet.
    """
    entries = _load()
    now = datetime.now(timezone.utc).isoformat()

    new_devices = []
    seen_keys = set()
    for device in devices:
        ip = device.get("ip")
        mac = device.get("mac")
        key = _identity_key(ip, mac)
        if key in seen_keys:
            continue
        seen_keys.add(key)

        if key not in entries:
            new_devices.append({"ip": ip, "mac": mac})
            entries[key] = {"ip": ip, "mac": mac, "first_seen": now}

    if new_devices:
        _save(entries)

    return new_devices
