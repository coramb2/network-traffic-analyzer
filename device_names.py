#!/usr/bin/env python3
"""
Device identity: friendly names for IPs, plus best-effort reverse-DNS
resolution used to *suggest* names.

Two independent pieces:
- Manual names (load_names/set_name/remove_name) live in a small JSON file
  in the shared state volume, written only by the dashboard. This is the
  source of truth for what a device is called.
- resolve_hostnames() does reverse-DNS (PTR) lookups for a set of IPs.
  The capture container runs this after a run and stores the result in
  that run's report as auto-suggestions; it never writes the names file.
"""

import ipaddress
import json
import os
import socket
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeout
from datetime import datetime, timezone

# A friendly name is a short label ("Cora's Laptop"), not free-form text -
# capped so a request can't bloat device_names.json (every load_names()
# call reads the whole file) with an arbitrarily large string.
MAX_NAME_LENGTH = 100


def _names_path():
    return os.environ.get("DEVICE_NAMES_PATH", "device_names.json")


def load_names():
    """Return the ip -> name mapping, or {} if the file is missing/corrupt."""
    try:
        with open(_names_path()) as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError):
        return {}
    names = data.get("names", {})
    return names if isinstance(names, dict) else {}


def _save_names(names):
    """Write via temp file + rename so a concurrent reader never sees a
    half-written file (same approach as the alert-state store)."""
    path = _names_path()
    tmp_path = f"{path}.tmp"
    payload = {"updated_at": datetime.now(timezone.utc).isoformat(), "names": names}
    with open(tmp_path, "w") as f:
        json.dump(payload, f, indent=2)
    os.chmod(tmp_path, 0o640)
    os.replace(tmp_path, path)


def is_valid_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def set_name(ip, name):
    """Set (or, with a blank name, clear) the friendly name for an IP.

    Returns the resulting names map. Caller is responsible for validating
    the IP first; we assert it here as a safety net.
    """
    if not is_valid_ip(ip):
        raise ValueError(f"Not a valid IP address: {ip}")
    names = load_names()
    name = (name or "").strip()[:MAX_NAME_LENGTH]
    if name:
        names[ip] = name
    else:
        names.pop(ip, None)
    _save_names(names)
    return names


def remove_name(ip):
    names = load_names()
    existed = ip in names
    names.pop(ip, None)
    _save_names(names)
    return existed


def resolve_hostnames(ips, per_lookup_timeout=1.0, max_workers=10):
    """Best-effort reverse-DNS for a list of IPs.

    Returns { ip: hostname } for the ones that resolved; IPs with no PTR
    record (or a lookup slower than per_lookup_timeout) are simply left
    out. Bounded in time so it can't stall the end of a capture run.
    """
    unique_ips = [ip for ip in dict.fromkeys(ips) if is_valid_ip(ip)]
    if not unique_ips:
        return {}

    def lookup(ip):
        return socket.gethostbyaddr(ip)[0]

    resolved = {}
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {pool.submit(lookup, ip): ip for ip in unique_ips}
        for future, ip in futures.items():
            try:
                hostname = future.result(timeout=per_lookup_timeout)
                if hostname and hostname != ip:
                    resolved[ip] = hostname
            except (FuturesTimeout, socket.herror, socket.gaierror, OSError):
                continue
    return resolved
