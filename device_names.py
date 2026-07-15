#!/usr/bin/env python3
"""
Device identity: friendly names for IPs, plus best-effort reverse-DNS
resolution used to *suggest* names.

Three independent pieces:
- Manual names (load_names/set_name/remove_name) live in a small JSON file
  in the shared state volume, written only by the dashboard. This is the
  source of truth for what a device is called.
- A name can optionally be tied to a MAC address too (set_name(..., mac=)),
  stored alongside the IP-keyed entry rather than instead of it - existing
  callers that only ever deal in IPs (load_names(), the dashboard's own
  GET /api/devices) keep working unchanged. resolve_name() is the one that
  knows to prefer the MAC-keyed name when a MAC is available, which is how
  a name survives a DHCP lease change: the MAC stays the same even when
  the IP doesn't. Devices we've never seen an Ethernet source MAC for
  (see analyzer.py) still only ever get an IP-keyed name - there's nothing
  more stable to key on for those.
- resolve_hostnames() does reverse-DNS (PTR) lookups for a set of IPs.
  The capture container runs this after a run and stores the result in
  that run's report as auto-suggestions; it never writes the names file.
"""

import contextlib
import fcntl
import ipaddress
import json
import os
import re
import socket
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeout
from datetime import datetime, timezone

# A friendly name is a short label ("Cora's Laptop"), not free-form text -
# capped so a request can't bloat device_names.json (every load_names()
# call reads the whole file) with an arbitrarily large string.
MAX_NAME_LENGTH = 100

# Standard colon- or hyphen-separated MAC notation, either separator but
# not mixed, either case. Also caps the string's length (unlike name
# above, this had no validation at all until now) - a fixed-format value
# to key mac_names by, not free-form text.
MAC_RE = re.compile(r"^[0-9a-fA-F]{2}([:-])(?:[0-9a-fA-F]{2}\1){4}[0-9a-fA-F]{2}$")

# Bounds memory/disk even if an authenticated client adds names for many
# distinct IPs or MACs - without a cap, either dict would otherwise grow
# by one entry per never-before-seen key forever (same reasoning as
# webapp.py's _LOGIN_ATTEMPT_MAX_TRACKED). Real home networks have
# nowhere near this many devices.
MAX_TRACKED_DEVICES = 5000
MAX_TRACKED_MACS = 5000


def _names_path():
    return os.environ.get("DEVICE_NAMES_PATH", "device_names.json")


def _load():
    try:
        with open(_names_path()) as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError):
        return {}, {}
    names = data.get("names", {})
    mac_names = data.get("mac_names", {})
    return (
        names if isinstance(names, dict) else {},
        mac_names if isinstance(mac_names, dict) else {},
    )


def load_names():
    """Return the ip -> name mapping, or {} if the file is missing/corrupt.

    Unchanged in shape regardless of whether any entry also has a MAC tied
    to it - existing callers that only ever deal in IPs don't need to
    change. Use resolve_name() instead of this when a MAC is available and
    you want a name to survive that device's IP changing.
    """
    names, _ = _load()
    return names


def load_mac_names():
    """Return the mac (lowercased) -> name mapping, or {} if none are set."""
    _, mac_names = _load()
    return mac_names


def resolve_name(ip, mac=None, names=None, mac_names=None):
    """The name to show for a device, preferring its MAC-keyed name (which
    survives an IP change) over its IP-keyed one.

    names/mac_names can be passed in when the caller already loaded them
    (e.g. once per request instead of once per device) - loaded fresh
    otherwise.
    """
    if names is None or mac_names is None:
        names, mac_names = _load()
    if mac and mac.lower() in mac_names:
        return mac_names[mac.lower()]
    return names.get(ip)


def _save(names, mac_names):
    """Write via temp file + rename so a concurrent reader never sees a
    half-written file (same approach as the alert-state store)."""
    path = _names_path()
    tmp_path = f"{path}.tmp"
    payload = {
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "names": names,
        "mac_names": mac_names,
    }
    with open(tmp_path, "w") as f:
        json.dump(payload, f, indent=2)
    os.chmod(tmp_path, 0o640)
    os.replace(tmp_path, path)


@contextlib.contextmanager
def _locked():
    """Serializes a _load()-modify-_save() cycle across threads and
    processes via an OS-level advisory lock on a dedicated lock file -
    see alert_rules._locked() for why this is a separate file from the
    names file itself (an flock() held on the live path would be
    silently invalidated by _save()'s atomic rename after the first
    write) and why this matters despite the documented single-threaded
    default deployment not currently triggering it.
    """
    fd = os.open(f"{_names_path()}.lock", os.O_CREAT | os.O_RDWR, 0o640)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def is_valid_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def is_valid_mac(mac):
    return bool(MAC_RE.match(mac or ""))


def _evict_oldest_if_full(d, key, cap):
    """Drop the oldest-tracked key before adding a new one past the cap
    (same eviction approach as webapp.py's login-attempt tracking dict)."""
    if key not in d and len(d) >= cap:
        del d[next(iter(d))]


def set_name(ip, name, mac=None):
    """Set (or, with a blank name, clear) the friendly name for an IP -
    and, if mac is given, tie that same name to the MAC too, so it's still
    found (via resolve_name()) after this IP is reassigned to something
    else. Caller is responsible for validating the IP and MAC first; we
    assert both here as a safety net.

    Returns the resulting ip -> name map, same as before mac_names existed.
    """
    if not is_valid_ip(ip):
        raise ValueError(f"Not a valid IP address: {ip}")
    if mac and not is_valid_mac(mac):
        raise ValueError(f"Not a valid MAC address: {mac}")
    with _locked():
        names, mac_names = _load()
        name = (name or "").strip()[:MAX_NAME_LENGTH]
        mac_key = mac.lower() if mac else None
        if name:
            _evict_oldest_if_full(names, ip, MAX_TRACKED_DEVICES)
            names[ip] = name
            if mac_key:
                _evict_oldest_if_full(mac_names, mac_key, MAX_TRACKED_MACS)
                mac_names[mac_key] = name
        else:
            names.pop(ip, None)
            if mac_key:
                mac_names.pop(mac_key, None)
        _save(names, mac_names)
    return names


def remove_name(ip, mac=None):
    with _locked():
        names, mac_names = _load()
        existed = ip in names
        names.pop(ip, None)
        if mac:
            mac_names.pop(mac.lower(), None)
        _save(names, mac_names)
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
