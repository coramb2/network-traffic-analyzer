#!/usr/bin/env python3
"""
Best-effort IP reputation check against a public threat-intelligence
blocklist, so traffic to/from a known-malicious IP (botnet C2 servers,
mainly) gets flagged as a HIGH severity alert instead of blending in with
ordinary traffic.

Source: abuse.ch's Feodo Tracker (https://feodotracker.abuse.ch/), a free,
no-API-key-required feed of active botnet command-and-control IPs. Opt-in
(THREAT_INTEL_ENABLED / --threat-intel): unlike GeoIP, no per-IP data
about your traffic is sent anywhere (this only downloads a public list),
but it's still a network call to a third party from your home server, so
it defaults off like the other opt-in lookups.

The blocklist itself (not per-IP results) is cached on disk with a TTL,
both to avoid hammering the feed on every run and so a temporarily
unreachable feed (or this sandbox's network policy) doesn't break
detection - the last successfully fetched list is reused until a refresh
succeeds.

This is a best-effort signal, not a complete threat feed: it only covers
what Feodo Tracker has indexed, so a clean result here doesn't mean an IP
is actually safe - just that it isn't on this particular list.
"""

import ipaddress
import json
import os
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone

BLOCKLIST_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist.txt"
SOURCE_NAME = "abuse.ch Feodo Tracker"
DEFAULT_TTL_HOURS = 24


def _cache_path():
    return os.environ.get("THREAT_INTEL_CACHE_PATH", "threat_intel_cache.json")


def _load_cache():
    try:
        with open(_cache_path()) as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(data.get("ips"), list) or "fetched_at" not in data:
        return None
    return data


def _save_cache(ips):
    """Write via temp file + rename so a concurrent reader never sees a
    half-written file (same approach as the geoip/alert-state stores)."""
    path = _cache_path()
    tmp_path = f"{path}.tmp"
    payload = {"fetched_at": datetime.now(timezone.utc).isoformat(), "ips": sorted(ips)}
    with open(tmp_path, "w") as f:
        json.dump(payload, f, indent=2)
    os.chmod(tmp_path, 0o640)
    os.replace(tmp_path, path)


def _fetch_blocklist(timeout=10):
    """Download and parse the blocklist. Returns a set of IPs, or None on
    any failure (network error, unexpected content, etc.) - a failed fetch
    is just "no update this time", never something to raise over."""
    try:
        with urllib.request.urlopen(BLOCKLIST_URL, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", errors="replace")
    except (urllib.error.URLError, OSError):
        return None

    ips = set()
    for line in body.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            ipaddress.ip_address(line)
        except ValueError:
            continue
        ips.add(line)
    return ips or None


def get_blocklist(ttl_hours=DEFAULT_TTL_HOURS, timeout=10):
    """The current blocklist as a set of IPs, refreshing from the feed if
    the cache is missing/stale. Falls back to a stale cache (rather than
    an empty set) if a refresh is attempted but fails - a day-old list is
    far more useful than no list at all."""
    cache = _load_cache()
    if cache:
        try:
            fetched_at = datetime.fromisoformat(cache["fetched_at"])
        except ValueError:
            fetched_at = None
        if fetched_at and fetched_at > datetime.now(timezone.utc) - timedelta(hours=ttl_hours):
            return set(cache["ips"])

    fresh = _fetch_blocklist(timeout)
    if fresh is not None:
        _save_cache(fresh)
        return fresh

    return set(cache["ips"]) if cache else set()


def match_ips(ips, ttl_hours=DEFAULT_TTL_HOURS, timeout=10):
    """Check ips against the blocklist, returning
    {ip: {"source": SOURCE_NAME}} for every match. Returns {} immediately
    for empty input, without even touching the blocklist/cache."""
    if not ips:
        return {}

    blocklist = get_blocklist(ttl_hours=ttl_hours, timeout=timeout)
    if not blocklist:
        return {}

    return {ip: {"source": SOURCE_NAME} for ip in dict.fromkeys(ips) if ip in blocklist}
