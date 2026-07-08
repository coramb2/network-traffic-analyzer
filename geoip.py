#!/usr/bin/env python3
"""
Best-effort GeoIP/org lookup for public IPs seen in a capture, used to
give unfamiliar external addresses some context ("US, DigitalOcean" is a
lot more useful than a bare IP when deciding whether an alert is worth
investigating).

Opt-in (GEOIP_ENABLED / --geoip), unlike reverse-DNS: a lookup here sends
the IP to a third-party API (ip-api.com's free tier) rather than just your
own configured resolver, which is a real privacy tradeoff worth defaulting
off for. Results are cached on disk (geoip_cache.json) with a TTL, both to
respect that API's free-tier rate limit and because geolocation for a
given IP rarely changes day to day.
"""

import ipaddress
import json
import os
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeout
from datetime import datetime, timedelta, timezone

GEOIP_API_URL = "http://ip-api.com/json/{ip}?fields=status,country,countryCode,org,as"
DEFAULT_TTL_DAYS = 30
DEFAULT_MAX_LOOKUPS = 15


def _cache_path():
    return os.environ.get("GEOIP_CACHE_PATH", "geoip_cache.json")


def is_public_ip(ip):
    """True for IPs actually worth geolocating - excludes private, loopback,
    link-local, multicast, and other reserved ranges, not just RFC1918."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_reserved
        or addr.is_unspecified
    )


def _load_cache():
    try:
        with open(_cache_path()) as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError):
        return {}
    entries = data.get("entries", {})
    return entries if isinstance(entries, dict) else {}


def _save_cache(entries):
    """Write via temp file + rename so a concurrent reader never sees a
    half-written file (same approach as the alert-state/device-name stores)."""
    path = _cache_path()
    tmp_path = f"{path}.tmp"
    payload = {"updated_at": datetime.now(timezone.utc).isoformat(), "entries": entries}
    with open(tmp_path, "w") as f:
        json.dump(payload, f, indent=2)
    os.chmod(tmp_path, 0o640)
    os.replace(tmp_path, path)


def _lookup_one(ip, timeout=3):
    """Single lookup against the GeoIP API. None on any failure - a bad
    response, a network error, or the API's own "failed to locate" status
    are all just "we don't know", not something to raise over."""
    url = GEOIP_API_URL.format(ip=ip)
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, OSError, ValueError):
        return None

    if data.get("status") != "success":
        return None

    return {
        "country": data.get("country"),
        "country_code": data.get("countryCode"),
        "org": data.get("org") or data.get("as"),
    }


def resolve_geoip(ips, max_lookups=DEFAULT_MAX_LOOKUPS, ttl_days=DEFAULT_TTL_DAYS,
                   per_lookup_timeout=3, max_workers=5):
    """Best-effort geo/org lookup for public IPs, backed by an on-disk cache.

    Private/loopback/link-local/etc. IPs are skipped entirely - there's no
    point geolocating a device on your own LAN. Cache entries younger than
    ttl_days are reused without a new network request, including entries
    for a lookup that previously failed (so a single bad/rate-limited IP
    doesn't get retried every run for the rest of the TTL window). Only
    the remaining IPs are queried, capped at max_lookups to stay well
    under the upstream API's free-tier rate limit and keep a capture run
    fast even with a long top-IPs list.

    Returns {ip: {country, country_code, org}} for every IP resolved, from
    cache or a fresh lookup, combined.
    """
    public_ips = [ip for ip in dict.fromkeys(ips) if is_public_ip(ip)]
    if not public_ips:
        return {}

    cache = _load_cache()
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(days=ttl_days)

    results = {}
    to_lookup = []
    for ip in public_ips:
        entry = cache.get(ip)
        cached_at = None
        if entry:
            try:
                cached_at = datetime.fromisoformat(entry["cached_at"])
            except (KeyError, ValueError):
                cached_at = None

        if cached_at and cached_at > cutoff:
            if entry.get("data"):
                results[ip] = entry["data"]
            continue

        to_lookup.append(ip)

    to_lookup = to_lookup[:max_lookups]
    if to_lookup:
        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            futures = {pool.submit(_lookup_one, ip, per_lookup_timeout): ip for ip in to_lookup}
            for future, ip in futures.items():
                try:
                    data = future.result(timeout=per_lookup_timeout + 1)
                except FuturesTimeout:
                    data = None
                cache[ip] = {"cached_at": now.isoformat(), "data": data}
                if data:
                    results[ip] = data

        _save_cache(cache)

    return results
