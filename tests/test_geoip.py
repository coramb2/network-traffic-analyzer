import json
from datetime import datetime, timedelta, timezone

import pytest

import geoip


@pytest.fixture(autouse=True)
def cache_file(tmp_path, monkeypatch):
    monkeypatch.setenv("GEOIP_CACHE_PATH", str(tmp_path / "geoip_cache.json"))
    return tmp_path / "geoip_cache.json"


# --- is_public_ip -------------------------------------------------------

@pytest.mark.parametrize("ip,expected", [
    ("8.8.8.8", True),
    ("93.184.216.34", True),
    ("192.168.1.1", False),
    ("10.0.0.1", False),
    ("172.16.0.1", False),
    ("127.0.0.1", False),
    ("169.254.1.1", False),
    ("224.0.0.1", False),  # multicast
    ("0.0.0.0", False),
    ("::1", False),
    ("2001:db8::1", False),  # documentation range is reserved
    ("not-an-ip", False),
    ("", False),
])
def test_is_public_ip(ip, expected):
    assert geoip.is_public_ip(ip) is expected


# --- resolve_geoip: basic behavior --------------------------------------

def test_resolve_geoip_empty_input():
    assert geoip.resolve_geoip([]) == {}


def test_resolve_geoip_skips_private_ips(monkeypatch):
    called = []
    monkeypatch.setattr(geoip, "_lookup_one", lambda ip, timeout: called.append(ip))
    geoip.resolve_geoip(["192.168.1.1", "10.0.0.1"])
    assert called == []


def test_resolve_geoip_looks_up_public_ips(monkeypatch):
    monkeypatch.setattr(geoip, "_lookup_one", lambda ip, timeout: {
        "country": "United States", "country_code": "US", "org": "Google LLC",
    })
    result = geoip.resolve_geoip(["8.8.8.8"])
    assert result["8.8.8.8"]["country_code"] == "US"


def test_resolve_geoip_dedupes_input(monkeypatch):
    calls = []

    def fake_lookup(ip, timeout):
        calls.append(ip)
        return {"country": "X", "country_code": "XX", "org": "Y"}

    monkeypatch.setattr(geoip, "_lookup_one", fake_lookup)
    geoip.resolve_geoip(["8.8.8.8", "8.8.8.8", "8.8.8.8"])
    assert calls == ["8.8.8.8"]


def test_resolve_geoip_mixed_public_and_private(monkeypatch):
    monkeypatch.setattr(geoip, "_lookup_one", lambda ip, timeout: {
        "country": "X", "country_code": "XX", "org": "Y",
    })
    result = geoip.resolve_geoip(["8.8.8.8", "192.168.1.1"])
    assert list(result.keys()) == ["8.8.8.8"]


def test_resolve_geoip_failed_lookup_omitted_from_results(monkeypatch):
    monkeypatch.setattr(geoip, "_lookup_one", lambda ip, timeout: None)
    result = geoip.resolve_geoip(["8.8.8.8"])
    assert result == {}


def test_resolve_geoip_respects_max_lookups(monkeypatch):
    calls = []

    def fake_lookup(ip, timeout):
        calls.append(ip)
        return {"country": "X", "country_code": "XX", "org": "Y"}

    monkeypatch.setattr(geoip, "_lookup_one", fake_lookup)
    ips = [f"8.8.8.{i}" for i in range(10)]
    geoip.resolve_geoip(ips, max_lookups=3)
    assert len(calls) == 3


# --- caching behavior -----------------------------------------------------

def test_resolve_geoip_writes_cache(monkeypatch, cache_file):
    monkeypatch.setattr(geoip, "_lookup_one", lambda ip, timeout: {
        "country": "United States", "country_code": "US", "org": "Google LLC",
    })
    geoip.resolve_geoip(["8.8.8.8"])

    assert cache_file.exists()
    data = json.loads(cache_file.read_text())
    assert data["entries"]["8.8.8.8"]["data"]["country_code"] == "US"


def test_resolve_geoip_reuses_fresh_cache_without_new_lookup(monkeypatch):
    calls = []
    monkeypatch.setattr(geoip, "_lookup_one", lambda ip, timeout: calls.append(ip))

    fresh_cache = {
        "8.8.8.8": {
            "cached_at": datetime.now(timezone.utc).isoformat(),
            "data": {"country": "United States", "country_code": "US", "org": "Google LLC"},
        }
    }
    monkeypatch.setattr(geoip, "_load_cache", lambda: fresh_cache)
    monkeypatch.setattr(geoip, "_save_cache", lambda entries: None)

    result = geoip.resolve_geoip(["8.8.8.8"])
    assert calls == []
    assert result["8.8.8.8"]["country_code"] == "US"


def test_resolve_geoip_expired_cache_triggers_new_lookup(monkeypatch):
    calls = []

    def fake_lookup(ip, timeout):
        calls.append(ip)
        return {"country": "United States", "country_code": "US", "org": "Google LLC"}

    monkeypatch.setattr(geoip, "_lookup_one", fake_lookup)

    stale_time = datetime.now(timezone.utc) - timedelta(days=90)
    stale_cache = {"8.8.8.8": {"cached_at": stale_time.isoformat(), "data": {"country_code": "US"}}}
    monkeypatch.setattr(geoip, "_load_cache", lambda: stale_cache)
    monkeypatch.setattr(geoip, "_save_cache", lambda entries: None)

    geoip.resolve_geoip(["8.8.8.8"], ttl_days=30)
    assert calls == ["8.8.8.8"]


def test_resolve_geoip_caches_failed_lookups_too(monkeypatch):
    """A consistently-failing/rate-limited IP shouldn't be retried every
    single run for the rest of the TTL window."""
    saved = {}
    monkeypatch.setattr(geoip, "_lookup_one", lambda ip, timeout: None)
    monkeypatch.setattr(geoip, "_load_cache", lambda: {})
    monkeypatch.setattr(geoip, "_save_cache", lambda entries: saved.update(entries))

    geoip.resolve_geoip(["8.8.8.8"])
    assert "8.8.8.8" in saved
    assert saved["8.8.8.8"]["data"] is None


# --- _lookup_one (the real HTTP-calling function) --------------------------

class FakeResponse:
    def __init__(self, body):
        self._body = body

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def read(self):
        return self._body


def test_lookup_one_success(monkeypatch):
    body = json.dumps({
        "status": "success", "country": "United States", "countryCode": "US",
        "org": "Google LLC", "as": "AS15169 Google LLC",
    }).encode()
    monkeypatch.setattr(geoip.urllib.request, "urlopen", lambda url, timeout: FakeResponse(body))

    result = geoip._lookup_one("8.8.8.8")
    assert result == {"country": "United States", "country_code": "US", "org": "Google LLC"}


def test_lookup_one_falls_back_to_as_when_org_missing(monkeypatch):
    body = json.dumps({"status": "success", "country": "X", "countryCode": "XX", "as": "AS1234 Some ISP"}).encode()
    monkeypatch.setattr(geoip.urllib.request, "urlopen", lambda url, timeout: FakeResponse(body))

    result = geoip._lookup_one("1.2.3.4")
    assert result["org"] == "AS1234 Some ISP"


def test_lookup_one_api_failure_status_returns_none(monkeypatch):
    body = json.dumps({"status": "fail", "message": "private range"}).encode()
    monkeypatch.setattr(geoip.urllib.request, "urlopen", lambda url, timeout: FakeResponse(body))
    assert geoip._lookup_one("8.8.8.8") is None


def test_lookup_one_network_error_returns_none(monkeypatch):
    def raise_error(url, timeout):
        raise geoip.urllib.error.URLError("timed out")

    monkeypatch.setattr(geoip.urllib.request, "urlopen", raise_error)
    assert geoip._lookup_one("8.8.8.8") is None


def test_lookup_one_malformed_json_returns_none(monkeypatch):
    monkeypatch.setattr(geoip.urllib.request, "urlopen", lambda url, timeout: FakeResponse(b"not json"))
    assert geoip._lookup_one("8.8.8.8") is None
