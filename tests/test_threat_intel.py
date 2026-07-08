import json
from datetime import datetime, timedelta, timezone

import pytest

import threat_intel


@pytest.fixture(autouse=True)
def cache_file(tmp_path, monkeypatch):
    monkeypatch.setenv("THREAT_INTEL_CACHE_PATH", str(tmp_path / "threat_intel_cache.json"))
    return tmp_path / "threat_intel_cache.json"


# --- match_ips: basic behavior -------------------------------------------

def test_match_ips_empty_input_skips_blocklist_fetch(monkeypatch):
    called = []
    monkeypatch.setattr(threat_intel, "get_blocklist", lambda **kw: called.append(1))
    assert threat_intel.match_ips([]) == {}
    assert called == []


def test_match_ips_flags_ips_on_blocklist(monkeypatch):
    monkeypatch.setattr(threat_intel, "get_blocklist", lambda **kw: {"1.2.3.4"})
    result = threat_intel.match_ips(["1.2.3.4", "5.6.7.8"])
    assert list(result.keys()) == ["1.2.3.4"]
    assert result["1.2.3.4"]["source"] == threat_intel.SOURCE_NAME


def test_match_ips_no_matches_returns_empty_dict(monkeypatch):
    monkeypatch.setattr(threat_intel, "get_blocklist", lambda **kw: {"9.9.9.9"})
    assert threat_intel.match_ips(["1.2.3.4"]) == {}


def test_match_ips_empty_blocklist_returns_empty_without_error(monkeypatch):
    monkeypatch.setattr(threat_intel, "get_blocklist", lambda **kw: set())
    assert threat_intel.match_ips(["1.2.3.4"]) == {}


def test_match_ips_dedupes_input(monkeypatch):
    monkeypatch.setattr(threat_intel, "get_blocklist", lambda **kw: {"1.2.3.4"})
    result = threat_intel.match_ips(["1.2.3.4", "1.2.3.4"])
    assert list(result.keys()) == ["1.2.3.4"]


# --- get_blocklist: caching behavior --------------------------------------

def test_get_blocklist_fetches_when_no_cache(monkeypatch):
    monkeypatch.setattr(threat_intel, "_load_cache", lambda: None)
    saved = {}
    monkeypatch.setattr(threat_intel, "_save_cache", lambda ips: saved.update(ips=ips))
    monkeypatch.setattr(threat_intel, "_fetch_blocklist", lambda timeout: {"1.2.3.4"})

    result = threat_intel.get_blocklist()
    assert result == {"1.2.3.4"}
    assert saved["ips"] == {"1.2.3.4"}


def test_get_blocklist_reuses_fresh_cache_without_fetch(monkeypatch):
    fresh_cache = {"fetched_at": datetime.now(timezone.utc).isoformat(), "ips": ["1.2.3.4"]}
    monkeypatch.setattr(threat_intel, "_load_cache", lambda: fresh_cache)
    called = []
    monkeypatch.setattr(threat_intel, "_fetch_blocklist", lambda timeout: called.append(1))

    result = threat_intel.get_blocklist(ttl_hours=24)
    assert result == {"1.2.3.4"}
    assert called == []


def test_get_blocklist_stale_cache_triggers_refetch(monkeypatch):
    stale_time = datetime.now(timezone.utc) - timedelta(hours=48)
    stale_cache = {"fetched_at": stale_time.isoformat(), "ips": ["1.2.3.4"]}
    monkeypatch.setattr(threat_intel, "_load_cache", lambda: stale_cache)
    monkeypatch.setattr(threat_intel, "_save_cache", lambda ips: None)
    monkeypatch.setattr(threat_intel, "_fetch_blocklist", lambda timeout: {"9.9.9.9"})

    result = threat_intel.get_blocklist(ttl_hours=24)
    assert result == {"9.9.9.9"}


def test_get_blocklist_falls_back_to_stale_cache_on_fetch_failure(monkeypatch):
    """A temporarily unreachable feed shouldn't wipe out an otherwise-still-useful list."""
    stale_time = datetime.now(timezone.utc) - timedelta(hours=48)
    stale_cache = {"fetched_at": stale_time.isoformat(), "ips": ["1.2.3.4"]}
    monkeypatch.setattr(threat_intel, "_load_cache", lambda: stale_cache)
    monkeypatch.setattr(threat_intel, "_fetch_blocklist", lambda timeout: None)

    result = threat_intel.get_blocklist(ttl_hours=24)
    assert result == {"1.2.3.4"}


def test_get_blocklist_no_cache_and_fetch_fails_returns_empty_set(monkeypatch):
    monkeypatch.setattr(threat_intel, "_load_cache", lambda: None)
    monkeypatch.setattr(threat_intel, "_fetch_blocklist", lambda timeout: None)

    assert threat_intel.get_blocklist() == set()


# --- cache read/write -------------------------------------------------------

def test_save_and_load_cache_round_trip(cache_file):
    threat_intel._save_cache({"1.2.3.4", "5.6.7.8"})
    assert cache_file.exists()

    loaded = threat_intel._load_cache()
    assert set(loaded["ips"]) == {"1.2.3.4", "5.6.7.8"}


def test_load_cache_missing_file_returns_none():
    assert threat_intel._load_cache() is None


def test_load_cache_corrupt_json_returns_none(cache_file):
    cache_file.write_text("not json")
    assert threat_intel._load_cache() is None


def test_load_cache_missing_expected_fields_returns_none(cache_file):
    cache_file.write_text(json.dumps({"something_else": True}))
    assert threat_intel._load_cache() is None


# --- _fetch_blocklist (the real HTTP-calling function) ----------------------

class FakeResponse:
    def __init__(self, body):
        self._body = body

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def read(self):
        return self._body


def test_fetch_blocklist_parses_plain_ip_list(monkeypatch):
    body = b"# comment line\n\n1.2.3.4\n5.6.7.8\n"
    monkeypatch.setattr(threat_intel.urllib.request, "urlopen", lambda url, timeout: FakeResponse(body))

    result = threat_intel._fetch_blocklist()
    assert result == {"1.2.3.4", "5.6.7.8"}


def test_fetch_blocklist_skips_invalid_lines(monkeypatch):
    body = b"1.2.3.4\nnot-an-ip\n\n5.6.7.8\n"
    monkeypatch.setattr(threat_intel.urllib.request, "urlopen", lambda url, timeout: FakeResponse(body))

    result = threat_intel._fetch_blocklist()
    assert result == {"1.2.3.4", "5.6.7.8"}


def test_fetch_blocklist_network_error_returns_none(monkeypatch):
    def raise_error(url, timeout):
        raise threat_intel.urllib.error.URLError("timed out")

    monkeypatch.setattr(threat_intel.urllib.request, "urlopen", raise_error)
    assert threat_intel._fetch_blocklist() is None


def test_fetch_blocklist_empty_response_returns_none(monkeypatch):
    monkeypatch.setattr(threat_intel.urllib.request, "urlopen", lambda url, timeout: FakeResponse(b""))
    assert threat_intel._fetch_blocklist() is None
