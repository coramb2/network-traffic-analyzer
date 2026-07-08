import json

import pytest

import known_devices


@pytest.fixture(autouse=True)
def store_file(tmp_path, monkeypatch):
    monkeypatch.setenv("KNOWN_DEVICES_PATH", str(tmp_path / "known_devices.json"))
    return tmp_path / "known_devices.json"


def test_all_devices_new_against_empty_store():
    devices = [{"ip": "192.168.1.5", "mac": "aa:bb:cc:dd:ee:ff"}, {"ip": "192.168.1.6", "mac": None}]
    new = known_devices.record_and_diff(devices)
    assert {d["ip"] for d in new} == {"192.168.1.5", "192.168.1.6"}


def test_same_devices_not_new_on_second_run():
    devices = [{"ip": "192.168.1.5", "mac": "aa:bb:cc:dd:ee:ff"}]
    known_devices.record_and_diff(devices)
    assert known_devices.record_and_diff(devices) == []


def test_only_the_actually_new_device_is_reported():
    known_devices.record_and_diff([{"ip": "192.168.1.5", "mac": "aa:bb:cc:dd:ee:ff"}])
    new = known_devices.record_and_diff([
        {"ip": "192.168.1.5", "mac": "aa:bb:cc:dd:ee:ff"},
        {"ip": "192.168.1.9", "mac": "11:22:33:44:55:66"},
    ])
    assert [d["ip"] for d in new] == ["192.168.1.9"]


def test_mac_keyed_identity_survives_ip_change():
    """A device keeping its MAC but getting a new DHCP-assigned IP is not
    reported as new - the whole point of preferring MAC over IP identity."""
    known_devices.record_and_diff([{"ip": "192.168.1.5", "mac": "aa:bb:cc:dd:ee:ff"}])
    new = known_devices.record_and_diff([{"ip": "192.168.1.77", "mac": "aa:bb:cc:dd:ee:ff"}])
    assert new == []


def test_ip_keyed_identity_used_when_no_mac_ever_seen():
    known_devices.record_and_diff([{"ip": "192.168.1.5", "mac": None}])
    # Same IP, still no MAC - not new.
    assert known_devices.record_and_diff([{"ip": "192.168.1.5", "mac": None}]) == []
    # A different IP with no MAC has a different identity key - new.
    new = known_devices.record_and_diff([{"ip": "192.168.1.6", "mac": None}])
    assert [d["ip"] for d in new] == ["192.168.1.6"]


def test_duplicate_devices_in_same_call_collapsed():
    devices = [{"ip": "192.168.1.5", "mac": "aa:bb:cc:dd:ee:ff"}] * 3
    new = known_devices.record_and_diff(devices)
    assert len(new) == 1


def test_mac_identity_is_case_insensitive():
    known_devices.record_and_diff([{"ip": "192.168.1.5", "mac": "AA:BB:CC:DD:EE:FF"}])
    new = known_devices.record_and_diff([{"ip": "192.168.1.6", "mac": "aa:bb:cc:dd:ee:ff"}])
    assert new == []


def test_store_persists_across_calls(store_file):
    known_devices.record_and_diff([{"ip": "192.168.1.5", "mac": "aa:bb:cc:dd:ee:ff"}])
    assert store_file.exists()
    data = json.loads(store_file.read_text())
    assert "mac:aa:bb:cc:dd:ee:ff" in data["entries"]
    assert data["entries"]["mac:aa:bb:cc:dd:ee:ff"]["ip"] == "192.168.1.5"


def test_corrupt_store_treated_as_empty(store_file):
    store_file.write_text("not json")
    new = known_devices.record_and_diff([{"ip": "192.168.1.5", "mac": None}])
    assert [d["ip"] for d in new] == ["192.168.1.5"]


def test_missing_store_treated_as_empty():
    new = known_devices.record_and_diff([{"ip": "192.168.1.5", "mac": None}])
    assert [d["ip"] for d in new] == ["192.168.1.5"]


def test_no_write_when_nothing_new(store_file):
    known_devices.record_and_diff([{"ip": "192.168.1.5", "mac": None}])
    mtime_before = store_file.stat().st_mtime_ns
    known_devices.record_and_diff([{"ip": "192.168.1.5", "mac": None}])
    assert store_file.stat().st_mtime_ns == mtime_before
