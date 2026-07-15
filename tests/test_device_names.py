import socket

import pytest

import device_names


@pytest.fixture(autouse=True)
def names_file(tmp_path, monkeypatch):
    monkeypatch.setenv("DEVICE_NAMES_PATH", str(tmp_path / "device_names.json"))
    return tmp_path / "device_names.json"


@pytest.mark.parametrize("ip,expected", [
    ("192.168.1.1", True),
    ("10.0.0.5", True),
    ("::1", True),
    ("2001:db8::1", True),
    ("not-an-ip", False),
    ("", False),
    ("999.999.999.999", False),
    ("<script>alert(1)</script>", False),
])
def test_is_valid_ip(ip, expected):
    assert device_names.is_valid_ip(ip) is expected


def test_load_names_defaults_to_empty_dict_when_missing():
    assert device_names.load_names() == {}


def test_load_names_defaults_to_empty_dict_when_corrupt(names_file):
    names_file.write_text("not json")
    assert device_names.load_names() == {}


def test_set_name_persists_and_round_trips():
    names = device_names.set_name("192.168.1.50", "Cora's Laptop")
    assert names["192.168.1.50"] == "Cora's Laptop"
    assert device_names.load_names()["192.168.1.50"] == "Cora's Laptop"


def test_set_name_strips_whitespace():
    device_names.set_name("192.168.1.50", "  Living Room TV  ")
    assert device_names.load_names()["192.168.1.50"] == "Living Room TV"


def test_set_blank_name_clears_existing_entry():
    device_names.set_name("192.168.1.50", "Something")
    device_names.set_name("192.168.1.50", "")
    assert "192.168.1.50" not in device_names.load_names()


def test_set_name_rejects_invalid_ip():
    with pytest.raises(ValueError):
        device_names.set_name("not-an-ip", "Whatever")


def test_remove_name_returns_true_when_existed():
    device_names.set_name("192.168.1.50", "Thing")
    assert device_names.remove_name("192.168.1.50") is True
    assert device_names.load_names() == {}


def test_remove_name_returns_false_when_absent():
    assert device_names.remove_name("192.168.1.99") is False


def test_set_name_truncates_oversized_input():
    """A friendly name is a short label, not free-form text - without a
    cap, a single request could bloat device_names.json (read in full on
    every load_names() call) with an arbitrarily large string."""
    huge_name = "A" * 10_000
    device_names.set_name("192.168.1.50", huge_name)
    stored = device_names.load_names()["192.168.1.50"]
    assert len(stored) == device_names.MAX_NAME_LENGTH
    assert stored == huge_name[:device_names.MAX_NAME_LENGTH]


# --- MAC-keyed naming (resolve_name) -------------------------------------

def test_set_name_with_mac_populates_both_maps():
    device_names.set_name("192.168.1.50", "Cora's Laptop", mac="AA:BB:CC:DD:EE:FF")
    assert device_names.load_names()["192.168.1.50"] == "Cora's Laptop"
    assert device_names.load_mac_names()["aa:bb:cc:dd:ee:ff"] == "Cora's Laptop"


def test_set_name_without_mac_leaves_mac_names_empty():
    device_names.set_name("192.168.1.50", "Cora's Laptop")
    assert device_names.load_mac_names() == {}


def test_resolve_name_prefers_mac_over_ip():
    """The whole point: once a name is tied to a MAC, it's found under
    that MAC even for a request naming a *different* IP - which is
    exactly what happens after a DHCP lease reassigns this IP."""
    device_names.set_name("192.168.1.50", "Cora's Laptop", mac="aa:bb:cc:dd:ee:ff")
    name = device_names.resolve_name("192.168.1.99", mac="aa:bb:cc:dd:ee:ff")
    assert name == "Cora's Laptop"


def test_resolve_name_survives_dhcp_style_ip_change():
    device_names.set_name("192.168.1.50", "Cora's Laptop", mac="aa:bb:cc:dd:ee:ff")
    # Device got a new IP from a lease renewal; nobody re-named it.
    new_ip = "192.168.1.77"
    name = device_names.resolve_name(new_ip, mac="aa:bb:cc:dd:ee:ff")
    assert name == "Cora's Laptop"


def test_resolve_name_falls_back_to_ip_when_no_mac_known():
    device_names.set_name("192.168.1.50", "Printer")
    assert device_names.resolve_name("192.168.1.50", mac=None) == "Printer"
    assert device_names.resolve_name("192.168.1.50", mac="aa:bb:cc:dd:ee:ff") == "Printer"


def test_resolve_name_returns_none_when_unnamed():
    assert device_names.resolve_name("192.168.1.50", mac="aa:bb:cc:dd:ee:ff") is None


def test_resolve_name_mac_lookup_is_case_insensitive():
    device_names.set_name("192.168.1.50", "Cora's Laptop", mac="AA:BB:CC:DD:EE:FF")
    assert device_names.resolve_name("192.168.1.99", mac="aa:bb:cc:dd:ee:ff") == "Cora's Laptop"


def test_blank_name_with_mac_clears_both_entries():
    device_names.set_name("192.168.1.50", "Cora's Laptop", mac="aa:bb:cc:dd:ee:ff")
    device_names.set_name("192.168.1.50", "", mac="aa:bb:cc:dd:ee:ff")
    assert device_names.load_names() == {}
    assert device_names.load_mac_names() == {}


def test_remove_name_with_mac_clears_both_entries():
    device_names.set_name("192.168.1.50", "Cora's Laptop", mac="aa:bb:cc:dd:ee:ff")
    device_names.remove_name("192.168.1.50", mac="aa:bb:cc:dd:ee:ff")
    assert device_names.load_names() == {}
    assert device_names.load_mac_names() == {}


def test_remove_name_without_mac_leaves_mac_names_entry_intact():
    """Removing by IP alone (no mac passed) can't know to clean up a
    mac-keyed entry set earlier - a known, accepted gap given the caller
    is responsible for passing mac when it has one."""
    device_names.set_name("192.168.1.50", "Cora's Laptop", mac="aa:bb:cc:dd:ee:ff")
    device_names.remove_name("192.168.1.50")
    assert device_names.load_names() == {}
    assert device_names.load_mac_names() == {"aa:bb:cc:dd:ee:ff": "Cora's Laptop"}


def test_load_mac_names_defaults_to_empty_dict_when_missing():
    assert device_names.load_mac_names() == {}


def test_load_mac_names_defaults_to_empty_dict_when_corrupt(names_file):
    names_file.write_text("not json")
    assert device_names.load_mac_names() == {}


def test_resolve_hostnames_empty_input_returns_empty_dict():
    assert device_names.resolve_hostnames([]) == {}


def test_resolve_hostnames_skips_invalid_ips(monkeypatch):
    monkeypatch.setattr(socket, "gethostbyaddr", lambda ip: (f"host-{ip}", [], [ip]))
    result = device_names.resolve_hostnames(["not-an-ip", "192.168.1.1"])
    assert result == {"192.168.1.1": "host-192.168.1.1"}


def test_resolve_hostnames_dedupes_input(monkeypatch):
    calls = []

    def fake_lookup(ip):
        calls.append(ip)
        return (f"host-{ip}", [], [ip])

    monkeypatch.setattr(socket, "gethostbyaddr", fake_lookup)
    device_names.resolve_hostnames(["192.168.1.1", "192.168.1.1"])
    assert calls == ["192.168.1.1"]


def test_resolve_hostnames_omits_ips_with_no_ptr_record(monkeypatch):
    def fake_lookup(ip):
        raise socket.herror("no PTR record")

    monkeypatch.setattr(socket, "gethostbyaddr", fake_lookup)
    result = device_names.resolve_hostnames(["192.168.1.1"])
    assert result == {}


def test_resolve_hostnames_omits_hostname_identical_to_ip(monkeypatch):
    """gethostbyaddr can return the IP itself as the "hostname" when there's
    no real PTR record on some resolvers - that's not a useful suggestion."""
    monkeypatch.setattr(socket, "gethostbyaddr", lambda ip: (ip, [], [ip]))
    result = device_names.resolve_hostnames(["192.168.1.1"])
    assert result == {}


def test_resolve_hostnames_respects_per_lookup_timeout(monkeypatch):
    import time

    def slow_lookup(ip):
        time.sleep(2)
        return (f"host-{ip}", [], [ip])

    monkeypatch.setattr(socket, "gethostbyaddr", slow_lookup)
    result = device_names.resolve_hostnames(["192.168.1.1"], per_lookup_timeout=0.1)
    assert result == {}
