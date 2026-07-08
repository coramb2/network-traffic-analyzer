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
