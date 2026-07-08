import vendor_lookup


def test_lookup_vendor_known_oui():
    # B8:27:EB is Raspberry Pi Foundation's most well-known registered
    # block - about as safe a "this will never change" fixture as exists.
    assert vendor_lookup.lookup_vendor("B8:27:EB:00:00:00") == "Raspberry Pi Foundation"


def test_lookup_vendor_accepts_lowercase_and_different_separators():
    assert vendor_lookup.lookup_vendor("b8:27:eb:aa:bb:cc") == "Raspberry Pi Foundation"
    assert vendor_lookup.lookup_vendor("B8-27-EB-AA-BB-CC") == "Raspberry Pi Foundation"


def test_lookup_vendor_none_for_empty_input():
    assert vendor_lookup.lookup_vendor(None) is None
    assert vendor_lookup.lookup_vendor("") is None


def test_lookup_vendor_none_for_garbage_input():
    assert vendor_lookup.lookup_vendor("not-a-mac-address") is None


def test_lookup_vendor_uses_shared_lazy_parser():
    # Calling it twice shouldn't reload the (large) bundled database twice.
    vendor_lookup._parser = None
    vendor_lookup.lookup_vendor("B8:27:EB:00:00:00")
    parser_after_first = vendor_lookup._parser
    assert parser_after_first is not None
    vendor_lookup.lookup_vendor("B8:27:EB:00:00:01")
    assert vendor_lookup._parser is parser_after_first


def test_vendor_map_resolves_known_macs():
    result = vendor_lookup.vendor_map({
        "192.168.1.10": "B8:27:EB:11:22:33",
        "192.168.1.20": "not-a-mac",
    })
    assert result["192.168.1.10"] == "Raspberry Pi Foundation"
    assert "192.168.1.20" not in result


def test_vendor_map_empty_input():
    assert vendor_lookup.vendor_map({}) == {}
    assert vendor_lookup.vendor_map(None) == {}
