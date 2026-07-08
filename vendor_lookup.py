#!/usr/bin/env python3
"""
MAC address -> vendor name lookup, via the `manuf` package (which bundles
Wireshark's actively-maintained manuf database - the same OUI-to-vendor
mapping Wireshark itself uses). Entirely offline: no network calls, no
rate limits, no privacy tradeoff to weigh, unlike geoip.py.

Deliberately not hand-rolled: the IEEE OUI registry has tens of thousands
of entries, and a hand-typed subset risks confidently mislabeling a
vendor, which is worse than no label at all for something meant to help
you recognize devices on your network.
"""

from manuf import manuf

_parser = None


def _get_parser():
    global _parser
    if _parser is None:
        _parser = manuf.MacParser()
    return _parser


def lookup_vendor(mac):
    """Best-effort vendor name for a MAC address, or None if unknown.

    Prefers the long/full vendor name (e.g. "Raspberry Pi Foundation")
    and falls back to the short one (e.g. "Apple") if that's all the
    database has for this OUI.
    """
    if not mac:
        return None
    parser = _get_parser()
    try:
        return parser.get_manuf_long(mac) or parser.get_manuf(mac)
    except (ValueError, KeyError):
        return None


def vendor_map(ip_to_mac):
    """{ip: mac} -> {ip: vendor} for every IP whose MAC resolved to a
    known vendor; IPs with no MAC or an unrecognized OUI are omitted."""
    result = {}
    for ip, mac in (ip_to_mac or {}).items():
        vendor = lookup_vendor(mac)
        if vendor:
            result[ip] = vendor
    return result
