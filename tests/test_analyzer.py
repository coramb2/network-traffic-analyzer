import json
import os
import stat

import pytest
from rich.console import Group
from rich.panel import Panel
from scapy.all import ICMP, IP, TCP, UDP, Ether, Raw

from analyzer import PacketAnalyzer


@pytest.fixture(autouse=True)
def in_tmp_dir(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    return tmp_path


def tcp_packet(src="192.168.1.10", dst="93.184.216.34", sport=51000, dport=443, payload=b""):
    return IP(src=src, dst=dst) / TCP(sport=sport, dport=dport) / Raw(load=payload)


def udp_packet(src="192.168.1.10", dst="8.8.8.8", sport=51000, dport=53, payload=b""):
    return IP(src=src, dst=dst) / UDP(sport=sport, dport=dport) / Raw(load=payload)


def icmp_packet(src="192.168.1.10", dst="8.8.8.8"):
    return IP(src=src, dst=dst) / ICMP()


def test_non_ip_packet_is_counted_but_not_analyzed():
    from scapy.all import Ether
    analyzer = PacketAnalyzer()
    analyzer.packet_callback(Ether())
    assert analyzer.packet_count == 1
    assert analyzer.protocol_stats == {}
    assert analyzer.packets == []


def test_tcp_packet_updates_stats():
    analyzer = PacketAnalyzer()
    analyzer.packet_callback(tcp_packet(dport=443))

    assert analyzer.packet_count == 1
    assert analyzer.protocol_stats["TCP"] == 1
    assert analyzer.ip_stats["192.168.1.10"] == 1
    assert analyzer.ip_stats["93.184.216.34"] == 1
    assert analyzer.port_stats[443] == 1
    assert len(analyzer.packets) == 1
    assert analyzer.packets[0]["protocol"] == "TCP"
    assert analyzer.packets[0]["dst_port"] == 443


def test_udp_packet_updates_stats():
    analyzer = PacketAnalyzer()
    analyzer.packet_callback(udp_packet(dport=53))
    assert analyzer.protocol_stats["UDP"] == 1
    assert analyzer.port_stats[53] == 1


def test_icmp_packet_has_no_ports():
    analyzer = PacketAnalyzer()
    analyzer.packet_callback(icmp_packet())
    assert analyzer.protocol_stats["ICMP"] == 1
    assert analyzer.packets[0]["src_port"] is None
    assert analyzer.packets[0]["dst_port"] is None
    assert analyzer.port_stats == {}


def test_records_source_mac_for_ip():
    analyzer = PacketAnalyzer()
    pkt = Ether(src="b8:27:eb:11:22:33") / tcp_packet(dport=443)
    analyzer.packet_callback(pkt)
    assert analyzer.ip_mac_map["192.168.1.10"] == "b8:27:eb:11:22:33"


def test_no_mac_recorded_without_ethernet_layer():
    """Packets built without an Ether layer (e.g. some capture backends,
    or synthetic test packets) shouldn't add a bogus entry."""
    analyzer = PacketAnalyzer()
    analyzer.packet_callback(tcp_packet())
    assert analyzer.ip_mac_map == {}


def test_mac_map_only_tracks_source_not_destination():
    """Only the sending device's MAC is reliable on a switched LAN - the
    destination MAC for internet-bound traffic is typically the gateway's,
    not the real destination's, so it's never recorded (see analyzer.py)."""
    analyzer = PacketAnalyzer()
    pkt = Ether(src="b8:27:eb:11:22:33", dst="aa:bb:cc:dd:ee:ff") / tcp_packet(dst="93.184.216.34")
    analyzer.packet_callback(pkt)
    assert "93.184.216.34" not in analyzer.ip_mac_map


def test_mac_map_updates_to_most_recent_sighting():
    analyzer = PacketAnalyzer()
    analyzer.packet_callback(Ether(src="aa:aa:aa:aa:aa:aa") / tcp_packet())
    analyzer.packet_callback(Ether(src="bb:bb:bb:bb:bb:bb") / tcp_packet())
    assert analyzer.ip_mac_map["192.168.1.10"] == "bb:bb:bb:bb:bb:bb"


def test_packet_history_capped_at_1000():
    analyzer = PacketAnalyzer()
    for i in range(1005):
        analyzer.packet_callback(tcp_packet(sport=50000 + i))
    assert len(analyzer.packets) == 1000
    assert analyzer.packet_count == 1005  # counter itself is uncapped


def test_packet_timestamp_uses_packet_capture_time_not_wall_clock():
    """Regression: using datetime.now() instead of the packet's own
    capture time badly distorted rate-based detection during fast .pcap
    replay, since every packet would look nearly simultaneous."""
    from datetime import datetime
    analyzer = PacketAnalyzer()
    pkt = tcp_packet()
    pkt.time = 1700000000.0  # 2023-11-14T22:13:20Z
    analyzer.packet_callback(pkt)

    recorded = datetime.fromisoformat(analyzer.packets[0]["timestamp"])
    expected = datetime.fromtimestamp(1700000000.0)
    assert recorded == expected


def test_http_request_fields_extracted():
    from scapy.layers import http
    pkt = (
        IP(src="192.168.1.10", dst="93.184.216.34")
        / TCP(sport=51000, dport=80)
        / http.HTTPRequest(Method=b"GET", Host=b"example.com", Path=b"/index.html")
    )
    analyzer = PacketAnalyzer()
    analyzer.packet_callback(pkt)

    info = analyzer.packets[0]
    assert info["http_method"] == "GET"
    assert info["http_host"] == "example.com"
    assert info["http_path"] == "/index.html"


def test_export_to_json_writes_expected_fields(tmp_path):
    analyzer = PacketAnalyzer(interface="eth0")
    analyzer.packet_callback(tcp_packet(dport=443))
    analyzer.export_to_json("traffic_analysis.json", hostnames={"192.168.1.10": "laptop.lan"})

    data = json.loads((tmp_path / "traffic_analysis.json").read_text())
    assert data["total_packets"] == 1
    assert data["protocol_stats"]["TCP"] == 1
    assert data["hostnames"] == {"192.168.1.10": "laptop.lan"}
    assert len(data["recent_packets"]) == 1
    # Regression: interface/packets_per_second used to be tracked live
    # (export_live_snapshot) but silently dropped from the persisted report,
    # so completed runs lost both once the capture ended.
    assert data["interface"] == "eth0"
    assert "packets_per_second" in data


def test_export_to_json_writes_mac_info(tmp_path):
    analyzer = PacketAnalyzer()
    analyzer.packet_callback(tcp_packet(dport=443))
    mac_info = {"192.168.1.10": {"mac": "b8:27:eb:11:22:33", "vendor": "Raspberry Pi Foundation"}}
    analyzer.export_to_json("traffic_analysis.json", mac_info=mac_info)

    data = json.loads((tmp_path / "traffic_analysis.json").read_text())
    assert data["mac_info"]["192.168.1.10"]["vendor"] == "Raspberry Pi Foundation"


def test_export_to_json_defaults_mac_info_to_empty_dict(tmp_path):
    analyzer = PacketAnalyzer()
    analyzer.packet_callback(tcp_packet())
    analyzer.export_to_json("traffic_analysis.json")

    data = json.loads((tmp_path / "traffic_analysis.json").read_text())
    assert data["mac_info"] == {}


def test_export_to_json_defaults_interface_when_none_given(tmp_path):
    analyzer = PacketAnalyzer()  # no interface specified
    analyzer.packet_callback(tcp_packet())
    analyzer.export_to_json("traffic_analysis.json")

    data = json.loads((tmp_path / "traffic_analysis.json").read_text())
    assert data["interface"] == "default"


def test_export_to_json_sets_restricted_permissions(tmp_path):
    analyzer = PacketAnalyzer()
    analyzer.packet_callback(tcp_packet())
    analyzer.export_to_json("traffic_analysis.json")
    mode = stat.S_IMODE(os.stat(tmp_path / "traffic_analysis.json").st_mode)
    assert mode == 0o640


def test_export_to_json_rejects_path_escape():
    analyzer = PacketAnalyzer()
    with pytest.raises(ValueError):
        analyzer.export_to_json("/etc/cron.d/malicious")


def test_export_live_snapshot_reflects_current_counters(tmp_path):
    analyzer = PacketAnalyzer(interface="eth0")
    analyzer.packet_callback(tcp_packet(dport=443))
    analyzer.packet_callback(udp_packet(dport=53))
    analyzer.export_live_snapshot("live_status.json")

    data = json.loads((tmp_path / "live_status.json").read_text())
    assert data["status"] == "running"
    assert data["packet_count"] == 2
    assert data["interface"] == "eth0"
    assert data["protocol_stats"]["TCP"] == 1
    assert data["protocol_stats"]["UDP"] == 1
    # No packet history in the lightweight snapshot (unlike export_to_json).
    assert "recent_packets" not in data


def test_export_live_snapshot_sets_restricted_permissions(tmp_path):
    analyzer = PacketAnalyzer()
    analyzer.export_live_snapshot("live_status.json")
    mode = stat.S_IMODE(os.stat(tmp_path / "live_status.json").st_mode)
    assert mode == 0o640


def test_generate_display_table_renders_as_group_not_raw_repr():
    """Regression: this used to interpolate rich Table objects into an
    f-string, so the live dashboard printed "<rich.table.Table object at
    0x...>" instead of an actual table."""
    analyzer = PacketAnalyzer()
    analyzer.packet_callback(tcp_packet(dport=443))

    panel = analyzer.generate_display_table()
    assert isinstance(panel, Panel)
    assert isinstance(panel.renderable, Group)

    from io import StringIO
    from rich.console import Console
    buf = StringIO()
    Console(file=buf, width=100).print(panel)
    rendered = buf.getvalue()
    assert "object at 0x" not in rendered
    assert "Total Packets" in rendered
