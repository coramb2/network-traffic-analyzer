import os
import stat
from datetime import datetime, timedelta

import pytest

from detector import AnomalyDetector


@pytest.fixture(autouse=True)
def isolated_state(tmp_path, monkeypatch):
    """Every detector loads its allowlist from ALERT_STATE_PATH on init -
    point it somewhere empty/per-test so tests don't see each other's state."""
    monkeypatch.setenv("ALERT_STATE_PATH", str(tmp_path / "alert_state.json"))
    monkeypatch.chdir(tmp_path)


def make_packet(src_ip="1.2.3.4", dst_ip="5.6.7.8", protocol="TCP", dst_port=443, size=100, ts=None):
    return {
        "timestamp": (ts or datetime.now()).isoformat(),
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "protocol": protocol,
        "src_port": 54321,
        "dst_port": dst_port,
        "size": size,
    }


def test_no_alerts_for_ordinary_traffic():
    detector = AnomalyDetector()
    alerts = detector.analyze_packet(make_packet(dst_port=443, protocol="TCP"))
    assert alerts == []
    assert detector.alerts == []


def test_port_scan_detected_above_threshold():
    detector = AnomalyDetector()
    alerts = []
    for port in range(1, 25):  # threshold is 20 distinct ports
        alerts = detector.analyze_packet(make_packet(src_ip="9.9.9.9", dst_port=port))

    types = [a["type"] for a in detector.alerts]
    assert "PORT_SCAN" in types


def test_port_scan_not_flagged_below_threshold():
    detector = AnomalyDetector()
    for port in range(1, 10):
        detector.analyze_packet(make_packet(src_ip="9.9.9.9", dst_port=port))
    assert detector.alerts == []


def test_high_connection_rate_detected():
    detector = AnomalyDetector()
    now = datetime.now()
    for i in range(60):  # threshold is 50/second
        detector.analyze_packet(make_packet(src_ip="9.9.9.9", dst_port=443, ts=now))

    types = [a["type"] for a in detector.alerts]
    assert "HIGH_CONNECTION_RATE" in types


def test_connection_rate_resets_outside_one_second_window():
    detector = AnomalyDetector()
    now = datetime.now()
    # A burst 5 seconds in the past - may itself trip the alert, that's not
    # what's under test here.
    for i in range(60):
        old_ts = now - timedelta(seconds=5) + timedelta(milliseconds=i)
        detector.analyze_packet(make_packet(src_ip="9.9.9.9", dst_port=443, ts=old_ts))
    # A single fresh packet should see a clean 1-second window - the old
    # burst is well outside it - not the accumulated 60 from that burst.
    fresh_alerts = detector.analyze_packet(make_packet(src_ip="9.9.9.9", dst_port=443, ts=now))
    assert not any(a["type"] == "HIGH_CONNECTION_RATE" for a in fresh_alerts)


@pytest.mark.parametrize("port", [1433, 3389, 23, 135, 137, 138, 139, 445, 5900])
def test_suspicious_port_access_is_recorded(port):
    """Regression test: SUSPICIOUS_PORT alerts were computed but never
    appended to self.alerts in an earlier version of this code, so they
    silently never reached security_alerts.json or the dashboard."""
    detector = AnomalyDetector()
    detector.analyze_packet(make_packet(dst_port=port))
    assert any(a["type"] == "SUSPICIOUS_PORT" and a["destination_port"] == port for a in detector.alerts)


def test_ordinary_port_is_not_suspicious():
    detector = AnomalyDetector()
    detector.analyze_packet(make_packet(dst_port=443))
    assert not any(a["type"] == "SUSPICIOUS_PORT" for a in detector.alerts)


def test_large_udp_packet_is_recorded():
    """Regression test: same missing-self.alerts.append bug as SUSPICIOUS_PORT."""
    detector = AnomalyDetector()
    detector.analyze_packet(make_packet(protocol="UDP", size=1401))
    assert any(a["type"] == "LARGE_PACKET" for a in detector.alerts)


def test_large_tcp_packet_is_not_flagged():
    """LARGE_PACKET is specifically about UDP (exfil/amplification concern)."""
    detector = AnomalyDetector()
    detector.analyze_packet(make_packet(protocol="TCP", size=1401))
    assert not any(a["type"] == "LARGE_PACKET" for a in detector.alerts)


def test_small_udp_packet_is_not_flagged():
    detector = AnomalyDetector()
    detector.analyze_packet(make_packet(protocol="UDP", size=500))
    assert not any(a["type"] == "LARGE_PACKET" for a in detector.alerts)


def test_allowlisted_alert_is_suppressed(monkeypatch, tmp_path):
    import alert_rules
    alert_rules.add_rule(alert_type="SUSPICIOUS_PORT", destination_port=3389)

    detector = AnomalyDetector()
    alerts = detector.analyze_packet(make_packet(dst_port=3389))

    assert alerts == []
    assert detector.alerts == []


def test_allowlist_is_scoped_to_matching_rule_only():
    import alert_rules
    alert_rules.add_rule(alert_type="SUSPICIOUS_PORT", destination_port=445)  # different port

    detector = AnomalyDetector()
    detector.analyze_packet(make_packet(dst_port=3389))  # not allowlisted

    assert any(a["type"] == "SUSPICIOUS_PORT" for a in detector.alerts)


def test_max_tracked_ips_evicts_oldest():
    detector = AnomalyDetector(max_tracked_ips=2)
    detector.analyze_packet(make_packet(src_ip="1.1.1.1", dst_port=1))
    detector.analyze_packet(make_packet(src_ip="2.2.2.2", dst_port=1))
    detector.analyze_packet(make_packet(src_ip="3.3.3.3", dst_port=1))

    assert len(detector.ip_port_map) <= 2
    assert "1.1.1.1" not in detector.ip_port_map  # oldest, evicted first
    assert "3.3.3.3" in detector.ip_port_map


@pytest.mark.parametrize("ip,expected", [
    ("10.0.0.1", True),
    ("10.255.255.255", True),
    ("172.16.0.1", True),
    ("172.31.255.255", True),
    ("172.15.0.1", False),
    ("172.32.0.1", False),
    ("192.168.0.1", True),
    ("192.169.0.1", False),
    ("8.8.8.8", False),
    ("", False),
    ("not-an-ip", False),
    ("1.2.3", False),
])
def test_is_private_ip(ip, expected):
    detector = AnomalyDetector()
    assert detector._is_private_ip(ip) is expected


def test_unusual_protocol_ratio_detected_above_30_percent():
    detector = AnomalyDetector()
    packets = [make_packet(protocol="ICMP") for _ in range(4)] + [make_packet(protocol="TCP") for _ in range(6)]
    alerts = detector.analyze_traffic_patterns(packets)
    assert any(a["type"] == "UNUSUAL_PROTOCOL_RATIO" for a in alerts)


def test_unusual_protocol_ratio_not_flagged_below_30_percent():
    detector = AnomalyDetector()
    packets = [make_packet(protocol="ICMP") for _ in range(2)] + [make_packet(protocol="TCP") for _ in range(8)]
    alerts = detector.analyze_traffic_patterns(packets)
    assert not any(a["type"] == "UNUSUAL_PROTOCOL_RATIO" for a in alerts)


def test_private_to_public_detected():
    detector = AnomalyDetector()
    packets = [make_packet(src_ip="192.168.1.50", dst_ip="93.184.216.34")]
    alerts = detector.analyze_traffic_patterns(packets)
    assert any(a["type"] == "PRIVATE_TO_PUBLIC" for a in alerts)


def test_private_to_public_ignores_common_dns_resolvers():
    detector = AnomalyDetector()
    packets = [make_packet(src_ip="192.168.1.50", dst_ip="8.8.8.8")]
    alerts = detector.analyze_traffic_patterns(packets)
    assert not any(a["type"] == "PRIVATE_TO_PUBLIC" for a in alerts)


def test_private_to_private_not_flagged():
    detector = AnomalyDetector()
    packets = [make_packet(src_ip="192.168.1.50", dst_ip="192.168.1.1")]
    alerts = detector.analyze_traffic_patterns(packets)
    assert not any(a["type"] == "PRIVATE_TO_PUBLIC" for a in alerts)


def test_analyze_traffic_patterns_empty_input():
    detector = AnomalyDetector()
    assert detector.analyze_traffic_patterns([]) == []


def test_get_alert_summary_no_alerts():
    detector = AnomalyDetector()
    assert detector.get_alert_summary() == "No suspicious activity detected"


def test_get_alert_summary_with_alerts():
    detector = AnomalyDetector()
    detector.analyze_packet(make_packet(dst_port=3389))
    detector.analyze_packet(make_packet(dst_port=445))

    summary = detector.get_alert_summary()
    assert summary["total_alerts"] == 2
    assert summary["by_type"]["SUSPICIOUS_PORT"] == 2
    assert summary["by_severity"]["MEDIUM"] == 2


def test_export_alerts_writes_json_with_restricted_permissions(tmp_path):
    detector = AnomalyDetector()
    detector.analyze_packet(make_packet(dst_port=3389))

    filename = detector.export_alerts("security_alerts.json")
    written = tmp_path / filename
    assert written.exists()

    mode = stat.S_IMODE(os.stat(written).st_mode)
    assert mode == 0o640

    import json
    data = json.loads(written.read_text())
    assert data["total_alerts"] == 1
    assert data["alerts"][0]["type"] == "SUSPICIOUS_PORT"


def test_export_alerts_rejects_path_escape(tmp_path):
    detector = AnomalyDetector()
    with pytest.raises(ValueError):
        detector.export_alerts("/etc/cron.d/malicious")
