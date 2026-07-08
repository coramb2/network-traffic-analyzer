import json
import os
import stat

import pytest

from reporter import TrafficReporter


@pytest.fixture(autouse=True)
def in_tmp_dir(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    return tmp_path


SAMPLE_ANALYZER_DATA = {
    "duration_seconds": 60,
    "total_packets": 150,
    "protocol_stats": {"TCP": 100, "UDP": 40, "ICMP": 10},
    "top_ips": {"192.168.1.1": 90, "192.168.1.2": 60},
    "top_ports": {"443": 80, "80": 40, "53": 30},
    "recent_packets": [
        {
            "timestamp": "2026-01-01T00:00:00",
            "src_ip": "192.168.1.1",
            "dst_ip": "1.1.1.1",
            "protocol": "TCP",
            "src_port": 51000,
            "dst_port": 443,
            "size": 128,
        }
    ],
}

SAMPLE_DETECTOR_DATA = {
    "total_alerts": 2,
    "alerts": [
        {"type": "PORT_SCAN", "severity": "HIGH", "description": "Possible port scan detected from 9.9.9.9"},
        {"type": "SUSPICIOUS_PORT", "severity": "MEDIUM", "description": "Access to potentially vulnerable service (RDP)"},
    ],
}


def test_generate_summary_report_includes_key_stats():
    reporter = TrafficReporter(SAMPLE_ANALYZER_DATA, SAMPLE_DETECTOR_DATA)
    summary = reporter.generate_summary_report()

    assert "150" in summary  # total packets
    assert "TCP" in summary
    assert "192.168.1.1" in summary
    assert "Total Alerts: 2" in summary
    assert "PORT_SCAN" in summary


def test_generate_summary_report_without_detector_data():
    reporter = TrafficReporter(SAMPLE_ANALYZER_DATA)
    summary = reporter.generate_summary_report()
    assert "SECURITY ALERTS" not in summary


def test_export_to_csv_writes_expected_rows(tmp_path):
    reporter = TrafficReporter(SAMPLE_ANALYZER_DATA)
    filename = reporter.export_to_csv("traffic_data.csv")

    content = (tmp_path / filename).read_text()
    assert "src_ip" in content.splitlines()[0]
    assert "192.168.1.1" in content


def test_export_to_csv_returns_none_when_no_packets():
    reporter = TrafficReporter({**SAMPLE_ANALYZER_DATA, "recent_packets": []})
    assert reporter.export_to_csv("traffic_data.csv") is None


def test_export_to_csv_sets_restricted_permissions(tmp_path):
    reporter = TrafficReporter(SAMPLE_ANALYZER_DATA)
    filename = reporter.export_to_csv("traffic_data.csv")
    mode = stat.S_IMODE(os.stat(tmp_path / filename).st_mode)
    assert mode == 0o640


def test_export_to_csv_rejects_path_escape():
    reporter = TrafficReporter(SAMPLE_ANALYZER_DATA)
    with pytest.raises(ValueError):
        reporter.export_to_csv("/etc/cron.d/malicious")


def test_export_to_json_round_trips(tmp_path):
    reporter = TrafficReporter(SAMPLE_ANALYZER_DATA, SAMPLE_DETECTOR_DATA)
    filename = reporter.export_to_json("full_report.json")

    data = json.loads((tmp_path / filename).read_text())
    assert data["traffic_analysis"]["total_packets"] == 150
    assert data["security_analysis"]["total_alerts"] == 2
    assert data["metadata"]["report_version"] == "1.0"


def test_generate_html_report_contains_stats_and_alerts(tmp_path):
    reporter = TrafficReporter(SAMPLE_ANALYZER_DATA, SAMPLE_DETECTOR_DATA)
    filename = reporter.generate_html_report("traffic_report.html")

    html = (tmp_path / filename).read_text()
    assert "<!DOCTYPE html>" in html
    assert "192.168.1.1" in html
    assert "Possible port scan detected from 9.9.9.9" in html
    # Chart.js is loaded with a pinned integrity hash, not bare from a CDN.
    assert 'integrity="sha384-' in html


def test_generate_html_report_omits_alerts_section_when_no_alerts(tmp_path):
    reporter = TrafficReporter(SAMPLE_ANALYZER_DATA, {"total_alerts": 0, "alerts": []})
    filename = reporter.generate_html_report("traffic_report.html")
    html = (tmp_path / filename).read_text()
    assert "Security Alerts" not in html


def test_generate_html_report_rejects_path_escape():
    reporter = TrafficReporter(SAMPLE_ANALYZER_DATA)
    with pytest.raises(ValueError):
        reporter.generate_html_report("../escape.html")
