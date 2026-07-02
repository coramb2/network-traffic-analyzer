#!/usr/bin/env python3
"""
Report Generation Module
Creates comprehensive traffic analysis reports
"""

import json
import csv
from datetime import datetime
from collections import Counter
import os

from paths import safe_output_path

class TrafficReporter:
    def __init__(self, analyzer_data, detector_data=None):
        """
        Initialize reporter with analyzer and detector data
        
        Args:
            analyzer_data: Dictionary containing packet analysis data
            detector_data: Dictionary containing security alerts (optional)
        """
        self.analyzer_data = analyzer_data
        self.detector_data = detector_data or {}
        
    def generate_summary_report(self):
        """Generate a text summary report"""
        report_lines = []
        report_lines.append("=" * 70)
        report_lines.append("NETWORK TRAFFIC ANALYSIS REPORT")
        report_lines.append("=" * 70)
        report_lines.append(f"\nGenerated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report_lines.append(f"Analysis Period: {self.analyzer_data.get('duration_seconds', 0)} seconds")
        report_lines.append(f"Total Packets Captured: {self.analyzer_data.get('total_packets', 0)}")
        
        # Protocol Statistics
        report_lines.append("\n" + "-" * 70)
        report_lines.append("PROTOCOL DISTRIBUTION")
        report_lines.append("-" * 70)
        
        protocol_stats = self.analyzer_data.get('protocol_stats', {})
        total = sum(protocol_stats.values())
        
        for protocol, count in sorted(protocol_stats.items(), key=lambda x: x[1], reverse=True):
            percentage = (count / total * 100) if total > 0 else 0
            report_lines.append(f"{protocol:15} {count:8} packets ({percentage:5.1f}%)")
        
        # Top IP Addresses
        report_lines.append("\n" + "-" * 70)
        report_lines.append("TOP 10 MOST ACTIVE IP ADDRESSES")
        report_lines.append("-" * 70)
        
        top_ips = self.analyzer_data.get('top_ips', {})
        for i, (ip, count) in enumerate(sorted(top_ips.items(), key=lambda x: x[1], reverse=True)[:10], 1):
            report_lines.append(f"{i:2}. {ip:20} {count:8} packets")
        
        # Top Ports
        report_lines.append("\n" + "-" * 70)
        report_lines.append("TOP 10 DESTINATION PORTS")
        report_lines.append("-" * 70)
        
        port_names = {
            80: "HTTP", 443: "HTTPS", 22: "SSH", 21: "FTP",
            25: "SMTP", 53: "DNS", 3389: "RDP", 3306: "MySQL"
        }
        
        top_ports = self.analyzer_data.get('top_ports', {})
        for i, (port, count) in enumerate(sorted(top_ports.items(), key=lambda x: int(x[1]), reverse=True)[:10], 1):
            service = port_names.get(int(port), "Unknown")
            report_lines.append(f"{i:2}. Port {port:5} ({service:15}) {count:8} packets")
        
        # Security Alerts
        if self.detector_data:
            report_lines.append("\n" + "-" * 70)
            report_lines.append("SECURITY ALERTS")
            report_lines.append("-" * 70)
            
            total_alerts = self.detector_data.get('total_alerts', 0)
            report_lines.append(f"Total Alerts: {total_alerts}")
            
            if total_alerts > 0:
                alerts = self.detector_data.get('alerts', [])
                severity_count = Counter(a['severity'] for a in alerts)
                
                report_lines.append(f"\nBy Severity:")
                for severity in ['HIGH', 'MEDIUM', 'LOW']:
                    count = severity_count.get(severity, 0)
                    if count > 0:
                        report_lines.append(f"  {severity:10} {count:5} alerts")
                
                alert_types = Counter(a['type'] for a in alerts)
                report_lines.append(f"\nBy Type:")
                for alert_type, count in alert_types.most_common():
                    report_lines.append(f"  {alert_type:30} {count:5} alerts")
                
                # Recent alerts
                recent = alerts[-5:]
                if recent:
                    report_lines.append(f"\nRecent Alerts (last 5):")
                    for alert in recent:
                        report_lines.append(f"  [{alert['severity']}] {alert['description']}")
        
        report_lines.append("\n" + "=" * 70)
        
        return "\n".join(report_lines)
    
    def export_to_csv(self, filename='traffic_data.csv'):
        """Export packet data to CSV format"""
        packets = self.analyzer_data.get('recent_packets', [])
        
        if not packets:
            return None
        
        fieldnames = ['timestamp', 'src_ip', 'dst_ip', 'protocol', 'src_port', 'dst_port', 'size']

        resolved_path = safe_output_path(filename)
        with open(resolved_path, 'w', newline='') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames, extrasaction='ignore')
            writer.writeheader()

            for packet in packets:
                writer.writerow(packet)
        os.chmod(resolved_path, 0o600)

        return filename

    def export_to_json(self, filename='full_report.json'):
        """Export complete analysis to JSON"""
        full_report = {
            'metadata': {
                'generated_at': datetime.now().isoformat(),
                'report_version': '1.0'
            },
            'traffic_analysis': self.analyzer_data,
            'security_analysis': self.detector_data
        }

        resolved_path = safe_output_path(filename)
        with open(resolved_path, 'w') as f:
            json.dump(full_report, f, indent=2)
        os.chmod(resolved_path, 0o600)

        return filename
    
    def generate_html_report(self, filename='report.html'):
        """Generate an HTML report with visualizations"""
        
        protocol_stats = self.analyzer_data.get('protocol_stats', {})
        protocol_labels = list(protocol_stats.keys())
        protocol_values = list(protocol_stats.values())
        
        html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Network Traffic Analysis Report</title>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/3.9.1/chart.min.js"></script>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background-color: white;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }}
        h1 {{
            color: #2c3e50;
            border-bottom: 3px solid #3498db;
            padding-bottom: 10px;
        }}
        h2 {{
            color: #34495e;
            margin-top: 30px;
        }}
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin: 20px 0;
        }}
        .stat-card {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 20px;
            border-radius: 8px;
            text-align: center;
        }}
        .stat-card h3 {{
            margin: 0;
            font-size: 14px;
            opacity: 0.9;
        }}
        .stat-card p {{
            margin: 10px 0 0 0;
            font-size: 32px;
            font-weight: bold;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }}
        th, td {{
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }}
        th {{
            background-color: #3498db;
            color: white;
        }}
        tr:hover {{
            background-color: #f5f5f5;
        }}
        .chart-container {{
            margin: 30px 0;
            padding: 20px;
            background-color: #f8f9fa;
            border-radius: 8px;
        }}
        .alert {{
            padding: 15px;
            margin: 10px 0;
            border-radius: 4px;
            border-left: 4px solid;
        }}
        .alert-high {{
            background-color: #fee;
            border-color: #e74c3c;
        }}
        .alert-medium {{
            background-color: #fef5e7;
            border-color: #f39c12;
        }}
        .alert-low {{
            background-color: #eef;
            border-color: #3498db;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🔍 Network Traffic Analysis Report</h1>
        <p><strong>Generated:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        
        <div class="stats-grid">
            <div class="stat-card">
                <h3>Total Packets</h3>
                <p>{self.analyzer_data.get('total_packets', 0)}</p>
            </div>
            <div class="stat-card">
                <h3>Duration</h3>
                <p>{self.analyzer_data.get('duration_seconds', 0)}s</p>
            </div>
            <div class="stat-card">
                <h3>Protocols</h3>
                <p>{len(protocol_stats)}</p>
            </div>
            <div class="stat-card">
                <h3>Unique IPs</h3>
                <p>{len(self.analyzer_data.get('top_ips', {}))}</p>
            </div>
        </div>
        
        <h2>Protocol Distribution</h2>
        <div class="chart-container">
            <canvas id="protocolChart"></canvas>
        </div>
        
        <h2>Top IP Addresses</h2>
        <table>
            <thead>
                <tr>
                    <th>Rank</th>
                    <th>IP Address</th>
                    <th>Packet Count</th>
                </tr>
            </thead>
            <tbody>
"""
        
        top_ips = self.analyzer_data.get('top_ips', {})
        for i, (ip, count) in enumerate(sorted(top_ips.items(), key=lambda x: x[1], reverse=True)[:10], 1):
            html_content += f"""
                <tr>
                    <td>{i}</td>
                    <td>{ip}</td>
                    <td>{count}</td>
                </tr>
"""
        
        html_content += """
            </tbody>
        </table>
"""
        
        # Add security alerts if available
        if self.detector_data and self.detector_data.get('total_alerts', 0) > 0:
            html_content += """
        <h2>🚨 Security Alerts</h2>
"""
            alerts = self.detector_data.get('alerts', [])[:10]
            for alert in alerts:
                severity_class = f"alert-{alert['severity'].lower()}"
                html_content += f"""
        <div class="alert {severity_class}">
            <strong>[{alert['severity']}]</strong> {alert['description']}<br>
            <small>{alert.get('details', '')}</small>
        </div>
"""
        
        html_content += f"""
    </div>
    
    <script>
        const ctx = document.getElementById('protocolChart').getContext('2d');
        new Chart(ctx, {{
            type: 'doughnut',
            data: {{
                labels: {json.dumps(protocol_labels)},
                datasets: [{{
                    data: {json.dumps(protocol_values)},
                    backgroundColor: [
                        '#3498db', '#e74c3c', '#2ecc71', '#f39c12', 
                        '#9b59b6', '#1abc9c', '#34495e'
                    ]
                }}]
            }},
            options: {{
                responsive: true,
                plugins: {{
                    legend: {{
                        position: 'right'
                    }},
                    title: {{
                        display: true,
                        text: 'Traffic by Protocol'
                    }}
                }}
            }}
        }});
    </script>
</body>
</html>
"""
        
        resolved_path = safe_output_path(filename)
        with open(resolved_path, 'w') as f:
            f.write(html_content)
        os.chmod(resolved_path, 0o600)

        return filename


if __name__ == "__main__":
    # Example usage
    sample_data = {
        'total_packets': 1500,
        'duration_seconds': 60,
        'protocol_stats': {'TCP': 1000, 'UDP': 400, 'ICMP': 100},
        'top_ips': {'192.168.1.1': 500, '192.168.1.2': 300},
        'top_ports': {'80': 400, '443': 350, '53': 150}
    }
    
    reporter = TrafficReporter(sample_data)
    print(reporter.generate_summary_report())
