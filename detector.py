#!/usr/bin/env python3
"""
Anomaly Detection Module
Detects suspicious network activity patterns
"""

from collections import defaultdict, Counter
from datetime import datetime, timedelta
import json

class AnomalyDetector:
    def __init__(self):
        self.port_scan_threshold = 20  # Connections to different ports from same IP
        self.syn_flood_threshold = 100  # SYN packets per second
        self.connection_rate_threshold = 50  # Connections per second from single IP
        
        self.ip_port_map = defaultdict(set)  # Track ports accessed per IP
        self.ip_connection_times = defaultdict(list)  # Track connection timestamps
        self.syn_packets = defaultdict(int)
        self.alerts = []
        
    def analyze_packet(self, packet_info):
        """Analyze a single packet for suspicious activity"""
        src_ip = packet_info.get('src_ip')
        dst_port = packet_info.get('dst_port')
        timestamp = datetime.fromisoformat(packet_info['timestamp'])
        protocol = packet_info.get('protocol')
        
        alerts = []
        
        # Port Scan Detection
        if dst_port and src_ip:
            self.ip_port_map[src_ip].add(dst_port)
            
            if len(self.ip_port_map[src_ip]) > self.port_scan_threshold:
                alert = {
                    'type': 'PORT_SCAN',
                    'severity': 'HIGH',
                    'timestamp': timestamp.isoformat(),
                    'source_ip': src_ip,
                    'description': f'Possible port scan detected from {src_ip}',
                    'details': f'Accessed {len(self.ip_port_map[src_ip])} different ports'
                }
                alerts.append(alert)
                self.alerts.append(alert)
        
        # Connection Rate Detection
        if src_ip:
            self.ip_connection_times[src_ip].append(timestamp)
            
            # Clean old timestamps (older than 1 second)
            cutoff_time = timestamp - timedelta(seconds=1)
            self.ip_connection_times[src_ip] = [
                t for t in self.ip_connection_times[src_ip] if t > cutoff_time
            ]
            
            conn_rate = len(self.ip_connection_times[src_ip])
            if conn_rate > self.connection_rate_threshold:
                alert = {
                    'type': 'HIGH_CONNECTION_RATE',
                    'severity': 'MEDIUM',
                    'timestamp': timestamp.isoformat(),
                    'source_ip': src_ip,
                    'description': f'High connection rate from {src_ip}',
                    'details': f'{conn_rate} connections per second'
                }
                alerts.append(alert)
                self.alerts.append(alert)
        
        # Suspicious Ports Detection
        suspicious_ports = {
            1433: 'MSSQL',
            3389: 'RDP',
            23: 'Telnet',
            135: 'RPC',
            137: 'NetBIOS',
            138: 'NetBIOS',
            139: 'NetBIOS',
            445: 'SMB',
            5900: 'VNC'
        }
        
        if dst_port in suspicious_ports:
            alert = {
                'type': 'SUSPICIOUS_PORT',
                'severity': 'MEDIUM',
                'timestamp': timestamp.isoformat(),
                'source_ip': src_ip,
                'destination_port': dst_port,
                'description': f'Access to potentially vulnerable service ({suspicious_ports[dst_port]})',
                'details': f'Connection to port {dst_port} ({suspicious_ports[dst_port]})'
            }
            alerts.append(alert)
        
        # Large Packet Detection (potential data exfiltration)
        if packet_info.get('size', 0) > 1400:  # Close to MTU size
            if protocol == 'UDP':
                alert = {
                    'type': 'LARGE_PACKET',
                    'severity': 'LOW',
                    'timestamp': timestamp.isoformat(),
                    'source_ip': src_ip,
                    'description': 'Large UDP packet detected',
                    'details': f'Packet size: {packet_info["size"]} bytes'
                }
                alerts.append(alert)
        
        return alerts
    
    def analyze_traffic_patterns(self, packets):
        """Analyze overall traffic patterns for anomalies"""
        if not packets:
            return []
        
        alerts = []
        
        # Protocol distribution analysis
        protocol_counts = Counter(p.get('protocol') for p in packets)
        total_packets = len(packets)
        
        # Detect unusual protocol ratios
        if protocol_counts.get('ICMP', 0) / total_packets > 0.3:
            alerts.append({
                'type': 'UNUSUAL_PROTOCOL_RATIO',
                'severity': 'MEDIUM',
                'timestamp': datetime.now().isoformat(),
                'description': 'Unusually high ICMP traffic',
                'details': f'ICMP packets: {protocol_counts["ICMP"]/total_packets*100:.1f}% of total traffic'
            })
        
        # Detect traffic to/from private IPs going external
        for packet in packets[-50:]:  # Check recent packets
            src_ip = packet.get('src_ip', '')
            dst_ip = packet.get('dst_ip', '')
            
            # Check for RFC1918 private IP communicating with public IP
            if self._is_private_ip(src_ip) and not self._is_private_ip(dst_ip):
                if dst_ip not in ['8.8.8.8', '8.8.4.4', '1.1.1.1']:  # Ignore DNS
                    alerts.append({
                        'type': 'PRIVATE_TO_PUBLIC',
                        'severity': 'LOW',
                        'timestamp': packet['timestamp'],
                        'source_ip': src_ip,
                        'destination_ip': dst_ip,
                        'description': 'Private IP communicating with public IP',
                        'details': f'{src_ip} -> {dst_ip}'
                    })
        
        return alerts
    
    def _is_private_ip(self, ip):
        """Check if IP is in private range"""
        if not ip:
            return False
        
        parts = ip.split('.')
        if len(parts) != 4:
            return False
        
        try:
            first_octet = int(parts[0])
            second_octet = int(parts[1])
            
            # Check private ranges
            if first_octet == 10:
                return True
            if first_octet == 172 and 16 <= second_octet <= 31:
                return True
            if first_octet == 192 and second_octet == 168:
                return True
            
            return False
        except ValueError:
            return False
    
    def get_alert_summary(self):
        """Get summary of all alerts"""
        if not self.alerts:
            return "No suspicious activity detected"
        
        alert_counts = Counter(a['type'] for a in self.alerts)
        severity_counts = Counter(a['severity'] for a in self.alerts)
        
        summary = {
            'total_alerts': len(self.alerts),
            'by_type': dict(alert_counts),
            'by_severity': dict(severity_counts),
            'recent_alerts': self.alerts[-10:]
        }
        
        return summary
    
    def export_alerts(self, filename='security_alerts.json'):
        """Export alerts to JSON file"""
        if '..' in filename:
            raise Exception('Invalid file path')
        with open(filename, 'w') as f:
            json.dump({
                'generated_at': datetime.now().isoformat(),
                'total_alerts': len(self.alerts),
                'alerts': self.alerts
            }, f, indent=2)
        
        return filename


if __name__ == "__main__":
    # Example usage
    detector = AnomalyDetector()
    
    # Simulate some packet data
    test_packets = [
        {
            'timestamp': datetime.now().isoformat(),
            'src_ip': '192.168.1.100',
            'dst_ip': '8.8.8.8',
            'protocol': 'TCP',
            'dst_port': 53,
            'size': 60
        }
    ]
    
    for packet in test_packets:
        alerts = detector.analyze_packet(packet)
        for alert in alerts:
            print(f"[{alert['severity']}] {alert['description']}")
