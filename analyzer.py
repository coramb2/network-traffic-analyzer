#!/usr/bin/env python3
"""
Network Traffic Analyzer - Main Packet Capture Module
Captures and analyzes network packets in real-time
"""

from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw
from scapy.layers import http
from scapy.utils import PcapWriter
from collections import defaultdict
from datetime import datetime
import json
import os
from rich.console import Console, Group
from rich.table import Table
from rich.live import Live
from rich.layout import Layout
from rich.panel import Panel
import threading
import time

from paths import safe_output_path

console = Console()

class PacketAnalyzer:
    def __init__(self, interface=None):
        self.interface = interface
        self.packet_count = 0
        self.protocol_stats = defaultdict(int)
        self.ip_stats = defaultdict(int)
        self.port_stats = defaultdict(int)
        self.packets = []
        self.start_time = datetime.now()
        self.suspicious_activity = []
        self.pcap_writer = None

    def packet_callback(self, packet):
        """Process each captured packet"""
        self.packet_count += 1

        # Written regardless of protocol, so the .pcap is a faithful replay
        # source even for packets analysis doesn't otherwise track (non-IP).
        if self.pcap_writer is not None:
            self.pcap_writer.write(packet)

        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            
            # Track IP addresses
            self.ip_stats[src_ip] += 1
            self.ip_stats[dst_ip] += 1
            
            # Determine protocol
            protocol = "OTHER"
            src_port = dst_port = None
            
            if TCP in packet:
                protocol = "TCP"
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
                self.port_stats[dst_port] += 1
                
            elif UDP in packet:
                protocol = "UDP"
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport
                self.port_stats[dst_port] += 1
                
            elif ICMP in packet:
                protocol = "ICMP"
            
            self.protocol_stats[protocol] += 1
            
            # Store packet info. Use the packet's own capture timestamp
            # (scapy sets this for both live and offline/.pcap-replay
            # captures) rather than datetime.now() - otherwise a fast
            # offline replay stamps every packet with nearly the same
            # wall-clock time, badly distorting rate-based detection
            # (PORT_SCAN, HIGH_CONNECTION_RATE) which depends on real gaps
            # between packets.
            packet_info = {
                'timestamp': datetime.fromtimestamp(float(packet.time)).isoformat(),
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'protocol': protocol,
                'src_port': src_port,
                'dst_port': dst_port,
                'size': len(packet)
            }
            
            # Check for HTTP traffic
            if packet.haslayer(http.HTTPRequest):
                packet_info['http_method'] = packet[http.HTTPRequest].Method.decode()
                packet_info['http_host'] = packet[http.HTTPRequest].Host.decode()
                packet_info['http_path'] = packet[http.HTTPRequest].Path.decode()
            
            self.packets.append(packet_info)
            
            # Keep only last 1000 packets in memory
            if len(self.packets) > 1000:
                self.packets.pop(0)
    
    def generate_display_table(self):
        """Generate a rich table for live display"""
        layout = Layout()
        
        # Stats table
        stats_table = Table(title="Traffic Statistics", show_header=True)
        stats_table.add_column("Metric", style="cyan")
        stats_table.add_column("Value", style="green")
        
        runtime = (datetime.now() - self.start_time).seconds
        stats_table.add_row("Total Packets", str(self.packet_count))
        stats_table.add_row("Runtime", f"{runtime}s")
        stats_table.add_row("Packets/sec", f"{self.packet_count/max(runtime, 1):.2f}")
        
        # Protocol distribution
        protocol_table = Table(title="Protocol Distribution", show_header=True)
        protocol_table.add_column("Protocol", style="cyan")
        protocol_table.add_column("Count", style="green")
        protocol_table.add_column("Percentage", style="yellow")
        
        for protocol, count in sorted(self.protocol_stats.items(), key=lambda x: x[1], reverse=True):
            percentage = (count / self.packet_count * 100) if self.packet_count > 0 else 0
            protocol_table.add_row(protocol, str(count), f"{percentage:.1f}%")
        
        # Top IPs
        top_ips_table = Table(title="Top 10 IP Addresses", show_header=True)
        top_ips_table.add_column("IP Address", style="cyan")
        top_ips_table.add_column("Packet Count", style="green")
        
        top_ips = sorted(self.ip_stats.items(), key=lambda x: x[1], reverse=True)[:10]
        for ip, count in top_ips:
            top_ips_table.add_row(ip, str(count))
        
        # Top Ports
        top_ports_table = Table(title="Top 10 Destination Ports", show_header=True)
        top_ports_table.add_column("Port", style="cyan")
        top_ports_table.add_column("Service", style="magenta")
        top_ports_table.add_column("Count", style="green")
        
        common_ports = {
            80: "HTTP", 443: "HTTPS", 22: "SSH", 21: "FTP",
            25: "SMTP", 53: "DNS", 3389: "RDP", 3306: "MySQL",
            5432: "PostgreSQL", 27017: "MongoDB", 6379: "Redis"
        }
        
        top_ports = sorted(self.port_stats.items(), key=lambda x: x[1], reverse=True)[:10]
        for port, count in top_ports:
            service = common_ports.get(port, "Unknown")
            top_ports_table.add_row(str(port), service, str(count))
        
        return Panel.fit(
            Group(stats_table, protocol_table, top_ips_table, top_ports_table),
            title="[bold cyan]Network Traffic Analyzer[/bold cyan]",
            border_style="blue"
        )
    
    def export_to_json(self, filename="traffic_analysis.json"):
        """Export analysis results to JSON"""
        output = {
            'analysis_time': datetime.now().isoformat(),
            'duration_seconds': (datetime.now() - self.start_time).seconds,
            'total_packets': self.packet_count,
            'protocol_stats': dict(self.protocol_stats),
            'top_ips': dict(sorted(self.ip_stats.items(), key=lambda x: x[1], reverse=True)[:20]),
            'top_ports': dict(sorted(self.port_stats.items(), key=lambda x: x[1], reverse=True)[:20]),
            'recent_packets': self.packets[-100:]  # Last 100 packets
        }
        
        resolved_path = safe_output_path(filename)

        with open(resolved_path, 'w') as f:
            json.dump(output, f, indent=2)
        # Group-readable, not just owner: the dashboard container reads these
        # reports as a different uid, but shares gid 0 with the capture
        # container's user by design (see Dockerfile / Dockerfile.dashboard).
        os.chmod(resolved_path, 0o640)

        console.print(f"\n[green]✓[/green] Analysis exported to {filename}")

    def export_live_snapshot(self, filename='live_status.json'):
        """Write a lightweight snapshot of in-progress stats for a dashboard to poll.

        Cheaper than export_to_json: no packet history, just the running
        counters, so it's safe to call every second or so during capture.
        """
        runtime = (datetime.now() - self.start_time).seconds
        snapshot = {
            'status': 'running',
            'updated_at': datetime.now().isoformat(),
            'capture_start': self.start_time.isoformat(),
            'interface': self.interface or 'default',
            'runtime_seconds': runtime,
            'packet_count': self.packet_count,
            'packets_per_second': round(self.packet_count / max(runtime, 1), 2),
            'protocol_stats': dict(self.protocol_stats),
            'top_ips': sorted(self.ip_stats.items(), key=lambda x: x[1], reverse=True)[:10],
            'top_ports': sorted(self.port_stats.items(), key=lambda x: x[1], reverse=True)[:10],
        }

        resolved_path = safe_output_path(filename)
        with open(resolved_path, 'w') as f:
            json.dump(snapshot, f, indent=2)
        os.chmod(resolved_path, 0o640)

    def start_capture(self, packet_count=0, timeout=None, filter_str=None, pcap_out=None, read_pcap=None):
        """Start capturing packets, or replay them from an existing .pcap file
        (read_pcap) instead of a live interface - useful for offline analysis
        of a capture taken elsewhere, or for testing without root/capabilities."""
        console.print(f"[bold cyan]Starting packet capture...[/bold cyan]")
        if read_pcap:
            console.print(f"Reading from: {read_pcap}")
        else:
            console.print(f"Interface: {self.interface or 'default'}")
        console.print(f"Filter: {filter_str or 'none'}")
        console.print("[yellow]Press Ctrl+C to stop capture[/yellow]\n")

        if pcap_out:
            resolved_pcap_path = safe_output_path(pcap_out)
            self.pcap_writer = PcapWriter(resolved_pcap_path, sync=True)
            os.chmod(resolved_pcap_path, 0o640)

        try:
            if read_pcap:
                sniff_kwargs = dict(offline=read_pcap, prn=self.packet_callback, filter=filter_str, store=False)
            else:
                sniff_kwargs = dict(
                    iface=self.interface,
                    prn=self.packet_callback,
                    count=packet_count,
                    timeout=timeout,
                    filter=filter_str,
                    store=False
                )

            # Start packet capture in a separate thread
            capture_thread = threading.Thread(target=lambda: sniff(**sniff_kwargs))
            capture_thread.daemon = True
            capture_thread.start()

            # Live display update
            with Live(self.generate_display_table(), refresh_per_second=2) as live:
                last_snapshot = 0
                while capture_thread.is_alive():
                    time.sleep(0.5)
                    live.update(self.generate_display_table())

                    now = time.monotonic()
                    if now - last_snapshot >= 1:
                        try:
                            self.export_live_snapshot()
                        except OSError as e:
                            console.print(f"[yellow]Warning: couldn't write live snapshot: {e}[/yellow]")
                        last_snapshot = now

        except KeyboardInterrupt:
            console.print("\n[yellow]Capture interrupted by user[/yellow]")
        except PermissionError:
            console.print("[red]Error: Packet capture requires root/administrator privileges[/red]")
            console.print("[yellow]Try running with: sudo python3 analyzer.py[/yellow]")
        except Exception as e:
            console.print(f"[red]Error during capture: {str(e)}[/red]")
        finally:
            if self.pcap_writer is not None:
                self.pcap_writer.close()


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Network Traffic Analyzer")
    parser.add_argument('-i', '--interface', help='Network interface to capture on')
    parser.add_argument('-c', '--count', type=int, default=0, help='Number of packets to capture (0=unlimited)')
    parser.add_argument('-t', '--timeout', type=int, help='Capture timeout in seconds')
    parser.add_argument('-f', '--filter', help='BPF filter string (e.g., "tcp port 80")')
    parser.add_argument('-o', '--output', default='traffic_analysis.json', help='Output JSON file')
    parser.add_argument('--pcap', action='store_true', help='Also save raw packets to traffic_capture.pcap')
    parser.add_argument('-r', '--read-pcap', help='Analyze an existing .pcap file instead of capturing live traffic')

    args = parser.parse_args()

    analyzer = PacketAnalyzer(interface=args.interface)
    analyzer.start_capture(
        packet_count=args.count,
        timeout=args.timeout,
        filter_str=args.filter,
        pcap_out='traffic_capture.pcap' if args.pcap else None,
        read_pcap=args.read_pcap
    )
    
    # Export results
    if analyzer.packet_count > 0:
        analyzer.export_to_json(args.output)
