#!/usr/bin/env python3
"""
Complete Network Traffic Monitor
Integrates packet capture, anomaly detection, and reporting
"""

import argparse
import os
import sys
import json
from datetime import datetime
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

# Import our modules
from analyzer import PacketAnalyzer
from detector import AnomalyDetector
from reporter import TrafficReporter
import device_names
import geoip
import notifications
import threat_intel
import vendor_lookup

console = Console()

def main():
    parser = argparse.ArgumentParser(
        description="Network Traffic Monitor with Anomaly Detection",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic capture for 60 seconds
  sudo python3 network_monitor.py -t 60
  
  # Monitor HTTP traffic on eth0
  sudo python3 network_monitor.py -i eth0 -f "tcp port 80" -c 1000
  
  # Full analysis with all reports
  sudo python3 network_monitor.py -t 120 --html --csv --alerts

  # Also save raw packets for later inspection in Wireshark/tcpdump
  sudo python3 network_monitor.py -t 60 --pcap

  # Re-analyze a capture taken elsewhere (no root/capabilities needed)
  python3 network_monitor.py -r existing_capture.pcap --html --alerts
        """
    )
    
    # Capture options
    parser.add_argument('-i', '--interface', help='Network interface to monitor')
    parser.add_argument('-c', '--count', type=int, default=0, 
                       help='Number of packets to capture (0=unlimited)')
    parser.add_argument('-t', '--timeout', type=int, 
                       help='Capture timeout in seconds')
    parser.add_argument('-f', '--filter', 
                       help='BPF filter (e.g., "tcp port 80")')
    
    # Output options
    parser.add_argument('-o', '--output', default='traffic_analysis.json',
                       help='JSON output filename')
    parser.add_argument('--csv', action='store_true',
                       help='Generate CSV report')
    parser.add_argument('--html', action='store_true',
                       help='Generate HTML report')
    parser.add_argument('--summary', action='store_true',
                       help='Print text summary to console')
    parser.add_argument('--alerts', action='store_true',
                       help='Enable anomaly detection and export alerts')
    parser.add_argument('--pcap', action='store_true',
                       help='Also save raw packets to traffic_capture.pcap')
    parser.add_argument('-r', '--read-pcap',
                       help='Analyze an existing .pcap file instead of capturing live traffic')
    parser.add_argument('--no-hostnames', action='store_true',
                       help='Skip reverse-DNS lookups (no device-name suggestions)')
    parser.add_argument('--geoip', action='store_true',
                       help='Look up country/org for public IPs (sends IPs to a third-party API - see README)')
    parser.add_argument('--threat-intel', action='store_true',
                       help='Check captured IPs against a public threat blocklist (requires --alerts; see README)')

    args = parser.parse_args()
    
    # Display banner
    console.print("\n[bold cyan]" + "=" * 70 + "[/bold cyan]")
    console.print("[bold cyan]          NETWORK TRAFFIC MONITOR & ANALYZER[/bold cyan]")
    console.print("[bold cyan]" + "=" * 70 + "[/bold cyan]\n")
    
    # Initialize components
    analyzer = PacketAnalyzer(interface=args.interface)
    detector = AnomalyDetector() if args.alerts else None
    
    try:
        # Start packet capture
        console.print("[yellow]Starting packet capture...[/yellow]")
        if args.read_pcap:
            console.print(f"Reading from: {args.read_pcap}")
        else:
            console.print(f"Interface: {args.interface or 'default'}")
        console.print(f"Filter: {args.filter or 'none'}")
        if args.timeout:
            console.print(f"Timeout: {args.timeout} seconds")
        if args.count:
            console.print(f"Target packets: {args.count}")
        console.print("\n[cyan]Press Ctrl+C to stop and generate reports[/cyan]\n")

        # Capture packets
        analyzer.start_capture(
            packet_count=args.count,
            timeout=args.timeout,
            filter_str=args.filter,
            pcap_out='traffic_capture.pcap' if args.pcap else None,
            read_pcap=args.read_pcap
        )
        
        # Check if we captured anything
        if analyzer.packet_count == 0:
            console.print("[yellow]No packets captured. Check your interface and filter settings.[/yellow]")
            return
        
        console.print(f"\n[green]✓[/green] Captured {analyzer.packet_count} packets")
        
        # Run anomaly detection if enabled
        if detector:
            console.print("[yellow]Running anomaly detection...[/yellow]")
            
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console
            ) as progress:
                task = progress.add_task("Analyzing packets...", total=len(analyzer.packets))
                
                for packet in analyzer.packets:
                    alerts = detector.analyze_packet(packet)
                    progress.update(task, advance=1)
                
                # Run pattern analysis
                pattern_alerts = detector.analyze_traffic_patterns(analyzer.packets)

                # New/unknown device detection - whole-run check against
                # every device ever seen, not just this run's packets, so
                # it's kept separate from analyze_packet/analyze_traffic_patterns
                # above. Entirely offline; always runs when --alerts is on.
                # ip_stats includes both sources and destinations (e.g.
                # 8.8.8.8 as a packet's dst_ip) - restrict to IPs that are
                # actually plausible LAN devices, not every external
                # address anything on the network happened to talk to.
                seen_devices = [
                    {'ip': ip, 'mac': analyzer.ip_mac_map.get(ip)}
                    for ip in analyzer.ip_stats.keys()
                    if ip in analyzer.ip_mac_map or not geoip.is_public_ip(ip)
                ]
                new_device_alerts = detector.detect_new_devices(seen_devices)
                if new_device_alerts:
                    console.print(f"[yellow]![/yellow] {len(new_device_alerts)} new device(s) seen for the first time")

            # Threat-intel blocklist matching - opt-in (--threat-intel)
            # since, unlike the local-only checks above, it's a network
            # call to a third party (downloading a public IP blocklist,
            # not sending it any of our traffic). Checked against every
            # captured IP, not just the top ones: a low-volume C2 beacon
            # is exactly the kind of traffic that wouldn't make a top-20
            # list but is the most important thing to catch.
            if args.threat_intel:
                console.print("[yellow]Checking IPs against threat intelligence feed...[/yellow]")
                threat_matches = threat_intel.match_ips(list(analyzer.ip_stats.keys()))
                threat_alerts = detector.detect_threat_matches(threat_matches)
                if threat_alerts:
                    console.print(f"[red]⚠[/red]  {len(threat_alerts)} IP(s) matched a known threat blocklist")

            alert_count = len(detector.alerts)
            if alert_count > 0:
                console.print(f"[red]⚠[/red]  Found {alert_count} security alerts")
            else:
                console.print("[green]✓[/green] No suspicious activity detected")
        elif args.threat_intel:
            console.print("[yellow]--threat-intel has no effect without --alerts[/yellow]")

        # Generate reports
        console.print("\n[yellow]Generating reports...[/yellow]")

        # Resolve reverse-DNS names for the busiest IPs, to power the
        # dashboard's device-name suggestions. Best-effort and time-bounded
        # (see device_names.resolve_hostnames); skipped with --no-hostnames.
        top_ip_list = [ip for ip, _ in sorted(analyzer.ip_stats.items(),
                                              key=lambda x: x[1], reverse=True)[:20]]
        hostnames = {}
        if not args.no_hostnames and top_ip_list:
            console.print("[yellow]Resolving device hostnames...[/yellow]")
            hostnames = device_names.resolve_hostnames(top_ip_list)
            if hostnames:
                console.print(f"[green]✓[/green] Resolved {len(hostnames)} hostname(s)")

        # GeoIP/org lookup for public IPs only (private ones are skipped
        # inside resolve_geoip) - opt-in via --geoip, since unlike the
        # reverse-DNS lookup above this sends IPs to a third-party API.
        geo_info = {}
        if args.geoip and top_ip_list:
            console.print("[yellow]Resolving GeoIP info...[/yellow]")
            geo_info = geoip.resolve_geoip(top_ip_list)
            if geo_info:
                console.print(f"[green]✓[/green] Resolved GeoIP for {len(geo_info)} IP(s)")

        # MAC + vendor for the busiest IPs we actually saw a source MAC for
        # (only ever recorded for the sending device - see analyzer.py).
        # Entirely offline (bundled OUI database), always on - no lookup to
        # skip, no rate limit or privacy tradeoff like the two lookups above.
        mac_info = {
            ip: {'mac': mac, 'vendor': vendor_lookup.lookup_vendor(mac)}
            for ip, mac in analyzer.ip_mac_map.items()
            if ip in top_ip_list
        }

        # Prepare analyzer data for reporting
        report_duration_seconds = (datetime.now() - analyzer.start_time).seconds
        analyzer_data = {
            'analysis_time': datetime.now().isoformat(),
            'duration_seconds': report_duration_seconds,
            'total_packets': analyzer.packet_count,
            'interface': analyzer.interface or 'default',
            'packets_per_second': round(analyzer.packet_count / max(report_duration_seconds, 1), 2),
            'protocol_stats': dict(analyzer.protocol_stats),
            'top_ips': dict(sorted(analyzer.ip_stats.items(),
                                  key=lambda x: x[1], reverse=True)[:20]),
            'top_ports': {str(k): v for k, v in
                         sorted(analyzer.port_stats.items(),
                               key=lambda x: x[1], reverse=True)[:20]},
            'hostnames': hostnames,
            'geoip': geo_info,
            'mac_info': mac_info,
            'recent_packets': analyzer.packets[-100:]
        }
        
        # Prepare detector data if available
        detector_data = None
        if detector:
            detector_data = {
                'total_alerts': len(detector.alerts),
                'alerts': detector.alerts
            }
        
        # Create reporter
        reporter = TrafficReporter(analyzer_data, detector_data)
        
        # Export JSON (always)
        analyzer.export_to_json(args.output, hostnames=hostnames, geoip=geo_info, mac_info=mac_info)
        
        # Export CSV if requested
        if args.csv:
            csv_file = reporter.export_to_csv('traffic_data.csv')
            if csv_file:
                console.print(f"[green]✓[/green] CSV exported to {csv_file}")
        
        # Export HTML if requested
        if args.html:
            html_file = reporter.generate_html_report('traffic_report.html')
            console.print(f"[green]✓[/green] HTML report generated: {html_file}")
        
        # Export alerts if detected
        if detector and detector.alerts:
            alerts_file = detector.export_alerts('security_alerts.json')
            console.print(f"[green]✓[/green] Security alerts exported to {alerts_file}")

            # Opt-in, best-effort: no-ops unless ALERT_WEBHOOK_URL/SMTP_HOST
            # are configured, and a delivery failure here never affects the
            # exit status - the report is already safely on disk above.
            notify_config = notifications.config_from_env()
            if notify_config['webhook_url'] or notify_config['smtp']:
                run_id = os.path.basename(os.getcwd())
                results = notifications.notify_alerts(detector.alerts, notify_config, run_id=run_id)
                for channel, sent in results.items():
                    if sent is True:
                        console.print(f"[green]✓[/green] Alert notification sent via {channel}")
                    elif sent is False:
                        console.print(f"[yellow]Warning: alert notification via {channel} failed[/yellow]")

        if args.pcap:
            console.print(f"[green]✓[/green] Raw packets saved to traffic_capture.pcap")
        
        # Print summary if requested
        if args.summary:
            console.print("\n")
            summary = reporter.generate_summary_report()
            console.print(summary)
        
        # Final summary
        console.print("\n[bold green]Analysis Complete![/bold green]")
        console.print(f"\nFiles generated:")
        console.print(f"  • {args.output} (JSON analysis)")
        if args.csv:
            console.print(f"  • traffic_data.csv (packet data)")
        if args.html:
            console.print(f"  • traffic_report.html (visual report)")
        if detector and detector.alerts:
            console.print(f"  • security_alerts.json (security alerts)")
        if args.pcap:
            console.print(f"  • traffic_capture.pcap (raw packets)")

        console.print("\n[cyan]Tip: Use --html flag to generate a visual report[/cyan]")
        console.print("[cyan]     Use --summary flag to print analysis to console[/cyan]\n")
        
    except KeyboardInterrupt:
        console.print("\n[yellow]Capture interrupted by user[/yellow]")
        if analyzer.packet_count > 0:
            console.print(f"[green]✓[/green] Captured {analyzer.packet_count} packets before interruption")
    except PermissionError:
        console.print("\n[red]Error: Packet capture requires root/administrator privileges[/red]")
        console.print("[yellow]Try running with: sudo python3 network_monitor.py[/yellow]")
        sys.exit(1)
    except Exception as e:
        console.print(f"\n[red]Error: {str(e)}[/red]")
        import traceback
        console.print(traceback.format_exc())
        sys.exit(1)


if __name__ == "__main__":
    main()
