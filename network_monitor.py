#!/usr/bin/env python3
"""
Complete Network Traffic Monitor
Integrates packet capture, anomaly detection, and reporting
"""

import argparse
import sys
import json
from datetime import datetime
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

# Import our modules
from analyzer import PacketAnalyzer
from detector import AnomalyDetector
from reporter import TrafficReporter

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
            filter_str=args.filter
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
            
            alert_count = len(detector.alerts)
            if alert_count > 0:
                console.print(f"[red]⚠[/red]  Found {alert_count} security alerts")
            else:
                console.print("[green]✓[/green] No suspicious activity detected")
        
        # Generate reports
        console.print("\n[yellow]Generating reports...[/yellow]")
        
        # Prepare analyzer data for reporting
        analyzer_data = {
            'analysis_time': datetime.now().isoformat(),
            'duration_seconds': (datetime.now() - analyzer.start_time).seconds,
            'total_packets': analyzer.packet_count,
            'protocol_stats': dict(analyzer.protocol_stats),
            'top_ips': dict(sorted(analyzer.ip_stats.items(), 
                                  key=lambda x: x[1], reverse=True)[:20]),
            'top_ports': {str(k): v for k, v in 
                         sorted(analyzer.port_stats.items(), 
                               key=lambda x: x[1], reverse=True)[:20]},
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
        analyzer.export_to_json(args.output)
        
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
