# 🔍 Network Traffic Analyzer

A real-time network packet capture and analysis tool with anomaly detection capabilities. Built for cybersecurity professionals, network engineers, and security researchers.

![Python Version](https://img.shields.io/badge/python-3.8%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

## 🎯 Features

- **Real-time Packet Capture**: Live network traffic monitoring with rich terminal UI
- **Protocol Analysis**: Automatic detection and classification of TCP, UDP, ICMP, and HTTP traffic
- **Anomaly Detection**: Identifies suspicious patterns including:
  - Port scanning attempts
  - High connection rates (potential DDoS)
  - Access to vulnerable services (RDP, Telnet, SMB)
  - Unusual protocol distributions
- **Comprehensive Reporting**: Generates JSON, CSV, and HTML reports with interactive visualizations
- **BPF Filtering**: Supports Berkeley Packet Filter syntax for targeted capture
- **Efficient Processing**: Handles thousands of packets per second with minimal overhead

## 📋 Prerequisites

- Python 3.8 or higher
- Root/Administrator privileges (required for packet capture)
- Linux, macOS, or Windows WSL

## 🚀 Quick Start
```bash
# Clone repository
git clone https://github.com/coramb2/network-traffic-analyzer.git
cd network-traffic-analyzer

# Setup virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run 60-second capture with full analysis
sudo venv/bin/python3 network_monitor.py -t 60 --html --summary --alerts
```

## 💻 Usage Examples

### Basic Capture
```bash
# 30-second capture with HTML report
sudo venv/bin/python3 network_monitor.py -t 30 --html
```

### Filter Specific Traffic
```bash
# Monitor only HTTP/HTTPS traffic
sudo venv/bin/python3 network_monitor.py -f "tcp port 80 or tcp port 443" -c 1000

# Capture DNS queries
sudo venv/bin/python3 network_monitor.py -f "udp port 53" -t 60

# Monitor SSH connections
sudo venv/bin/python3 network_monitor.py -f "tcp port 22" -t 120 --alerts
```

### Full Analysis
```bash
# Complete analysis with anomaly detection and all report formats
sudo venv/bin/python3 network_monitor.py -t 120 --html --csv --alerts --summary
```

### Capture on Specific Interface
```bash
# List available interfaces
ip link show

# Capture on specific interface
sudo venv/bin/python3 network_monitor.py -i eth0 -t 60 --html
```

## 📊 Output Examples

### Real-Time Terminal Display
The analyzer provides a live dashboard showing:
- Total packets captured and capture rate (packets/second)
- Protocol distribution (TCP/UDP/ICMP percentages)
- Top 10 most active IP addresses
- Top 10 destination ports with service identification

### Generated Reports

**JSON Report** (`traffic_analysis.json`)
- Comprehensive traffic statistics
- Protocol breakdowns
- Top IP addresses and ports
- Recent packet details

**CSV Export** (`traffic_data.csv`)
- Packet-level data with timestamps
- Source/destination IPs and ports
- Protocol information
- Ready for import into analysis tools

**HTML Dashboard** (`traffic_report.html`)
- Interactive charts and visualizations
- Protocol distribution pie charts
- Sortable tables for IPs and ports
- Security alerts (if any detected)

## 🔒 Security Features

The built-in anomaly detection engine identifies:

- **Port Scanning**: Detects when a single IP accesses 20+ different ports
- **High Connection Rates**: Flags potential DDoS attacks (50+ connections/second)
- **Suspicious Services**: Monitors access to commonly exploited services:
  - RDP (3389), Telnet (23), SMB (445)
  - MSSQL (1433), VNC (5900), NetBIOS (137-139)
- **Traffic Anomalies**: Identifies unusual protocol distributions
- **Large Packets**: Detects potential data exfiltration via oversized UDP packets

## 🛠️ Technical Stack

- **Scapy 2.5.0**: Powerful Python packet manipulation library
- **Rich 13.7.0**: Modern terminal UI with live updates
- **Python Threading**: Non-blocking packet processing
- **BPF (Berkeley Packet Filter)**: Industry-standard packet filtering

## 📁 Project Structure
```
network-traffic-analyzer/
├── analyzer.py          # Main packet capture and real-time analysis
├── detector.py          # Anomaly detection engine
├── reporter.py          # Multi-format report generation (JSON/CSV/HTML)
├── network_monitor.py   # Integrated CLI application
├── requirements.txt     # Python dependencies
└── README.md           # Documentation
```

## 🎓 Skills Demonstrated

- **Network Security**: Protocol analysis, threat detection, traffic pattern recognition
- **Python Development**: Threading, CLI design, error handling, optimized data structures
- **System Programming**: Low-level packet capture, BPF filtering
- **Data Visualization**: Real-time dashboards, HTML reporting with Chart.js

## 🔧 Troubleshooting

### Permission Denied
**Problem**: `PermissionError: Operation not permitted`

**Solution**: Packet capture requires root privileges
```bash
sudo venv/bin/python3 network_monitor.py -t 60
```

### No Packets Captured
**Problem**: Filter too restrictive or wrong interface

**Solutions**:
```bash
# Remove filter to test
sudo venv/bin/python3 network_monitor.py -t 30

# Try different interface
sudo venv/bin/python3 network_monitor.py -i lo -t 30

# Generate traffic (in another terminal)
ping google.com
```

### Interface Not Found
**Problem**: Specified network interface doesn't exist

**Solution**: List available interfaces
```bash
# Linux
ip link show

# Or use default interface (don't specify -i flag)
sudo venv/bin/python3 network_monitor.py -t 60
```

## 📚 Learning Resources

This project demonstrates understanding of:
- **OSI Model**: Operates at Layer 3 (Network) and Layer 4 (Transport)
- **TCP/IP Protocol Suite**: TCP, UDP, ICMP, HTTP analysis
- **Network Security**: IDS/IPS fundamentals, threat detection
- **Packet Analysis**: Deep packet inspection techniques

## 🚀 Future Enhancements

Potential additions:
- [ ] Machine learning-based anomaly detection
- [ ] GeoIP lookup for traffic origin mapping
- [ ] PCAP file import/export
- [ ] Real-time alerting (email/Slack/webhook)
- [ ] Database storage for historical analysis
- [ ] Web-based dashboard

## 📝 License

MIT License - Free to use for learning and portfolio purposes

## 👤 Author

**Cora Baldwin**
- GitHub: [@coramb2](https://github.com/coramb2)
- LinkedIn: [Cora Baldwin](https://www.linkedin.com/in/cora-baldwin-11605730b/)

*Recent Software Engineering graduate (BA) with minor in Business Engineering Technology from a D1 university. Passionate about cybersecurity, network engineering, and building practical security tools.*

---

⭐ **Star this repo if you found it useful!**

📧 **Questions or feedback?** Open an issue or connect on LinkedIn
