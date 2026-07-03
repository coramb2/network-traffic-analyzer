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
- **Flask 3.0.3**: Read-only web dashboard for live stats and run history
- **Python Threading**: Non-blocking packet processing
- **BPF (Berkeley Packet Filter)**: Industry-standard packet filtering

## 📁 Project Structure
```
network-traffic-analyzer/
├── analyzer.py                 # Main packet capture and real-time analysis
├── detector.py                 # Anomaly detection engine
├── reporter.py                 # Multi-format report generation (JSON/CSV/HTML)
├── network_monitor.py          # Integrated CLI application
├── webapp.py                   # Read-only Flask dashboard (live view + run history)
├── templates/index.html        # Dashboard frontend
├── static/vendor/chart.min.js  # Vendored Chart.js (no CDN dependency)
├── requirements.txt            # Python dependencies (capture container)
├── requirements-dashboard.txt  # Python dependencies (dashboard container)
├── Dockerfile                  # Capture container image
├── Dockerfile.dashboard        # Dashboard container image
├── docker-compose.yml          # Both services wired together
└── README.md                  # Documentation
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

## 🏠 Home Server Deployment (Docker)

For unattended use on a home server, `docker-compose.yml` runs scheduled
captures instead of one-off manual runs: every `INTERVAL_SECONDS` it
captures for `CAPTURE_DURATION` seconds, writes a full report set
(JSON/CSV/HTML/alerts) into its own timestamped folder under `./reports`,
updates a `reports/latest` symlink, and prunes old runs beyond
`RETENTION_RUNS` so disk usage stays bounded.

### Setup

```bash
# Find your host's real network interface (not a container/veth one)
ip -brief link

# Configure
cp .env.example .env
# edit .env: set IFACE to the interface above, adjust CAPTURE_DURATION/
# INTERVAL_SECONDS/RETENTION_RUNS to taste

# The container runs as a fixed non-root uid (10001) for defense in depth —
# make the host-side reports directory writable by it
mkdir -p reports && sudo chown -R 10001:10001 reports

# Build and start
docker compose up -d --build

# Watch it work
docker compose logs -f
```

Reports land in `./reports/<UTC timestamp>/` on the host, with
`./reports/latest` always pointing at the newest run. Open
`reports/latest/traffic_report.html` in a browser for the visual report,
or use the web dashboard below for a live view plus history browsing.

### Web Dashboard

`docker compose up` also starts a `dashboard` service: a small read-only
Flask app at `http://<host>:8080` (change with `DASHBOARD_PORT` in `.env`)
that polls the capture container's live stats during an active run and
lets you browse past runs (alerts, protocol breakdown, links to each run's
full HTML report / CSV).

It's a separate container from the capture service on purpose: it only
needs read access to `./reports` (mounted `:ro`) and one published port —
no `NET_RAW`/`NET_ADMIN`, no host networking. Restarting or rebuilding it
never touches the capture container.

### Why it's set up this way

- **`network_mode: host`**: the analyzer's whole job is to see your home
  network's real traffic, which bridge networking hides from a container.
  This does mean the container shares the host's network namespace — a
  deliberate tradeoff for this tool, not something to copy into
  general-purpose containers.
- **`cap_drop: ALL` + `cap_add: [NET_RAW, NET_ADMIN]`, non-root user**:
  packet capture needs raw sockets, not full root. The image grants those
  two capabilities directly to the `python3` binary (`setcap`, see
  `Dockerfile`) and runs as an unprivileged `analyzer` user, so a bug or
  compromise in this tool doesn't hand over a root shell on your server.
- **Scheduled runs instead of one continuous capture**: bounds memory
  growth and gives you a rotating history of reports instead of one
  ever-growing process/file. `RETENTION_RUNS` caps disk usage.
- **Reports written `0640`**: capture output includes every device's IPs,
  ports, and (in the JSON) visited HTTP hosts/paths — treat `./reports` as
  sensitive if other people use your network. Group-readable (not `0600`)
  because the dashboard container reads them as a different, unprivileged
  uid that shares the capture container's `gid 0` by design.
- **`mem_limit` / `pids_limit`**: bounds a runaway capture on a busy network.

### Manual (non-Docker) alternative

You can still run it directly with `sudo`, as described above — useful for
one-off captures or debugging. The systemd-service route (a persistent
unit + `setcap` on a venv's python, instead of Docker) is a reasonable
alternative if you'd rather not run Docker on your home server; ask if
you'd like that added too.

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
- [x] Web-based dashboard

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
