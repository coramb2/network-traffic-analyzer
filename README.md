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

### PCAP Export / Import
```bash
# Also save raw packets alongside the usual reports, for Wireshark/tcpdump
sudo venv/bin/python3 network_monitor.py -t 60 --pcap

# Re-run analysis (including --alerts) against an existing capture instead
# of live traffic - no root/capabilities needed, since nothing is sniffed
venv/bin/python3 network_monitor.py -r existing_capture.pcap --html --alerts
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
├── alert_rules.py              # Shared allowlist/resolved-alert state (both containers)
├── device_names.py             # Shared device naming + reverse-DNS resolution
├── webapp.py                   # Dashboard: live view, run history, alert workflow
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

# Same idea for the small shared state directory the dashboard uses to
# store allowlist rules and resolved-alert markers (see "Alert Rules" below)
mkdir -p data && sudo chown -R 10002:0 data && chmod -R 0770 data

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

### Alert Rules (allowlist + resolve)

Recurring alerts for something you already know about (your own RDP jump
box, a NAS that legitimately talks to a lot of ports, etc.) don't need to
keep reappearing every cycle. From an alert's row in the dashboard:

- **Allowlist** — pins the alert's type plus (optionally) its source IP
  and/or destination port as a rule. Future alerts matching that pattern
  are suppressed *before* they're ever written to `security_alerts.json` —
  the detector loads current rules once per capture cycle, so a new rule
  takes effect starting the next run, not retroactively. Manage existing
  rules (see what's suppressed, remove one) in the "Alert Rules" panel.
- **Resolve** — a lighter, per-alert acknowledgment for one-off alerts you
  don't want allowlisted forever. It doesn't stop the alert from firing
  again if the same thing happens later; it just marks that specific past
  occurrence as dealt with so it stops showing as an open item.

This state (`data/alert_state.json`) lives in its own small volume, kept
separate from `./reports`: the dashboard needs read-write access to manage
it, while the capture container only ever reads it (mounted `:ro` there)
to know what to suppress.

### Alert Resolution Pathways

Clicking **Details** on an alert expands a per-type playbook (`alert_playbooks.py`)
covering what the alert means, signs it's likely benign vs. worth a closer
look, and a short list of concrete next steps - written for a home-network
setting rather than an enterprise SOC.

Resolving an alert now records a structured **outcome** alongside the
optional note, not just a bare acknowledgment:

- `known` - expected traffic you recognize
- `false_positive` - not real activity of that kind
- `benign` - real, but not a concern
- `mitigated` - you took action (blocked it, closed the port, etc.)
- `investigating` - still looking into it
- `threat` - confirmed something bad

Every outcome except `investigating` removes the alert from the open/unresolved
count - `investigating` is meant to stay visible as an in-progress item until
you resolve it again with a final outcome. The outcome shows as a badge next
to the alert going forward.

For alerts with a source IP and/or destination port (port scans, high
connection rate, suspicious port access), the details view also suggests
matching firewall rules in a few formats (`ufw`, `iptables`, `nftables`) plus
a plain-English description of what to do on your router, each with a
**Copy** button. These are suggestions only - nothing here is ever applied
automatically; you decide whether and how to act on them.

### Device Names

Raw IPs are hard to reason about ("port scan from 192.168.1.47" — which
box is that?). The dashboard's **Devices** panel lets you give any IP a
friendly name, which then shows up everywhere that IP appears (top-IP
tables, alert descriptions).

To save you naming everything by hand, each capture run does best-effort
**reverse-DNS** (PTR) lookups on the busiest IPs and stores the results as
suggestions — click a suggestion to accept it as the name, or type your
own. Lookups are time-bounded so they can't stall a run, and can be turned
off entirely with `RESOLVE_HOSTNAMES=false` (or `--no-hostnames` on the
CLI) if you'd rather no PTR queries leave the host. Names are keyed by IP
for now, stored in `data/device_names.json` in the same read-write state
volume as the alert rules.

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
- [x] PCAP file import/export
- [ ] Real-time alerting (email/Slack/webhook)
- [ ] Database storage for historical analysis
- [x] Web-based dashboard
- [x] Alert resolution pathways (playbooks, structured outcomes, firewall suggestions)

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
