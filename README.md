# 🔍 Network Traffic Analyzer

A real-time network packet capture and analysis tool with anomaly detection capabilities. Built for cybersecurity professionals, network engineers, and security researchers.

![CI](https://github.com/coramb2/network-traffic-analyzer/actions/workflows/ci.yml/badge.svg)
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
- **New Devices**: Flags a device (by MAC, or IP if no MAC was observed) the first time it's ever seen on the network - entirely offline, always on with `--alerts`. See "New Device Detection" below.

## 🆕 New Device Detection

`--alerts` also checks every device seen in a run against `known_devices.json` (or `KNOWN_DEVICES_PATH`), a small on-disk record of every MAC/IP ever seen in a previous run, and raises a `NEW_DEVICE` alert the first time one shows up. Identity is keyed by MAC when available - since a MAC survives a DHCP lease renewal, a device that just got a new IP isn't wrongly flagged as new - falling back to IP only when no source MAC was ever observed for it (e.g. traffic captured over an interface without Ethernet framing).

Two things worth knowing:
- **The very first capture run against a fresh install will flag every device as "new"** - there's no history yet to compare against. That's expected, not a bug; treat that first run's alerts as a baseline, not a threat report.
- Only devices that look like they're actually on your LAN are checked (a device we recorded a source MAC for, or any device with a private/local IP) - a public destination IP your devices merely talked to (e.g. `8.8.8.8`) is never flagged as a "new device".

This is entirely local and offline - no third-party service involved, unlike GeoIP above.

## 🛡️ Threat Intelligence Matching

`--threat-intel` (or `THREAT_INTEL_ENABLED=true`) checks every captured IP against [abuse.ch's Feodo Tracker](https://feodotracker.abuse.ch/), a free, no-API-key feed of active botnet command-and-control server IPs, and raises a **HIGH severity** `THREAT_INTEL_MATCH` alert for any hit. Requires `--alerts`.

- **Off by default.** Unlike GeoIP, no data about your traffic is sent anywhere - this only downloads a public IP list - but it's still an outbound network call to a third party, so it stays opt-in.
- The blocklist itself is cached on disk (`threat_intel_cache.json` / `THREAT_INTEL_CACHE_PATH`) and refreshed at most once every 24 hours. If a refresh fails (feed unreachable, network policy blocking it, etc.) the last successfully fetched list keeps being used - a day-old blocklist is far more useful than none, and a capture run never fails just because the feed couldn't be reached.
- Every captured IP is checked, not just the top ones - a low-volume botnet beacon is exactly the kind of traffic that wouldn't make a top-20 list.
- **This is a best-effort signal from one blocklist, not a complete threat feed.** A clean result doesn't mean an IP is safe, only that it isn't on this particular list.

## 📈 Bandwidth by Device

The dashboard's "Bandwidth by Device" chart breaks the aggregate Traffic Trend chart down by device: a line per device, packet counts across the last 20 completed runs (`/api/device-trend`), for whichever 5 devices generated the most total traffic in that window - useful for spotting which device is actually driving a spike the aggregate chart shows, or noticing one device's usage creeping up over time.

- Each line is labeled with the device's manual name if you've set one, else its reverse-DNS hostname, else its MAC vendor, else the bare IP - same precedence the Devices panel uses.
- A device's line color is stable for as long as it stays in the top 5, even as its *rank* within the top 5 moves - only when a device actually drops out of the top 5 does its color slot free up for whichever device takes its place.
- A run where a device wasn't among that run's top 20 IPs shows as 0 for that point, not a gap - it wasn't one of the busiest devices that run, which isn't the same as being silent.

## ✅ Testing

```bash
pip install -r requirements.txt -r requirements-dashboard.txt -r requirements-dev.txt
pytest
```

The suite covers the pure-logic modules directly (`paths`, `detector`,
`alert_rules`, `alert_playbooks`, `device_names`, `reporter`, `analyzer` -
the last using synthetic in-memory packets built with scapy, so no root or
real network access is needed) plus the dashboard's Flask routes via its
test client (path-traversal attempts against run IDs, allowlist/device
validation, resolved-alert state, live-vs-idle status). Each test file
isolates its own state directory (`ALERT_STATE_PATH`/`DEVICE_NAMES_PATH`/
`REPORTS_ROOT`) via `tmp_path`, so tests don't share or leak state between
runs. No network access, root, or a running capture is required for any
of it.

`tests/test_dashboard_browser.py` is different: it launches a real
browser (Playwright) against a live instance of the dashboard and drives
`templates/index.html`'s actual JS - Chart.js rendering, the escaping
discipline, the device-trend chart's color-stability guarantee - rather
than going through Flask's in-process test client like everything else.
Needs a browser installed once (`playwright install chromium`); every
other test file needs nothing beyond `requirements-dev.txt`.

**CI** (`.github/workflows/ci.yml`) runs the same install + compile-check +
lint + supply-chain scan + `pytest` on every push to `main` and every pull
request targeting it, on `ubuntu-latest` with Python 3.11 - the badge at
the top of this README reflects the latest run. Lint is `ruff`
(`pyproject.toml`) with a deliberately narrow, correctness-focused rule
set - unused imports/variables, undefined names, ambiguous variable
names - not full style enforcement.

The supply-chain scan (`check_pip_audit.py`) runs `pip-audit` against all
three requirement files, failing CI the moment a CVE is disclosed for an
already-pinned dependency rather than waiting on a Dependabot PR. A
finding with no fixed version released yet can be temporarily suppressed
via `pip_audit_ignores.toml`, but every entry there needs an `expires`
date - once it passes, the script refuses to even run `pip-audit` until
the suppression is re-evaluated (extended or dropped in favor of a real
fix), so a suppression can't quietly outlive its reason.

## 🛠️ Technical Stack

- **Scapy 2.5.0**: Powerful Python packet manipulation library
- **Rich 13.7.0**: Modern terminal UI with live updates
- **Flask 3.0.3**: Read-only web dashboard for live stats and run history
- **manuf 1.1.5**: Offline MAC vendor lookup (bundles Wireshark's OUI database)
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
├── notifications.py            # Webhook/email alert digests (stdlib only)
├── geoip.py                    # Opt-in GeoIP/org lookup for public IPs (cached)
├── vendor_lookup.py            # Offline MAC -> vendor lookup (manuf)
├── known_devices.py            # Persistent MAC/IP history, powers NEW_DEVICE alerts
├── threat_intel.py             # Opt-in threat blocklist matching (cached)
├── webapp.py                   # Dashboard: live view, run history, alert workflow
├── templates/index.html        # Dashboard frontend
├── static/vendor/chart.min.js  # Vendored Chart.js (no CDN dependency)
├── requirements.txt            # Python dependencies (capture container)
├── requirements-dashboard.txt  # Python dependencies (dashboard container)
├── Dockerfile                  # Capture container image
├── Dockerfile.dashboard        # Dashboard container image
├── docker-compose.yml          # Both services wired together
├── systemd/                     # Native systemd deployment (Docker alternative)
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
# INTERVAL_SECONDS/RETENTION_RUNS to taste, and set DASHBOARD_PASSWORD
# (required - the dashboard won't start without it, see "Web Dashboard" below)
echo "DASHBOARD_PASSWORD=$(openssl rand -base64 24)" >> .env
echo "DASHBOARD_SECRET_KEY=$(openssl rand -hex 32)" >> .env

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

**Login is required.** The dashboard can silently suppress security alerts
(allowlist) and serves raw packet captures, so unlike the report files
themselves it refuses to start without `DASHBOARD_PASSWORD` set in `.env`.
Sessions last 30 days; set `DASHBOARD_SECRET_KEY` too or everyone gets
logged out on every container restart (a fresh random key is used
otherwise). Neither has a default - there's no factory password to leave
unchanged.

**Hardening, from an internal pentest:** every response carries
`X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, and a
`Content-Security-Policy` (skipped only for the per-run HTML report,
which loads Chart.js from a CDN with an SRI hash rather than this app's
vendored copy) - so the dashboard can't be embedded in another page's
iframe for a UI-redress/clickjacking attempt. Request bodies are capped
at 64KB (`MAX_CONTENT_LENGTH`) and a device name is capped at 100
characters, so a single request can't bloat `device_names.json` with an
arbitrarily large string. The login throttle escalates per-IP after each
failed attempt (1s, 2s, 4s, ... capped at 30s) rather than holding to a
flat rate forever, and resets on a successful login; its tracking dict
is itself bounded (10,000 entries, oldest evicted first) so it can't
grow without limit under a wide range of source IPs. Stored/reflected XSS and
CSRF were both actively tested for (payloads planted in every
attacker-influenceable field; real cross-site request attempts from a
genuinely different host) and found not exploitable - the consistent
`escapeHtml()` discipline in the frontend and the lack of any
`Access-Control-Allow-Origin` header (so a browser refuses to complete a
cross-site fetch with credentials) hold up under testing.

The **Traffic Trend** panel charts packets/sec and open-alert count across
recent runs (oldest to newest) so you can see whether current traffic or
alert volume looks normal compared to history, not just this one run in
isolation - the one thing a per-run snapshot alone can't show you. It's
built entirely from data `/api/runs` already returns (bounded by
`RETENTION_RUNS`), no extra endpoint or storage needed.

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

### Alert Notifications

Opening the dashboard is the only way to learn about a new alert otherwise
— for anything you'd actually want to know about promptly, configure a
notification channel and skip that. When a completed capture run has new
alerts (past the allowlist), a digest is sent to whichever of these is
configured in `.env` (`notifications.py`); both are optional and
independent, and neither is on by default:

- **Webhook** (`ALERT_WEBHOOK_URL`) — posts `{"text": "..."}`, which works
  as-is with Slack/Discord/Mattermost incoming webhooks.
- **Email** (`SMTP_HOST` + `SMTP_TO` at minimum) — sent via SMTP with
  `smtplib`, no third-party service required.

`ALERT_NOTIFY_MIN_SEVERITY` (default `LOW`, i.e. everything) filters what's
worth a notification versus just showing up in the dashboard on its own.
One digest is sent per run, not one per alert, since a single port scan
can produce dozens of individual alerts — the digest groups them by
severity/type with a handful of examples. A delivery failure (bad
credentials, webhook host down) is logged and otherwise ignored; it never
affects the capture or the reports already written to disk.

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
CLI) if you'd rather no PTR queries leave the host. Names are stored in
`data/device_names.json` in the same read-write state volume as the
alert rules.

**A name survives a DHCP lease change** when a MAC address was recorded
for that device (see "source MAC address and manufacturer" below): saving
a name while a MAC is known ties it to that MAC as well as the IP it was
set on, and the Devices/Traffic Trend panels prefer the MAC-keyed name
whenever one exists - so the device keeps its name even after its IP
changes, as long as it's seen again with the same MAC. A device we've
never recorded an Ethernet source MAC for (see `analyzer.py`) has nothing
more stable to key on, so its name stays IP-only.

For public IPs, the Devices panel can also show a country and
organization ("🌍 US · DigitalOcean") - useful context for deciding
whether an unfamiliar external address in an alert is worth a second
look. Unlike reverse-DNS, this is **off by default**: it queries a
third-party API (ip-api.com's free tier) rather than just your own DNS
resolver, sending it the IPs your devices talked to. Enable with
`GEOIP_ENABLED=true` (or `--geoip` on the CLI) if you're fine with that
tradeoff. Results are cached on disk for 30 days (`geoip.py`), both to
respect that API's free-tier rate limit and because an IP's geolocation
rarely changes day to day; a failed/rate-limited lookup is cached too, so
one bad IP doesn't get retried every single run.

The Devices panel also shows the **source MAC address and manufacturer**
for devices where one was actually seen ("📡 b8:27:eb:11:22:33 · Raspberry
Pi Foundation") - vendor lookup is via `manuf` (`vendor_lookup.py`), which
bundles Wireshark's OUI database, so it's fully offline: no network call,
no rate limit, no privacy tradeoff like GeoIP above, always on. Only the
*source* MAC is ever recorded, and only for the sending device - a
packet's destination MAC for internet-bound traffic is typically your
router's, not the real destination's, so recording it would misattribute
the router's vendor to whatever external IP the traffic happened to go
to (see the comment in `analyzer.py`). An unrecognized OUI (common for
newer or less common hardware, and inherent to any curated-but-incomplete
database) just shows no vendor, never a guess.

Note this doesn't yet solve the underlying problem MAC-based identity is
usually used for - a name still won't follow a device across a DHCP
lease change, since naming itself is still keyed by IP. Re-keying names
to MAC (with a migration for existing `device_names.json` data) would
close that gap but is a bigger, riskier change than this pass; flagging
it here rather than silently doing part of the job.

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
one-off captures or debugging.

## 🖥️ Home Server Deployment (systemd, no Docker)

If you'd rather not run Docker on your home server, `systemd/` sets up the
same two-service architecture (scheduled capture + read-only dashboard)
as native systemd units instead of containers. Same scheduling loop
(`docker/entrypoint.sh` is shared verbatim between both deployments — see
the comment at its top), same environment variables, same security
posture (least-privilege capabilities instead of root, a shared group
instead of a shared Docker gid) — just no container runtime involved.

### Setup

```bash
git clone https://github.com/coramb2/network-traffic-analyzer.git
cd network-traffic-analyzer
sudo systemd/install.sh
```

`install.sh` is idempotent (safe to re-run after `git pull`) and:
- creates a shared `nettraffic` group plus two unprivileged system users,
  `netanalyzer` (runs the capture loop) and `netdashboard` (runs the web
  UI) — mirroring the Docker deployment's non-root `analyzer` user and
  shared-group pattern, just with two real users instead of one
- copies the application code to `/opt/network-traffic-analyzer` and
  creates a Python virtualenv there with both requirements files installed
- creates `/var/lib/network-traffic-analyzer/{reports,state}`, owned so
  each service can write what it owns and read the other's output via the
  shared `nettraffic` group — the same read/write split as the Docker
  volumes (`./reports`, `./data`)
- writes `/etc/network-traffic-analyzer/{capture,dashboard}.env` from the
  templates in `systemd/*.env.example` **only if they don't already
  exist**, so a re-run never clobbers your edits
- installs `systemd/*.service` to `/etc/systemd/system/` and runs
  `systemctl daemon-reload`

Then edit the two generated env files — set `IFACE` in `capture.env` and
`DASHBOARD_PASSWORD` in `dashboard.env` (`openssl rand -base64 24`) — and
start both services:

```bash
sudo systemctl enable --now network-traffic-analyzer network-traffic-dashboard
sudo systemctl status network-traffic-analyzer network-traffic-dashboard
journalctl -u network-traffic-analyzer -f    # tail capture logs
journalctl -u network-traffic-dashboard -f   # tail dashboard logs
```

### Why it's set up this way

- **`AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN`** instead of `setcap`
  on the venv's python binary: it's the systemd-native equivalent of the
  Docker image's `setcap` grant (see above), and unlike a file capability
  it's inherited transparently across `entrypoint.sh`'s exec into
  `python3`, so `NoNewPrivileges=yes` can stay on for both services — a
  `setcap`-on-binary approach would conflict with that setting.
- **`ProtectSystem=strict` + `ProtectHome=yes` + a narrow
  `ReadWritePaths=`**: each service's filesystem is read-only except the
  one directory it actually needs to write to (`reports` for capture,
  `state` for the dashboard) — the systemd equivalent of the containers'
  read-only bind mounts.
- **Shared `nettraffic` group, `0770` directories**: since capture and the
  dashboard run as two different Linux users (unlike the two containers,
  which share Docker's networking-namespace isolation instead), each
  needs read access to state it doesn't own. Group membership plus
  `0770`/`0640` permissions grants exactly that, without either service
  running as root or as the same user as the other.
- **`Restart=on-failure`**: same self-healing behavior as Docker Compose's
  `restart: unless-stopped`.

Everything else — `GEOIP_ENABLED`, `RESOLVE_HOSTNAMES`, alert
notifications, retention — is configured identically to the Docker
deployment; see the comments in `systemd/capture.env.example` and
`systemd/dashboard.env.example`.

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
