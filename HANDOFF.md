# Handoff: continuing this project locally

This session ran in an isolated cloud sandbox with no route to your
desktop or your home network, so testing hit a hard wall: no real base
router traffic to capture, and container registry pulls (Docker Hub,
GHCR, MCR) were all blocked by the sandbox's network policy. This doc is
so a Claude Code session running *on your desktop* can pick up exactly
where this one left off, with full context.

Delete this file once you no longer need it — it's a handoff note, not
project documentation.

## Where things are

- **Repo**: `coramb2/network-traffic-analyzer`
- **Branch**: `claude/debug-security-homeserver-psteyj` (pushed, all work below is on it)
- **To resume**: `git clone`, `git checkout claude/debug-security-homeserver-psteyj`, then open Claude Code in the repo and paste this file's contents (or just point it at `HANDOFF.md`) as the first message.

## What's done (commits, oldest to newest)

1. **`acb3ae2` — Fix broken live dashboard and harden output-file handling**
   - Real bug: the terminal live dashboard (`analyzer.py`) embedded `rich`
     `Table` objects into an f-string, so it printed
     `<rich.table.Table object at 0x...>` instead of rendering the
     tables. Fixed with `rich.console.Group`.
   - A prior bot auto-fix had added `if ".." in filename: raise
     Exception(...)` guards on output paths, which don't stop absolute
     paths or symlink escapes, and one write site (`reporter.py`
     `export_to_json`) had no check at all. Replaced with `paths.py`'s
     `safe_output_path()`, which resolves the path and confirms it's
     contained in the cwd.
   - Reports (JSON/CSV/HTML/alerts) now written `0600` — they capture
     every device's IPs/ports/HTTP-host activity on the network and
     were previously world-readable.
   - `AnomalyDetector`'s per-IP tracking dicts (`ip_port_map`,
     `ip_connection_times`) now capped at `max_tracked_ips` (default
     10,000) with simple eviction, so a long-running capture can't grow
     memory unbounded.
   - No known CVEs found in pinned `scapy==2.5.0` / `rich==13.7.0`.
   - **Not fixed**: the HTML report loads Chart.js from
     `cdnjs.cloudflare.com` with no Subresource Integrity hash. I
     couldn't fetch the file to get a verified hash (network policy
     blocked it in the sandbox). Worth vendoring the JS file locally for
     an offline home-server deployment, or adding a verified SRI hash.

2. **`4778041` — Add Docker-based home-server deployment with scheduled captures**
   - You chose: Docker container, scheduled interval captures (not
     continuous, not systemd).
   - `Dockerfile`: grants `CAP_NET_RAW`/`CAP_NET_ADMIN` to the `python3`
     binary via `setcap` at build time, runs as a fixed non-root uid
     (10001) — so the container doesn't need `--privileged` or full root
     just to sniff packets.
   - `docker-compose.yml`: `network_mode: host` (bridge networking can't
     see real LAN traffic), `cap_drop: [ALL]` + `cap_add: [NET_RAW,
     NET_ADMIN]`, `mem_limit`/`pids_limit` to bound a runaway capture.
   - `docker/entrypoint.sh`: loops forever — captures for
     `CAPTURE_DURATION` seconds every `INTERVAL_SECONDS`, writes each
     run into its own `reports/<UTC timestamp>/` directory (avoids races
     between scheduled runs), maintains a `reports/latest` symlink,
     prunes run directories beyond `RETENTION_RUNS`.
   - `.env.example`, `.dockerignore`, README section explaining the
     above choices.
   - **Verified**: `docker-compose.yml` is syntactically valid
     (`docker compose config` resolves cleanly). The entrypoint's
     scheduling/rotation *logic* was verified by running the actual
     unmodified script directly against real generated loopback traffic
     (copied the `.py` files to `/app` to match the Dockerfile's layout,
     since I couldn't build the real image).
   - **Not verified**: the actual `docker build` succeeding, or that
     `setcap` + non-root + the capability set really lets packet capture
     work inside a real container. Registry pulls are blocked in this
     sandbox (tried `docker.io`, `mcr.microsoft.com`, `ghcr.io` — all
     denied at the storage-backend level by the sandbox's network
     policy). **This is the first thing to verify on your desktop.**

3. **`bb2ddd2` — Fix missing alert persistence and stale 'latest' symlink**
   Found by actually running the full scheduled-capture flow with
   synthetic traffic to RDP/SMB/MSSQL/VNC/Telnet ports:
   - `detector.py`: `SUSPICIOUS_PORT` and `LARGE_PACKET` alerts were
     computed and returned from `analyze_packet()` but never appended to
     `self.alerts` (unlike `PORT_SCAN` and `HIGH_CONNECTION_RATE`).
     Result: connections to vulnerable services and oversized UDP
     packets — core advertised detection features — silently never
     showed up in the alert count, `security_alerts.json`, or the HTML
     report. Fixed.
   - `docker/entrypoint.sh`: a capture cycle with zero packets leaves
     its run directory empty (`network_monitor.py` skips writing reports
     when nothing was captured), but the loop always repointed
     `reports/latest` at it anyway — so any quiet period left `latest`
     pointing at an empty directory instead of the last real report.
     Fixed: only repoints `latest` when the run actually produced
     output, prunes the empty directory otherwise.

4. **`cfff2f9` — Add live snapshot export for upcoming web dashboard**
   - `PacketAnalyzer.export_live_snapshot()` writes a small
     `live_status.json` (packet/protocol/IP/port counters,
     packets-per-second) roughly once a second during an active capture,
     separate from the full `export_to_json()` dump (which includes
     packet history and only happens once at the end).
   - **No consumer of this file exists yet** — this was prep for the
     dashboard work below, interrupted before the dashboard itself was
     built.

## In progress / not started: the web dashboard

You asked for a real interface — currently reports are static HTML
regenerated per scheduled run, no live view, not touch-friendly. You
said: **a mix of a live auto-updating dashboard and a nicer viewer for
past runs**, viewed on your computer for now, with a touchscreen tablet
as a possible future central display in the home.

Planned architecture (not yet built, this is where to pick up):

- **Keep the capture container as-is.** It already writes
  `live_status.json` (live counters, ~1/sec, added in `cfff2f9`) and, at
  the end of each run, the full `traffic_analysis.json` /
  `traffic_data.csv` / `traffic_report.html` / `security_alerts.json`
  into `reports/<timestamp>/`.
- **Add a second, separate, lightweight container**: a small Flask app
  (`webapp.py`) that mounts the same `reports/` volume **read-only** and
  serves:
  - `/` — a single dashboard page (responsive/touch-friendly from the
    start, since a tablet is the eventual target)
  - `/api/live` — reads the most recent run's `live_status.json` if its
    `updated_at` is recent (e.g. < 5s old, so a crashed process doesn't
    show as falsely "live" forever); otherwise falls back to the latest
    completed run's summary and reports status as idle/last-run
  - `/api/runs` — list of past run directories with summary stats, for
    a history browser
  - `/api/runs/<run_id>` — full detail for one run (drill into alerts,
    tables, etc.)
  - Frontend: poll `/api/live` every 1-2s (deliberately chose polling
    over websockets/SSE for v1 — much simpler and more robust, revisit
    only if polling proves too laggy). Reuse Chart.js like the existing
    HTML report for visual consistency.
- **Why a separate container from the capture one**: the dashboard needs
  zero packet-capture capabilities — no `NET_RAW`/`NET_ADMIN`, no host
  networking, just read access to `reports/` and one published port.
  Keeps the capture container's privilege footprint minimal and lets the
  dashboard be restarted/rebuilt independently.
- **Dockerfile split**: capture container's `Dockerfile` needs
  `scapy`/`tcpdump`/`libcap2-bin`; the dashboard needs none of that, just
  `flask`. Use a separate `Dockerfile.dashboard` with its own minimal
  `requirements-dashboard.txt` rather than bloating the capture image or
  giving the dashboard unnecessary packet-capture-adjacent dependencies.

Task list from this session (recreate with `TaskCreate`/check
`TaskList` if the tool carries over; otherwise just treat this as the
plan):

1. ~~Add live snapshot writing to `analyzer.py`~~ — done (`cfff2f9`)
2. Build the Flask web dashboard app (`webapp.py` + frontend) — **not started**
3. Wire the dashboard into `docker-compose.yml` as a separate service — **not started**
4. Test the dashboard end-to-end with real traffic and an actual browser
   (this sandbox has Playwright/Chromium available, in case that's true
   in your local environment too — worth using it for a visual check
   rather than only checking HTTP status codes) — **not started**

## Known open items (not urgent, but worth remembering)

- Chart.js loaded from CDN with no SRI hash (see item 1 above) —
  consider vendoring it, especially now that you're adding a dashboard
  that'll also want charting.
- A systemd-service deployment alternative (instead of Docker) was
  mentioned as an option but never requested or built.
- True *live* (per-packet, real-time) security alerts were explicitly
  scoped out of v1: today, `AnomalyDetector` only runs after a capture
  window ends, batch-processing all packets from that run. The live
  dashboard will show live traffic *stats* but alerts will only update
  once per `CAPTURE_DURATION` cycle (e.g., every 5 min), same as today.
  Making alerts truly live would mean running detection inline in
  `PacketAnalyzer.packet_callback()` instead of after the fact in
  `network_monitor.py` — a real architecture change, deliberately not
  taken on without discussing it with you first.
- The one thing this session could never validate: an actual `docker
  build` + `docker compose up` completing successfully, and packet
  capture actually working inside the resulting container (the
  `setcap`/non-root/capability approach is correct in theory and
  matches how this is normally done, but "in theory" is exactly what
  local testing should close out first).

## Suggested first steps on your desktop

```bash
git clone <repo-url>
cd network-traffic-analyzer
git checkout claude/debug-security-homeserver-psteyj

cp .env.example .env
# edit .env: set IFACE to your real interface (find it with `ip -brief link`)

mkdir -p reports && sudo chown -R 10001:10001 reports
docker compose up -d --build
docker compose logs -f
```

If the build or capture fails, that's the first real bug report this
project will get from outside a sandbox — worth debugging carefully
rather than assuming the Dockerfile is right just because it read
correctly.
