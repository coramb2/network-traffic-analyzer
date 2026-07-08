FROM python:3.11-slim

# tcpdump: scapy shells out to it to compile BPF filter strings on Linux
# libcap2-bin: provides setcap, used below to grant packet-capture
#   capabilities to python3 without running the whole process as root
RUN apt-get update && apt-get install -y --no-install-recommends \
        tcpdump \
        libcap2-bin \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY analyzer.py detector.py reporter.py network_monitor.py paths.py alert_rules.py alert_playbooks.py device_names.py notifications.py ./
COPY docker/entrypoint.sh /entrypoint.sh

# Grant CAP_NET_RAW/CAP_NET_ADMIN on the python3 binary itself so the
# capture loop can sniff packets while running as a non-root user, instead
# of needing the whole container to run as root/--privileged.
RUN chmod +x /entrypoint.sh \
    && setcap cap_net_raw,cap_net_admin=eip "$(readlink -f "$(command -v python3)")" \
    && useradd --uid 10001 --gid 0 --no-create-home --shell /usr/sbin/nologin analyzer \
    && mkdir -p /data/reports \
    && chown -R analyzer:0 /data/reports \
    && chmod -R 0770 /data/reports

USER analyzer
ENTRYPOINT ["/entrypoint.sh"]
