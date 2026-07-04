#!/usr/bin/env python3
"""
Per-alert-type playbooks and firewall-rule suggestions for the dashboard's
alert detail view.

Playbooks are static, home-network-practical guidance (what an alert type
means, benign vs. concerning signs, and steps to investigate/fix). Firewall
suggestions are generated per-alert (they need the actual IP/port) and are
strictly informational - commands are shown for the user to copy and run
themselves, never executed by this tool.
"""

PLAYBOOKS = {
    "PORT_SCAN": {
        "title": "Port Scan",
        "what": (
            "A single source IP connected to an unusually large number of "
            "different destination ports in a short window - the classic "
            "signature of someone (or something) probing for open services."
        ),
        "benign": (
            "Your own vulnerability scanner (Nessus, nmap you ran yourself), "
            "a network monitoring tool, or a device doing service discovery "
            "(some NAS/media servers probe a range of ports on startup)."
        ),
        "concerning": (
            "An unfamiliar device on your network, or a source IP outside "
            "your LAN, scanning your hosts - especially if followed by "
            "connection attempts to whatever ports responded."
        ),
        "steps": [
            "Identify the source IP - is it a device you recognize? Check the Devices panel.",
            "If it's your own machine/tool, allowlist this alert type for that IP.",
            "If it's unfamiliar and on your LAN, physically locate the device and check what's running on it.",
            "If it's from outside your LAN, consider blocking it at your router/firewall (see suggestions below).",
            "Check whether any of the scanned ports are actually open and exposed - close ones you don't need.",
        ],
    },
    "HIGH_CONNECTION_RATE": {
        "title": "High Connection Rate",
        "what": (
            "One source IP opened an unusually high number of connections "
            "per second - could be a busy legitimate service, or a scripted "
            "tool hammering your network."
        ),
        "benign": (
            "A backup job, sync client, or media server making many rapid "
            "connections; a browser or app doing bulk downloads/streaming."
        ),
        "concerning": (
            "A compromised device on your network participating in a botnet "
            "or scanning/brute-forcing outward; an external IP flooding a "
            "service you expose."
        ),
        "steps": [
            "Check what device the source IP belongs to and what it should normally be doing.",
            "If it's a known noisy service (backups, sync), allowlist it.",
            "If unknown, check the device for malware or unexpected processes.",
            "If the source is external and hitting a port you expose, consider rate-limiting or blocking it.",
        ],
    },
    "SUSPICIOUS_PORT": {
        "title": "Suspicious Port Access",
        "what": (
            "A connection was made to a port associated with a service that "
            "commonly has known vulnerabilities or shouldn't be reachable "
            "from outside a trusted zone (RDP, SMB, Telnet, VNC, etc.)."
        ),
        "benign": (
            "You intentionally run that service (e.g. RDP to your own PC, "
            "SMB file sharing between your own devices) and the source is a "
            "device you trust."
        ),
        "concerning": (
            "The source IP is unfamiliar or external, or you don't recall "
            "intentionally running that service on the destination host."
        ),
        "steps": [
            "Confirm whether the destination host is actually supposed to run that service.",
            "If it's expected traffic between your own devices, allowlist it.",
            "If the service isn't needed, disable it on the destination host.",
            "If it must stay on, restrict access to it at your firewall/router to only trusted source IPs.",
            "Never expose services like RDP/SMB/VNC/Telnet directly to the public internet - use a VPN instead.",
        ],
    },
    "LARGE_PACKET": {
        "title": "Large UDP Packet",
        "what": (
            "A UDP packet close to the network's maximum size was seen - "
            "worth a look because large UDP payloads can carry bulk data "
            "(potential exfiltration) or be part of certain amplification "
            "techniques, though most large UDP traffic is completely normal."
        ),
        "benign": (
            "Streaming media, VoIP, game traffic, DNS over UDP with large "
            "responses (EDNS), or file-sync protocols that use UDP."
        ),
        "concerning": (
            "Large UDP bursts to an unfamiliar external IP with no obvious "
            "streaming/gaming app running, especially from a device that "
            "doesn't normally send much outbound traffic."
        ),
        "steps": [
            "Identify what application on the source device generated this traffic.",
            "If it matches known streaming/gaming/VoIP usage, no action needed.",
            "If the source device shouldn't be sending bulk data, investigate it for compromise.",
            "If it's recurring and unexplained, consider blocking the destination IP.",
        ],
    },
    "UNUSUAL_PROTOCOL_RATIO": {
        "title": "Unusual Protocol Ratio",
        "what": (
            "ICMP (ping/traceroute-style) traffic made up an unusually high "
            "share of overall traffic in this run - normal networks are "
            "mostly TCP/UDP, so a spike in ICMP stands out."
        ),
        "benign": (
            "Someone running network diagnostics (ping, traceroute, MTU "
            "discovery) or a monitoring tool that pings devices frequently."
        ),
        "concerning": (
            "ICMP flood/sweep activity, which can be a reconnaissance "
            "technique (ping sweep to find live hosts) or a low-effort "
            "denial-of-service attempt."
        ),
        "steps": [
            "Check if you or a monitoring tool were actively running ping/traceroute during this window.",
            "If expected, no action needed - this is a low-severity, informational alert.",
            "If unexplained and recurring, look at which IPs are the source of the ICMP traffic.",
            "Consider rate-limiting ICMP at your router if it becomes a recurring nuisance.",
        ],
    },
    "PRIVATE_TO_PUBLIC": {
        "title": "Private IP to Public IP",
        "what": (
            "A device on your private network (RFC1918 address) talked "
            "directly to a public IP outside the common DNS resolvers - "
            "flagged because it's a broad, low-severity signal, not because "
            "it's inherently unusual (nearly all internet use looks like this)."
        ),
        "benign": (
            "Completely normal internet browsing, app traffic, updates, or "
            "cloud service usage from any device on your network."
        ),
        "concerning": (
            "Only worth a second look if the source device shouldn't have "
            "internet access at all (e.g. an IoT device you isolated), or "
            "the destination IP is known-bad."
        ),
        "steps": [
            "Check whether the source device is expected to reach the internet.",
            "If it's an IoT/smart-home device that shouldn't need internet access, consider isolating it on a separate VLAN/guest network.",
            "Look up the destination IP's reputation if the device's behavior seems otherwise abnormal.",
            "Otherwise, this is expected traffic and needs no action.",
        ],
    },
}


def get_playbook(alert_type):
    return PLAYBOOKS.get(alert_type)


def firewall_suggestions(alert):
    """Build a list of {label, command} firewall snippets for actionable
    alerts (those with a source_ip and/or destination_port). Purely
    informational - the user copies and runs these themselves; nothing here
    is ever executed by this tool.
    """
    source_ip = alert.get("source_ip")
    dest_port = alert.get("destination_port")

    if not source_ip and not dest_port:
        return []

    suggestions = []

    if source_ip:
        suggestions.append({
            "label": "ufw - block this source IP",
            "command": f"sudo ufw deny from {source_ip}",
        })
        suggestions.append({
            "label": "iptables - block this source IP",
            "command": f"sudo iptables -A INPUT -s {source_ip} -j DROP",
        })
        suggestions.append({
            "label": "nftables - block this source IP",
            "command": f"sudo nft add rule inet filter input ip saddr {source_ip} drop",
        })

    if dest_port:
        suggestions.append({
            "label": f"ufw - block inbound to port {dest_port}",
            "command": f"sudo ufw deny in to any port {dest_port}",
        })
        suggestions.append({
            "label": f"iptables - block inbound to port {dest_port}",
            "command": f"sudo iptables -A INPUT -p tcp --dport {dest_port} -j DROP",
        })
        suggestions.append({
            "label": f"nftables - block inbound to port {dest_port}",
            "command": f"sudo nft add rule inet filter input tcp dport {dest_port} drop",
        })

    if source_ip and dest_port:
        suggestions.append({
            "label": f"ufw - block this IP for port {dest_port} only",
            "command": f"sudo ufw deny from {source_ip} to any port {dest_port}",
        })

    plain_english = "On your router: "
    if source_ip and dest_port:
        plain_english += (
            f"add a firewall/access-control rule blocking {source_ip} "
            f"from reaching port {dest_port}, or block the device entirely "
            f"if it's not one of yours."
        )
    elif source_ip:
        plain_english += (
            f"add {source_ip} to a blocklist or access-control rule so it "
            f"can no longer reach your network."
        )
    else:
        plain_english += (
            f"close or restrict port {dest_port} in your router's port-forwarding "
            f"/ firewall settings so it isn't reachable from outside your LAN."
        )

    suggestions.append({"label": "Plain English", "command": plain_english})

    return suggestions
