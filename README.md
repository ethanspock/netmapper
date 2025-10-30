NetMapper – Auto Network Mapping (MVP)

Overview

- Scans an IPv4 subnet (CIDR) using OS ping for host discovery.
- Pulls MAC addresses from the ARP cache to enrich results.
- Builds a simple topology: subnet → gateway → alive hosts.
- Visualizes the graph with networkx + matplotlib embedded in Tkinter.

Setup

- Requires Python 3.9+.
- Install dependencies:
  - `pip install -r netmapper_gui/requirements.txt`

Run

- `python netmapper_gui/app.py`
- Click “Use Local” to auto-fill your first private IPv4 subnet.
- Optionally enable “Reverse DNS” to attempt hostnames.
- Click “Scan” to discover hosts and render the map.

Notes

- Windows: scanning uses `ping`, `arp -a`, and `route print` under the hood.
- Reverse DNS can be slow if PTR records are missing; leave off for speed.
- ARP cache only reflects local L2 segment; MACs may be missing for remote subnets.
- You do not need admin for ping/arp on Windows.

Roadmap Ideas

- Add Nmap integration for richer port/service detection.
- SNMP (and LLDP/CDP) to infer real L2/L3 links.
- Local ARP sweep or Scapy (requires admin/raw sockets) for deeper discovery.
- Export results to JSON/CSV and save graph images.
- Filter by alive/RTT and subnet presets per interface.

