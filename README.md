# NetMapper – Auto Network Mapping
![Alt Text](app/logo/netmapper_icon.png)

## Overview

- Discover hosts on IPv4 subnets via ping and ARP cache enrichment.
- Visual map: Subnet → Gateway/Router → Hosts with device-type icons.
- Host table with IP/Alive/RTT/Hostname/MAC/Open Ports.
- Optional Nmap scanning and Passive Listener (Scapy or tcpdump backend) to observe live ports.
- Save/Load layouts per subnet, Dark/Light mode, zoom/pan, PNG/CSV/JSON export.

## Install and Run

### Linux

```bash
git clone 
# From this folder
bash linux-install.sh
python3 app.py
```

### Windows

```powershell
# From this folder in an elevated PowerShell
./windows-install.ps1
. .\.venv\Scripts\Activate.ps1
python app.py
```

### Manual (if you prefer)

- Windows: `pip install -r requirements-windows.txt`
- Linux: `pip install -r requirements-linux.txt`

## Pages

- Home: Subnet/interface, Reverse DNS, Include ARP-only, Dark Mode, Nmap options, Passive Listener controls.
- Map: Network diagram; drag nodes, zoom/pan, export, Save/Load Layout.
- Table: Host list and merged ports (Nmap + passive).

## Scanning

- Use Local fills a private IPv4 subnet from your NICs.
- Include ARP-only shows hosts seen in ARP even if they drop ICMP.
- Reverse DNS resolves hostnames; on Linux install avahi-utils and dnsutils for best results.

## Nmap

- Enable “Use Nmap”, set Options (e.g., `-sV -T4 -Pn`) and Ports (e.g., `80,443,445,3389`).
- “Alive only” scans only hosts marked alive; uncheck to scan all discovered IPs.
- Results appear in the Table’s Open Ports column and in JSON export.

## Passive Listener

- Interfaces: on Linux, prefer “any (all interfaces)” for broad capture.
- Backend: tcpdump backend (default on Linux if installed) or Scapy.
- Protocols: dropdown of BPF presets (editable for custom filters).
- Test Capture: 2‑second no‑filter probe to validate the interface/permissions.

## Export & Layout

- PNG/CSV/JSON from Map page. JSON includes positions and port results.
- Save Layout stores node positions; auto-loads per subnet from `netmapper_gui/layouts/<subnet>.layout.json`.

## Troubleshooting

- Linux/Kali
  - Confirm: `sudo tcpdump -i any -nn -c 10`
  - Run app with sudo, or grant caps: `sudo setcap cap_net_raw,cap_net_admin=eip $(readlink -f $(which python3))`
  - Select “any (all interfaces)” + “No filter” then Test Capture.
  - If Wi‑Fi is in monitor mode, switch to managed interface (wlan0) or use `any`.
- Windows
  - Install Npcap (WinPcap-compatible) and run as Administrator.
  - Pick “Ethernet”/“Wi‑Fi”; try “All TCP/UDP” or “No filter”; Test Capture.

## Device Icons (Heuristic)

- Network: hexagon, blue; Gateway: triangle‑up, gold; Router: triangle‑up, orange
- Switch: square, blue; AP: triangle‑down, teal; Server: pentagon, purple
- NAS: diamond, cyan; Printer: diamond, gray; Camera: octagon, dark gray
- VM: circle, light blue; PC/Unknown: circle, green/gray

## Notes

- ARP cache reflects only local L2; remote subnets may lack MACs.
- Reverse DNS may be slow; disable for speed or install helpers.
- Topology is heuristic; SNMP/LLDP integration would improve accuracy.

## Safety

Only scan/capture on networks you are authorized to assess.
