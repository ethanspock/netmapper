from __future__ import annotations

from typing import Dict, Optional, Tuple


def _norm(s: Optional[str]) -> str:
    return (s or "").strip().lower()


def _mac_prefix(mac: Optional[str]) -> Optional[str]:
    if not mac:
        return None
    m = mac.replace("-", ":").lower()
    parts = m.split(":")
    if len(parts) >= 3:
        return ":".join(parts[:3])
    return None


def classify_device(host: Dict[str, Optional[str]], gateway_ip: Optional[str] = None) -> str:
    """Return a device type string based on hostname/MAC/IP heuristics.

    Types: network, gateway, router, switch, ap, server, printer, camera, nas,
           firewall, pc, vm, unknown
    """
    ip = _norm(host.get("ip"))
    hostname = _norm(host.get("hostname"))
    mac = _norm(host.get("mac"))

    if gateway_ip and ip == _norm(gateway_ip):
        return "gateway"

    # Hostname cues
    hn = hostname
    if hn:
        if any(k in hn for k in ("router", "rtr", "edge", "gateway", "gw")):
            return "router"
        if any(k in hn for k in ("switch", "sw", "catalyst", "nexus", "arista", "procurve", "icx")):
            return "switch"
        if any(k in hn for k in ("ap", "wlan", "wlc", "wifi", "unifi", "meraki", "aruba")):
            return "ap"
        if any(k in hn for k in ("printer", "prn", "hp-")):
            return "printer"
        if any(k in hn for k in ("cam", "camera", "hik", "axis", "dahua")):
            return "camera"
        if any(k in hn for k in ("nas", "synology", "qnap")):
            return "nas"
        if any(k in hn for k in ("pfsense", "opnsense", "forti", "pan-", "palo", "asa")):
            return "firewall"
        if any(k in hn for k in ("srv", "server", "dc", "sql", "web", "file", "esxi", "hyperv")):
            return "server"

    # MAC OUI hints (very small, common cases)
    prefix = _mac_prefix(mac)
    if prefix in {
        "3c:fd:fe",  # Ubiquiti
        "b4:fb:e4",  # Ubiquiti
        "24:a4:3c",  # Ubiquiti
    }:
        return "ap"
    if prefix in {
        "f0:9f:c2",  # HPE Aruba
        "18:64:72",  # HPE Aruba
    }:
        return "ap"
    if prefix in {
        "d0:73:d5",  # Cisco Meraki
        "64:70:02",  # Cisco
    }:
        return "switch"
    if prefix in {
        "00:50:56",  # VMware
        "00:1c:14",  # VMware
        "00:05:69",  # VMware
        "00:1c:42",  # Parallels
    }:
        return "vm"

    # IP-based hints
    if ip.endswith(".1") or ip.endswith(".254"):
        return "router"

    return "pc"


def icon_style_for_type(tp: str) -> Tuple[str, str, int]:
    """Return (shape, color, size) for a device type."""
    mapping = {
        "network": ("h", "#5b8ff9", 1100),
        "gateway": ("^", "#f6bd16", 900),
        "router": ("^", "#f6903d", 850),
        "switch": ("s", "#5b8ff9", 750),
        "ap": ("v", "#36cfc9", 650),
        "server": ("p", "#9254de", 700),
        "printer": ("d", "#8c8c8c", 600),
        "camera": ("8", "#595959", 600),
        "nas": ("d", "#13c2c2", 650),
        "firewall": (">", "#ff7875", 800),
        "vm": ("o", "#69c0ff", 500),
        "pc": ("o", "#5ad8a6", 500),
        "unknown": ("o", "#bfbfbf", 480),
    }
    return mapping.get(tp, mapping["unknown"])

