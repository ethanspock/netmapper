from __future__ import annotations

from typing import Dict, Iterable, Set
import os
import re

try:
    # Scapy is optional at runtime but recommended
    from scapy.utils import RawPcapReader  # type: ignore
    try:
        from scapy.utils import RawPcapNgReader  # type: ignore
    except Exception:  # older scapy versions
        RawPcapNgReader = None  # type: ignore
    from scapy.layers.l2 import Ether  # type: ignore
    from scapy.layers.inet import IP, TCP, UDP  # type: ignore
    try:
        from scapy.layers.inet6 import IPv6  # type: ignore
    except Exception:
        IPv6 = None  # type: ignore
    try:
        from scapy.layers.l2 import ARP  # type: ignore
    except Exception:
        ARP = None  # type: ignore
except Exception:
    RawPcapReader = None  # type: ignore
    RawPcapNgReader = None  # type: ignore
    Ether = None  # type: ignore
    IP = TCP = UDP = IPv6 = ARP = None  # type: ignore


def parse_capture(path: str) -> Dict[str, Set[str]]:
    """Parse a capture file (pcap/pcapng or tcpdump text) and return ip -> set of ports.

    Ports are strings like "80/tcp", "53/udp", or "arp".
    """
    ext = os.path.splitext(path)[1].lower()
    if ext in {".pcap", ".pcapng"}:
        return _parse_pcap(path, is_pcapng=(ext == ".pcapng"))
    # Fallback: parse as tcpdump/wireshark text
    return _parse_tcpdump_text(path)


def _parse_pcap(path: str, *, is_pcapng: bool = False) -> Dict[str, Set[str]]:
    out: Dict[str, Set[str]] = {}
    if RawPcapReader is None:
        return out
    reader = None
    try:
        if is_pcapng and RawPcapNgReader is not None:
            reader = RawPcapNgReader(path)
        else:
            reader = RawPcapReader(path)
        for pkt_data, _ in reader:
            try:
                if Ether is None:
                    continue
                eth = Ether(pkt_data)
                # ARP
                if ARP is not None and eth.haslayer(ARP):
                    a = eth[ARP]
                    for ip in filter(None, [getattr(a, "psrc", None), getattr(a, "pdst", None)]):
                        out.setdefault(str(ip), set()).add("arp")
                    continue
                # IPv4/IPv6
                ip_layer = None
                if eth.haslayer(IP):
                    ip_layer = eth[IP]
                elif IPv6 is not None and eth.haslayer(IPv6):
                    ip_layer = eth[IPv6]
                if ip_layer is None:
                    continue
                src = str(getattr(ip_layer, "src", "") or "")
                dst = str(getattr(ip_layer, "dst", "") or "")
                if eth.haslayer(TCP):
                    tp = eth[TCP]
                    if getattr(tp, "sport", None) is not None:
                        out.setdefault(src, set()).add(f"{int(tp.sport)}/tcp")
                    if getattr(tp, "dport", None) is not None:
                        out.setdefault(dst, set()).add(f"{int(tp.dport)}/tcp")
                elif eth.haslayer(UDP):
                    up = eth[UDP]
                    if getattr(up, "sport", None) is not None:
                        out.setdefault(src, set()).add(f"{int(up.sport)}/udp")
                    if getattr(up, "dport", None) is not None:
                        out.setdefault(dst, set()).add(f"{int(up.dport)}/udp")
            except Exception:
                continue
    except Exception:
        return out
    finally:
        try:
            if reader is not None:
                reader.close()
        except Exception:
            pass
    return out


def _parse_tcpdump_text(path: str) -> Dict[str, Set[str]]:
    out: Dict[str, Set[str]] = {}
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                # ARP request/reply
                if "ARP" in line:
                    m_req = re.search(r"who-has\s+(\d+\.\d+\.\d+\.\d+)\s+tell\s+(\d+\.\d+\.\d+\.\d+)", line)
                    if m_req:
                        out.setdefault(m_req.group(1), set()).add("arp")
                        out.setdefault(m_req.group(2), set()).add("arp")
                        continue
                    m_rep = re.search(r"ARP,\s+Reply\s+(\d+\.\d+\.\d+\.\d+)\s+", line)
                    if m_rep:
                        out.setdefault(m_rep.group(1), set()).add("arp")
                        continue
                # IP/IPv6 flows
                m = re.search(r"\bIP6?\s+([^\s>]+)\s*>\s*([^\s:]+)", line)
                if not m:
                    continue
                a, b = m.group(1), m.group(2)
                proto = "udp" if (" UDP" in line) else ("tcp" if (" TCP" in line or " Flags [" in line) else "")
                def _extract(addr: str):
                    if re.match(r"^\d+\.\d+\.\d+\.\d+\.\d+$", addr):
                        host, port = addr.rsplit(".", 1)
                        return host, (f"{port}/{proto}" if proto else port)
                    return addr, (f"/{proto}" if proto else "")
                src_ip, src_p = _extract(a)
                dst_ip, dst_p = _extract(b)
                if src_ip:
                    out.setdefault(src_ip, set()).add(src_p or (proto if proto else ""))
                if dst_ip:
                    out.setdefault(dst_ip, set()).add(dst_p or (proto if proto else ""))
    except Exception:
        return out
    return out

