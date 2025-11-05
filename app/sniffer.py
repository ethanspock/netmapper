from typing import Callable, Optional, List, Dict
import threading
import socket
import platform

try:
    from scapy.all import sniff, IP, IPv6, TCP, UDP, get_if_list  # type: ignore
    try:
        from scapy.all import get_windows_if_list  # type: ignore
    except Exception:
        get_windows_if_list = None  # type: ignore
    try:
        # Some Scapy versions expose it here instead
        from scapy.arch.windows import get_windows_if_list as _gwif_arch  # type: ignore
        if get_windows_if_list is None:
            get_windows_if_list = _gwif_arch  # type: ignore
    except Exception:
        pass
except Exception:
    sniff = None  # type: ignore
    IP = None  # type: ignore
    IPv6 = None  # type: ignore
    TCP = None  # type: ignore
    UDP = None  # type: ignore
    get_if_list = None  # type: ignore
    get_windows_if_list = None  # type: ignore

try:
    import psutil  # type: ignore
except Exception:
    psutil = None  # type: ignore


def sniff_available() -> bool:
    return sniff is not None and get_if_list is not None


def get_capture_interfaces() -> List[str]:
    try:
        return list(get_if_list()) if get_if_list else []
    except Exception:
        return []


def get_capture_interfaces_detailed() -> List[Dict[str, str]]:
    """Return a list of interfaces for display and capture.

    Each item: {display: str, scapy: str}
    """
    items: List[Dict[str, str]] = []
    # Gather IPv4 addresses and up status via psutil for friendly display
    ipv4_by_if: Dict[str, List[str]] = {}
    isup_by_if: Dict[str, bool] = {}
    if psutil:
        try:
            for ifname, addrs in psutil.net_if_addrs().items():
                for a in addrs:
                    if getattr(a, "family", None) == socket.AF_INET and getattr(a, "address", None):
                        ipv4_by_if.setdefault(ifname, []).append(a.address)
            for ifname, st in psutil.net_if_stats().items():
                isup_by_if[ifname] = bool(getattr(st, "isup", False))
        except Exception:
            pass

    try:
        if get_windows_if_list:
            for it in get_windows_if_list():  # type: ignore
                cap_name = it.get("name") or ""
                friendly = (
                    it.get("win_name")
                    or it.get("friendly_name")
                    or it.get("friendlyname")
                    or it.get("description")
                    or cap_name
                )
                # Filter noisy loopback/virtual entries from default view
                disp = str(friendly)
                if "loopback" in disp.lower():
                    continue
                items.append({"display": disp, "scapy": cap_name, "friendly": disp, "ips": ", ".join(ipv4_by_if.get(disp) or [])})
        else:
            for name in get_if_list() or []:  # type: ignore
                items.append({"display": name, "scapy": name, "friendly": name, "ips": ", ".join(ipv4_by_if.get(name) or [])})
    except Exception:
        pass

    # Add Linux/Unix pcap "any" pseudo interface to listen on all (if not Windows)
    try:
        if platform.system().lower() != "windows":
            items.append({"display": "any (all interfaces)", "scapy": "any", "friendly": "any", "ips": ""})
    except Exception:
        pass

    # Sort: up interfaces first, then by display
    def sort_key(d: Dict[str, str]):
        friendly = d.get("friendly") or d.get("display") or ""
        up = isup_by_if.get(friendly, False)
        return (0 if up else 1, (d.get("ips") or "" == ""), friendly.lower())

    items.sort(key=sort_key)
    # Keep only display and scapy keys for UI mapping
    return [{"display": d["display"], "scapy": d["scapy"]} for d in items]


def sniff_packets(
    iface: Optional[str],
    bpf_filter: str,
    cb: Callable[[str, str], None],
    stop_event: threading.Event,
    *,
    err_cb: Optional[Callable[[str], None]] = None,
    promisc: bool = True,
):
    if not sniff_available():
        return

    def _proc(pkt):
        try:
            ip = None
            if IP is not None and pkt.haslayer(IP):
                ip = pkt[IP]
            elif IPv6 is not None and pkt.haslayer(IPv6):
                ip = pkt[IPv6]
            if ip is None:
                return
            src = ip.src
            dst = ip.dst
            if TCP is not None and pkt.haslayer(TCP):
                tp = pkt[TCP]
                cb(src, f"{tp.sport}/tcp")
                cb(dst, f"{tp.dport}/tcp")
            elif UDP is not None and pkt.haslayer(UDP):
                up = pkt[UDP]
                cb(src, f"{up.sport}/udp")
                cb(dst, f"{up.dport}/udp")
        except Exception:
            return

    while not stop_event.is_set():
        try:
            # On Windows, ensure Scapy uses pcap backend
            try:
                if platform.system().lower() == "windows":
                    from scapy.config import conf  # type: ignore
                    conf.use_pcap = True  # type: ignore
                    try:
                        conf.sniff_promisc = promisc  # type: ignore
                    except Exception:
                        pass
            except Exception:
                pass
            sniff(
                iface=iface,
                filter=(bpf_filter or None),
                prn=_proc,
                store=False,
                timeout=1,
                promisc=promisc,
            )
        except Exception as e:
            # If filter failed (e.g., libpcap missing), retry without filter
            try:
                msg = str(e)
            except Exception:
                msg = ""
            if err_cb:
                try:
                    err_cb(str(e))
                except Exception:
                    pass
            try:
                sniff(
                    iface=iface,
                    prn=_proc,
                    store=False,
                    timeout=1,
                    promisc=promisc,
                )
            except Exception:
                pass
            # Continue trying until stop requested
            continue


# ---- tcpdump backend as an alternative on Unix-like systems ----
import shutil
import subprocess
import re


def tcpdump_available() -> bool:
    return shutil.which("tcpdump") is not None


def run_tcpdump(
    iface: Optional[str],
    bpf_filter: str,
    cb: Callable[[str, str], None],
    stop_event: threading.Event,
    *,
    err_cb: Optional[Callable[[str], None]] = None,
    line_cb: Optional[Callable[[str], None]] = None,
):
    if not tcpdump_available():
        if err_cb:
            err_cb("tcpdump not found")
        return
    cmd = ["tcpdump", "-nn", "-l"]
    if iface:
        cmd += ["-i", iface]
    if bpf_filter:
        cmd += [bpf_filter]
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1)
    except Exception as e:
        if err_cb:
            err_cb(str(e))
        return

    def _reader():
        try:
            if not proc.stdout:
                return
            for line in proc.stdout:
                if stop_event.is_set():
                    break
                try:
                    if line_cb:
                        try:
                            line_cb(line.rstrip())
                        except Exception:
                            pass
                    m = re.search(r"\bIP6?\s+([^\s>]+)\s*>\s*([^\s:]+)", line)
                    if not m:
                        continue
                    a = m.group(1)
                    b = m.group(2)
                    proto = "udp" if (" UDP" in line) else ("tcp" if (" TCP" in line or " Flags [" in line) else "")
                    def _extract(addr: str):
                        if re.match(r"^\d+\.\d+\.\d+\.\d+\.\d+$", addr):
                            host, port = addr.rsplit(".", 1)
                            suffix = f"/{proto}" if proto else ""
                            return host, port + suffix
                        return addr, f"/{proto}" if proto else ""
                    src_ip, src_p = _extract(a)
                    dst_ip, dst_p = _extract(b)
                    if src_ip:
                        cb(src_ip, src_p)
                    if dst_ip:
                        cb(dst_ip, dst_p)
                except Exception:
                    continue
        finally:
            try:
                proc.terminate()
            except Exception:
                pass

    t = threading.Thread(target=_reader, daemon=True)
    t.start()
    while not stop_event.is_set():
        if proc.poll() is not None:
            break
        stop_event.wait(0.2)
    try:
        proc.terminate()
    except Exception:
        pass
