from typing import Callable, Optional, List, Dict
import threading
import socket

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
            sniff(
                iface=iface,
                filter=bpf_filter,
                prn=_proc,
                store=False,
                timeout=1,
                promisc=promisc,
            )
        except Exception as e:
            if err_cb:
                try:
                    err_cb(str(e))
                except Exception:
                    pass
            # Continue trying until stop requested
            continue
