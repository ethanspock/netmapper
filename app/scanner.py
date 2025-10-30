import concurrent.futures
import ipaddress
import os
import platform
import re
import socket
import subprocess
from typing import Dict, Iterable, List, Optional, Tuple

try:
    import psutil  # type: ignore
except Exception:  # pragma: no cover - optional dependency at runtime
    psutil = None  # type: ignore


def _run(cmd: List[str]) -> str:
    try:
        out = subprocess.check_output(cmd, stderr=subprocess.STDOUT, text=True)
        return out
    except Exception:
        return ""


def get_local_ipv4_networks() -> List[ipaddress.IPv4Network]:
    nets: List[ipaddress.IPv4Network] = []
    # Prefer psutil for reliability
    if psutil:
        try:
            for ifname, addrs in psutil.net_if_addrs().items():
                for addr in addrs:
                    if getattr(addr, "family", None) == socket.AF_INET:
                        ip = addr.address
                        netmask = getattr(addr, "netmask", None) or ""
                        try:
                            if ip and _is_private_ipv4(ip) and netmask:
                                nets.append(ipaddress.ip_interface(f"{ip}/{netmask}").network)
                        except Exception:
                            continue
        except Exception:
            pass
    if nets:
        return _dedup_networks(nets)
    # Fallback: parse ipconfig/ifconfig output
    system = platform.system().lower()
    if system == "windows":
        text = _run(["ipconfig"])
        ip_re = re.compile(r"IPv4 Address[ .]*: ([0-9.]+)")
        mask_re = re.compile(r"Subnet Mask[ .]*: ([0-9.]+)")
        ips = ip_re.findall(text)
        masks = mask_re.findall(text)
        for ip, mask in zip(ips, masks):
            try:
                if _is_private_ipv4(ip):
                    nets.append(ipaddress.ip_interface(f"{ip}/{mask}").network)
            except Exception:
                continue
    else:
        text = _run(["ifconfig"]) or _run(["ip", "addr"])
        for m in re.finditer(r"inet (?:addr:)?([0-9.]+) .*?netmask (?:0x[0-9a-f]+|([0-9.]+))", text, re.I | re.S):
            ip = m.group(1)
            mask = m.group(2) or _cidr_to_netmask(_extract_cidr(text, ip))
            if not mask:
                continue
            try:
                if _is_private_ipv4(ip):
                    nets.append(ipaddress.ip_interface(f"{ip}/{mask}").network)
            except Exception:
                continue
    return _dedup_networks(nets)


def get_local_ipv4_networks_detailed() -> List[Dict[str, str]]:
    """Return a list of dicts with keys: ifname, ip, netmask, cidr"""
    out: List[Dict[str, str]] = []
    if psutil:
        try:
            for ifname, addrs in psutil.net_if_addrs().items():
                for addr in addrs:
                    if getattr(addr, "family", None) == socket.AF_INET:
                        ip = addr.address
                        netmask = getattr(addr, "netmask", None) or ""
                        try:
                            if ip and _is_private_ipv4(ip) and netmask:
                                cidr = str(ipaddress.ip_interface(f"{ip}/{netmask}").network)
                                out.append({"ifname": ifname, "ip": ip, "netmask": netmask, "cidr": cidr})
                        except Exception:
                            continue
        except Exception:
            pass
    # Dedup by cidr
    seen = set()
    deduped: List[Dict[str, str]] = []
    for item in out:
        if item["cidr"] not in seen:
            seen.add(item["cidr"])
            deduped.append(item)
    return deduped


def _dedup_networks(nets: Iterable[ipaddress.IPv4Network]) -> List[ipaddress.IPv4Network]:
    out: List[ipaddress.IPv4Network] = []
    for n in nets:
        if n not in out:
            out.append(n)
    return out


def _is_private_ipv4(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except Exception:
        return False


def _extract_cidr(text: str, ip: str) -> Optional[int]:
    m = re.search(fr"{re.escape(ip)}/(\d+)", text)
    if m:
        return int(m.group(1))
    return None


def _cidr_to_netmask(cidr: Optional[int]) -> Optional[str]:
    if cidr is None:
        return None
    try:
        return str(ipaddress.ip_network(f"0.0.0.0/{cidr}").netmask)
    except Exception:
        return None


def get_default_gateway() -> Optional[str]:
    system = platform.system().lower()
    if system == "windows":
        text = _run(["route", "print"])
        # Look for 0.0.0.0          0.0.0.0        GATEWAY_IP
        for line in text.splitlines():
            parts = line.split()
            if len(parts) >= 3 and parts[0] == "0.0.0.0" and parts[1] == "0.0.0.0":
                return parts[2]
    else:
        text = _run(["ip", "route"]) or _run(["route", "-n"])
        m = re.search(r"default via ([0-9.]+)", text)
        if m:
            return m.group(1)
    return None


def ping_ip(ip: str, timeout_ms: int = 300) -> Tuple[bool, Optional[float]]:
    system = platform.system().lower()
    if system == "windows":
        cmd = ["ping", "-n", "1", "-w", str(timeout_ms), ip]
        out = _run(cmd)
        alive = "TTL=" in out.upper()
        rtt = None
        m = re.search(r"time[=<]([0-9]+)ms", out, re.I)
        if m:
            rtt = float(m.group(1))
        return alive, rtt
    else:
        # -c 1 one packet, -W timeout in seconds
        timeout_s = max(1, int(round(timeout_ms / 1000.0)))
        cmd = ["ping", "-c", "1", "-W", str(timeout_s), ip]
        out = _run(cmd)
        alive = ", 0% packet loss" in out or "1 received" in out
        rtt = None
        m = re.search(r"time=([0-9.]+) ms", out)
        if m:
            rtt = float(m.group(1))
        return alive, rtt


def get_arp_table() -> Dict[str, str]:
    table: Dict[str, str] = {}
    system = platform.system().lower()
    out = _run(["arp", "-a"]) if system == "windows" else _run(["arp", "-n"])
    for line in out.splitlines():
        if system == "windows":
            m = re.search(r"\s([0-9.]+)\s+([0-9a-f\-]{17})\s+", line, re.I)
            if m:
                table[m.group(1)] = m.group(2).lower()
        else:
            m = re.search(r"([0-9.]+)\s+.*?(([0-9a-f]{2}:){5}[0-9a-f]{2})", line, re.I)
            if m:
                table[m.group(1)] = m.group(2).lower()
    return table


def resolve_hostname(ip: str) -> Optional[str]:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None


def scan_subnet(
    cidr: str,
    timeout_ms: int = 300,
    max_workers: int = 128,
    do_dns: bool = False,
    progress_cb: Optional[callable] = None,
    include_arp_only: bool = True,
) -> List[Dict[str, Optional[str]]]:
    network = ipaddress.ip_network(cidr, strict=False)
    targets = [str(ip) for ip in network.hosts()]
    total = len(targets)
    results: List[Dict[str, Optional[str]]] = []
    done = 0

    arp = get_arp_table()

    def _work(ip: str):
        alive, rtt = ping_ip(ip, timeout_ms=timeout_ms)
        hostname = resolve_hostname(ip) if (alive and do_dns) else None
        mac = arp.get(ip)
        return {
            "ip": ip,
            "alive": "yes" if alive else "no",
            "rtt_ms": f"{rtt:.0f}" if rtt is not None else None,
            "hostname": hostname,
            "mac": mac,
        }

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as ex:
        future_map = {ex.submit(_work, ip): ip for ip in targets}
        for fut in concurrent.futures.as_completed(future_map):
            res = fut.result()
            results.append(res)
            done += 1
            if progress_cb:
                try:
                    progress_cb(done, total)
                except Exception:
                    pass

    # sort: alive first, then by IP
    def _ip_key(rec):
        try:
            return (0 if rec["alive"] == "yes" else 1, ipaddress.ip_address(rec["ip"]))
        except Exception:
            return (1, rec["ip"])  # type: ignore

    # After scan, refresh ARP and include ARP-only neighbors if requested
    if include_arp_only:
        arp2 = get_arp_table()
        arp.update(arp2)
        by_ip: Dict[str, Dict[str, Optional[str]]] = {r["ip"]: r for r in results if r.get("ip")}
        for ip in targets:
            mac = arp.get(ip)
            if mac and (ip not in by_ip or by_ip[ip].get("alive") != "yes"):
                rec = by_ip.get(ip, {"ip": ip, "alive": "no", "rtt_ms": None, "hostname": None, "mac": None})
                rec.update({"alive": "yes", "mac": mac})
                by_ip[ip] = rec
        results = list(by_ip.values())

    results.sort(key=_ip_key)
    return results
