import shutil
import subprocess
import xml.etree.ElementTree as ET
from typing import Dict, List, Tuple


def nmap_available() -> bool:
    return shutil.which("nmap") is not None


def run_nmap_xml(targets: List[str], options: str, ports: str, timeout: int = 300) -> Dict[str, List[Tuple[str, str]]]:
    """Run nmap and return mapping ip -> list of (port/proto, service) tuples.

    - options: free-form options, e.g., "-sV -T4 -Pn"
    - ports: e.g., "80,443,445,3389" or "1-1024"
    """
    if not nmap_available() or not targets:
        return {}
    cmd = ["nmap"] + options.split() + ["-p", ports, "-oX", "-"] + targets
    try:
        out = subprocess.check_output(cmd, stderr=subprocess.STDOUT, text=True, timeout=timeout)
    except Exception:
        return {}
    try:
        root = ET.fromstring(out)
    except Exception:
        return {}
    results: Dict[str, List[Tuple[str, str]]] = {}
    for host in root.findall("host"):
        addr_el = host.find("address[@addrtype='ipv4']")
        if addr_el is None:
            continue
        ip = addr_el.get("addr") or ""
        ports_el = host.find("ports")
        items: List[Tuple[str, str]] = []
        if ports_el is not None:
            for p in ports_el.findall("port"):
                state = p.find("state")
                if state is None or state.get("state") != "open":
                    continue
                portid = p.get("portid") or "?"
                proto = p.get("protocol") or "tcp"
                service_el = p.find("service")
                svc = service_el.get("name") if service_el is not None else "open"
                items.append((f"{portid}/{proto}", svc))
        if items:
            results[ip] = items
    return results

