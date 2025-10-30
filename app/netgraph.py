from typing import Dict, List, Optional, Tuple, Callable, Any

import matplotlib.pyplot as plt
import networkx as nx

from device_classifier import classify_device, icon_style_for_type
import ipaddress
import math


def build_graph(
    subnet_cidr: str,
    hosts: List[Dict[str, Optional[str]]],
    gateway_ip: Optional[str] = None,
) -> nx.Graph:
    g = nx.DiGraph()

    net_node = f"network:{subnet_cidr}"
    g.add_node(net_node, label=subnet_cidr, kind="network", type="network")

    gw_node = None
    if gateway_ip:
        gw_node = f"gw:{gateway_ip}"
        g.add_node(gw_node, label=f"GW\n{gateway_ip}", kind="gateway", type="gateway")
        g.add_edge(net_node, gw_node)

    # Identify router-like devices from hosts (router/gateway/firewall)
    router_ips: List[str] = []
    if gateway_ip:
        router_ips.append(gateway_ip)

    prelim_nodes: List[Tuple[str, Dict[str, Optional[str]], str]] = []  # (node_id, host, dtype)
    for h in hosts:
        if h.get("alive") != "yes":
            continue
        ip = h.get("ip") or "?"
        dtype = classify_device(h, gateway_ip=gateway_ip)
        node_id = f"host:{ip}"
        prelim_nodes.append((node_id, h, dtype))
        if dtype in ("router", "firewall") and ip not in router_ips:
            router_ips.append(ip)

    # Add router nodes first under network
    for node_id, h, dtype in prelim_nodes:
        ip = h.get("ip") or "?"
        if dtype in ("router", "firewall"):
            g.add_node(
                node_id,
                label=((h.get("hostname") or "") + f"\n{ip}") if h.get("hostname") else ip,
                ip=ip,
                mac=h.get("mac"),
                rtt=h.get("rtt_ms"),
                kind="host",
                type=dtype,
            )
            parent = gw_node or net_node
            g.add_edge(parent, node_id)

    # Then add non-router hosts and attach to closest router (same /24, /16), else GW, else network
    for node_id, h, dtype in prelim_nodes:
        if dtype in ("router", "firewall"):
            continue
        ip = h.get("ip") or "?"
        hn = h.get("hostname")
        label = f"{hn}\n{ip}" if hn else ip
        g.add_node(
            node_id,
            label=label,
            ip=ip,
            mac=h.get("mac"),
            rtt=h.get("rtt_ms"),
            kind="host",
            type=dtype,
        )
        parent_router = _choose_parent_router(ip, router_ips, gateway_ip)
        if parent_router:
            parent = f"host:{parent_router}" if parent_router != gateway_ip else (gw_node or net_node)
        else:
            parent = gw_node or net_node
        g.add_edge(parent, node_id)

    return g


def _tree_layout(g: nx.DiGraph) -> Dict[str, Tuple[float, float]]:
    # Three layers: network -> routers/gateway -> hosts grouped under their parent
    levels: Dict[str, int] = {}
    for n, data in g.nodes(data=True):
        tp = data.get("type") or data.get("kind")
        if tp == "network":
            levels[n] = 0
        elif tp in ("gateway", "router"):
            levels[n] = 1
        else:
            levels[n] = 2

    # Group bottom hosts by their direct parent (incoming edge source)
    bottom_nodes = [n for n, lvl in levels.items() if lvl == 2]
    parent_groups: Dict[str, List[str]] = {}
    for n in bottom_nodes:
        preds = list(g.predecessors(n))
        parent = preds[0] if preds else None
        parent_groups.setdefault(parent or "", []).append(n)

    # Deterministic ordering
    for k in list(parent_groups.keys()):
        parent_groups[k].sort(key=lambda x: g.nodes[x].get("ip") or g.nodes[x].get("label") or x)

    # Assign x positions, allocating a block per mid node
    pos: Dict[str, Tuple[float, float]] = {}

    # Top levels centered
    top_nodes = [n for n, lvl in levels.items() if lvl == 0]
    mid_nodes = [n for n, lvl in levels.items() if lvl == 1]
    pos_y = {0: 0.92, 1: 0.65, 2: 0.18}

    def _place_row(nodes: List[str], y: float):
        if not nodes:
            return
        spacing = 1.0 / (len(nodes) + 1)
        for i, n in enumerate(nodes, start=1):
            pos[n] = (i * spacing, y)

    _place_row(top_nodes, pos_y[0])
    _place_row(mid_nodes, pos_y[1])

    # For bottom, allocate a block under each mid-level parent
    total_groups = max(1, len(mid_nodes))
    block_w = 1.0 / total_groups
    for gi, parent in enumerate(mid_nodes):
        nodes = parent_groups.get(parent, [])
        if not nodes:
            continue
        left = gi * block_w
        spacing = block_w / (len(nodes) + 1)
        for i, n in enumerate(nodes, start=1):
            x = left + i * spacing
            pos[n] = (x, pos_y[2])

    # Any unplaced bottom nodes (no parent mid-node) distribute across width
    if any(n not in pos for n in bottom_nodes):
        remaining = [n for n in bottom_nodes if n not in pos]
        spacing = 1.0 / (len(remaining) + 1)
        for i, n in enumerate(remaining, start=1):
            pos[n] = (i * spacing, pos_y[2])

    return pos


def draw_graph(g: nx.DiGraph, figsize=(10.5, 6.0)) -> Dict[str, Any]:
    fig, ax = plt.subplots(figsize=figsize)
    ax.axis("off")

    pos = _tree_layout(g)
    pos = _resolve_overlaps(pos, same_row_only=True, min_dist=0.04, iterations=40)

    def _render(ax, pos):
        ax.clear()
        ax.axis("off")
        # Edges
        nx.draw_networkx_edges(g, pos, ax=ax, width=1.2, edge_color="#888")
        # Labels with background for readability
        labels = {n: (data.get("label") or n) for n, data in g.nodes(data=True)}
        # Draw nodes by type with distinct shapes
        typed: Dict[str, List[str]] = {}
        for n, data in g.nodes(data=True):
            tp = data.get("type", "unknown")
            typed.setdefault(tp, []).append(n)
        for tp, nodes in typed.items():
            shape, color, size = icon_style_for_type(tp)
            nx.draw_networkx_nodes(
                g,
                pos,
                nodelist=nodes,
                node_shape=shape,
                node_color=color,
                node_size=size,
                linewidths=1,
                edgecolors="#333",
                ax=ax,
            )
        nx.draw_networkx_labels(
            g,
            pos,
            labels=labels,
            font_size=9,
            ax=ax,
            bbox=dict(boxstyle="round,pad=0.2", fc="white", ec="none", alpha=0.75),
        )
        fig.tight_layout()

    _render(ax, pos)
    return {"fig": fig, "ax": ax, "pos": pos, "g": g, "redraw": _render}


def _resolve_overlaps(
    pos: Dict[str, Tuple[float, float]],
    *,
    min_dist: float = 0.05,
    iterations: int = 30,
    same_row_only: bool = True,
) -> Dict[str, Tuple[float, float]]:
    nodes = list(pos.keys())
    coords = {n: [pos[n][0], pos[n][1]] for n in nodes}
    def same_row(a, b):
        return abs(coords[a][1] - coords[b][1]) < 0.02
    for _ in range(iterations):
        moved = False
        for i in range(len(nodes)):
            for j in range(i + 1, len(nodes)):
                a, b = nodes[i], nodes[j]
                if same_row_only and not same_row(a, b):
                    continue
                dx = coords[b][0] - coords[a][0]
                dy = coords[b][1] - coords[a][1]
                dist = math.hypot(dx, dy)
                if dist < 1e-6:
                    dx, dy = 1e-3, 0
                    dist = 1e-3
                if dist < min_dist:
                    push = (min_dist - dist) / 2.0
                    ux, uy = dx / dist, dy / dist
                    coords[a][0] -= ux * push
                    coords[b][0] += ux * push
                    if not same_row_only:
                        coords[a][1] -= uy * push
                        coords[b][1] += uy * push
                    moved = True
        if not moved:
            break
    # clamp
    for n in nodes:
        coords[n][0] = min(0.97, max(0.03, coords[n][0]))
        coords[n][1] = min(0.97, max(0.03, coords[n][1]))
    return {n: (coords[n][0], coords[n][1]) for n in nodes}


def _choose_parent_router(host_ip: str, router_ips: List[str], gateway_ip: Optional[str]) -> Optional[str]:
    def _same_prefix(a: ipaddress.IPv4Address, b: ipaddress.IPv4Address, bits: int) -> bool:
        net_a = ipaddress.ip_network(f"{a}/{bits}", strict=False)
        return ipaddress.ip_address(b) in net_a

    try:
        hip = ipaddress.ip_address(host_ip)
    except Exception:
        return gateway_ip

    candidates = []
    for rip in router_ips:
        try:
            candidates.append(ipaddress.ip_address(rip))
        except Exception:
            continue

    # Prefer same /24, then same /16
    for bits in (24, 16):
        for r in candidates:
            if _same_prefix(hip, r, bits):
                return str(r)

    # Fallback to gateway
    return gateway_ip
