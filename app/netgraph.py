from typing import Dict, Iterable, List, Optional, Tuple, Callable, Any

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

    # Sort helpers for consistent grouping
    type_order = {
        "router": 0,
        "gateway": 1,
        "switch": 2,
        "ap": 3,
        "server": 4,
        "nas": 5,
        "printer": 6,
        "camera": 7,
        "vm": 8,
        "pc": 9,
        "unknown": 10,
    }

    def node_sort_key(n: str):
        data = g.nodes[n]
        tp = (data.get("type") or data.get("kind") or "unknown").lower()
        ip = data.get("ip") or data.get("label") or n
        return (type_order.get(tp, 99), str(ip))

    for k in list(parent_groups.keys()):
        parent_groups[k].sort(key=node_sort_key)

    pos: Dict[str, Tuple[float, float]] = {}

    # Top and mid layers
    top_nodes = [n for n, lvl in levels.items() if lvl == 0]
    mid_nodes = [n for n, lvl in levels.items() if lvl == 1]

    top_nodes.sort(key=lambda n: (g.nodes[n].get("label") or g.nodes[n].get("ip") or n))
    mid_nodes.sort(key=lambda n: (g.nodes[n].get("label") or g.nodes[n].get("ip") or n))

    pos_y = {0: 0.94, 1: 0.70, 2: 0.20}

    def _place_row(nodes: List[str], y: float):
        if not nodes:
            return
        spacing = 1.0 / (len(nodes) + 1)
        for i, n in enumerate(nodes, start=1):
            pos[n] = (i * spacing, y)

    _place_row(top_nodes, pos_y[0])
    _place_row(mid_nodes, pos_y[1])

    # Place hosts grouped by /24 under their parent with multi-row support
    def _place_children(parent: Optional[str], children: List[str]):
        if not children:
            return
        anchor_x = pos[parent][0] if (parent and parent in pos) else (pos[top_nodes[0]][0] if top_nodes else 0.5)

        def _subnet24(nid: str) -> str:
            try:
                ip = g.nodes[nid].get("ip")
                net = ipaddress.ip_network(f"{ip}/24", strict=False)
                return str(net.network_address)
            except Exception:
                return "other"
        groups: Dict[str, List[str]] = {}
        for c in children:
            groups.setdefault(_subnet24(c), []).append(c)
        ordered = sorted(groups.items(), key=lambda kv: kv[0])
        total_n = len(children)
        half_w = min(0.45, max(0.12, 0.02 * total_n + 0.08))
        left = max(0.03, anchor_x - half_w)
        right = min(0.97, anchor_x + half_w)
        total_width = max(0.12, right - left)
        padding = 0.015
        group_count = len(ordered)
        block_w = max(0.10, (total_width - padding * (group_count - 1)) / max(1, group_count))
        y_min = pos_y[2]
        y_max = pos_y[1] - 0.14
        if y_max <= y_min:
            y_max = y_min + 0.05
        for idx, (subnet, nodes) in enumerate(ordered):
            nodes.sort(key=node_sort_key)
            if group_count > 1:
                base_y = y_min + (idx / (group_count - 1)) * (y_max - y_min)
            else:
                base_y = y_min
            cur_left = left + idx * (block_w + padding)
            n = len(nodes)
            max_cols = max(3, int(block_w / 0.08))
            rows = max(1, (n + max_cols - 1) // max_cols)
            row_gap = 0.07
            for r in range(rows):
                row_nodes = nodes[r * max_cols : (r + 1) * max_cols]
                if not row_nodes:
                    continue
                spacing = block_w / (len(row_nodes) + 1)
                y = min(y_max, base_y + r * row_gap)
                for i, nid in enumerate(row_nodes, start=1):
                    x = cur_left + i * spacing
                    pos[nid] = (x, y)

    for parent in mid_nodes:
        _place_children(parent, parent_groups.get(parent, []))

    for net in top_nodes:
        _place_children(net, parent_groups.get(net, []))

    remaining = [n for n in bottom_nodes if n not in pos]
    if remaining:
        spacing = 1.0 / (len(remaining) + 1)
        for i, n in enumerate(remaining, start=1):
            pos[n] = (i * spacing, pos_y[2])

    return pos


def draw_graph(
    g: nx.DiGraph,
    figsize=(10.5, 6.0),
    theme: str = "light",
    highlight: Optional[Iterable[str]] = None,
) -> Dict[str, Any]:
    fig, ax = plt.subplots(figsize=figsize)
    ax.axis("off")

    pos = _tree_layout(g)
    pos = _resolve_overlaps(pos, same_row_only=True, min_dist=0.08, iterations=120)

    current_theme = {"name": theme}
    highlight_set = set(highlight or [])

    def _theme_colors(name: str):
        if name == "dark":
            return {
                "bg": "#0f1115",
                "edge": "#9aa4b2",
                "label_fc": "#000000",
                "label_alpha": 0.55,
                "label_color": "#e6e6e6",
                "node_edge": "#dddddd",
            }
        return {
            "bg": "#ffffff",
            "edge": "#888888",
            "label_fc": "#ffffff",
            "label_alpha": 0.75,
            "label_color": "#000000",
            "node_edge": "#333333",
        }

    def _render(ax, pos, highlight_nodes: Optional[Iterable[str]] = None):
        ax.clear()
        ax.axis("off")
        th = _theme_colors(current_theme["name"])  # type: ignore
        ax.set_facecolor(th["bg"])  # type: ignore
        fig.patch.set_facecolor(th["bg"])  # type: ignore
        current_highlight = set(highlight_nodes) if highlight_nodes is not None else highlight_set
        # Edges
        nx.draw_networkx_edges(g, pos, ax=ax, width=1.2, edge_color=th["edge"])  # type: ignore
        # Labels with background for readability
        labels = {n: (data.get("label") or n) for n, data in g.nodes(data=True)}
        # Draw nodes by type with distinct shapes
        typed: Dict[str, List[str]] = {}
        for n, data in g.nodes(data=True):
            tp = data.get("type", "unknown")
            typed.setdefault(tp, []).append(n)
        for tp, nodes in typed.items():
            shape, color, size = icon_style_for_type(tp)
            normal = [n for n in nodes if n not in current_highlight]
            selected = [n for n in nodes if n in current_highlight]
            if normal:
                nx.draw_networkx_nodes(
                    g,
                    pos,
                    nodelist=normal,
                    node_shape=shape,
                    node_color=color,
                    node_size=size,
                    linewidths=1,
                    edgecolors=th["node_edge"],  # type: ignore
                    ax=ax,
                )
            if selected:
                nx.draw_networkx_nodes(
                    g,
                    pos,
                    nodelist=selected,
                    node_shape=shape,
                    node_color=color,
                    node_size=[size * 1.15] * len(selected),
                    linewidths=2.6,
                    edgecolors="#ff4d4f",
                    ax=ax,
                )
        nx.draw_networkx_labels(
            g,
            pos,
            labels=labels,
            font_size=9,
            font_color=th["label_color"],  # type: ignore
            ax=ax,
            bbox=dict(boxstyle="round,pad=0.2", fc=th["label_fc"], ec="none", alpha=th["label_alpha"]),  # type: ignore
        )
        fig.tight_layout()

    def _set_theme(name: str):
        current_theme["name"] = name
        _render(ax, pos)

    def _set_highlight(nodes: Iterable[str]):
        highlight_set.clear()
        highlight_set.update(nodes)
        _render(ax, pos)
        fig.canvas.draw_idle()

    def _redraw(ax, new_pos, highlight_nodes: Optional[Iterable[str]] = None):
        _render(ax, new_pos, highlight_nodes)

    _render(ax, pos)
    return {
        "fig": fig,
        "ax": ax,
        "pos": pos,
        "g": g,
        "redraw": _redraw,
        "set_theme": _set_theme,
        "set_highlight": _set_highlight,
    }


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
