import threading
import queue
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from typing import Optional
import os
import json
import shutil

from scanner import (
    get_default_gateway,
    get_local_ipv4_networks,
    get_local_ipv4_networks_detailed,
    scan_subnet,
)
from netgraph import build_graph, draw_graph
from device_classifier import classify_device
from nmap_utils import nmap_available, run_nmap_xml
from sniffer import (
    sniff_available,
    get_capture_interfaces,
    get_capture_interfaces_detailed,
    sniff_packets,
    tcpdump_available,
    run_tcpdump,
)

try:
    from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
except Exception as e:  # pragma: no cover
    FigureCanvasTkAgg = None  # type: ignore


class NetMapperApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("NetMapper – Auto Network Mapping")
        self.geometry("1000x650")

        self._build_ui()
        self._scan_thread: Optional[threading.Thread] = None
        self._stop = threading.Event()
        self._progress_queue: "queue.Queue[tuple[int,int]]" = queue.Queue()
        self.last_results = None
        self.last_subnet = None
        self.last_gateway = None
        self.nmap_results = {}
        self.passive_ports = {}
        self._sniff_thread = None
        self._sniff_stop = threading.Event()
        self._sniff_queue: "queue.Queue[tuple[str,str]]" = queue.Queue()
        self._sniff_err_queue: "queue.Queue[str]" = queue.Queue()
        self._sniff_count = 0

        # Pre-fill subnet
        nets = get_local_ipv4_networks()
        if nets:
            self.subnet_var.set(str(nets[0]))

    def _build_ui(self):
        # Pages
        self.nb = ttk.Notebook(self)
        self.page_home = ttk.Frame(self.nb)
        self.page_map = ttk.Frame(self.nb)
        self.page_table = ttk.Frame(self.nb)
        self.nb.add(self.page_home, text="Home")
        self.nb.add(self.page_map, text="Map")
        self.nb.add(self.page_table, text="Table")
        self.nb.pack(fill=tk.BOTH, expand=True)

        top = ttk.Frame(self.page_home)
        top.pack(fill=tk.X, padx=10, pady=10)

        ttk.Label(top, text="Subnet (CIDR)").pack(side=tk.LEFT)
        self.subnet_var = tk.StringVar()
        self.subnet_entry = ttk.Entry(top, textvariable=self.subnet_var, width=30)
        self.subnet_entry.pack(side=tk.LEFT, padx=6)

        # Interface/subnet dropdown
        self.iface_var = tk.StringVar()
        self.iface_combo = ttk.Combobox(top, textvariable=self.iface_var, width=35, state="readonly")
        self.iface_combo.pack(side=tk.LEFT, padx=6)
        self.iface_combo.bind("<<ComboboxSelected>>", self._on_iface_selected)

        self.dns_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(top, text="Reverse DNS", variable=self.dns_var).pack(side=tk.LEFT, padx=8)

        self.arp_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(top, text="Include ARP-only", variable=self.arp_var).pack(side=tk.LEFT, padx=8)

        # Theme toggle
        self.dark_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(top, text="Dark Mode", variable=self.dark_var, command=lambda: self._apply_theme()).pack(side=tk.LEFT, padx=8)

        ttk.Button(top, text="Use Local", command=self._use_local).pack(side=tk.LEFT, padx=4)
        self.scan_btn = ttk.Button(top, text="Scan", command=self._start_scan)
        self.scan_btn.pack(side=tk.LEFT, padx=4)
        self.stop_btn = ttk.Button(top, text="Stop", command=self._stop_scan, state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT, padx=4)

        # Progress
        prog_frame = ttk.Frame(self.page_home)
        prog_frame.pack(fill=tk.X, padx=10)
        self.progress = ttk.Progressbar(prog_frame, maximum=100)
        self.progress.pack(fill=tk.X)
        self.status_var = tk.StringVar(value="Idle")
        ttk.Label(prog_frame, textvariable=self.status_var).pack(anchor=tk.W)

        # Table page content
        self.tree = ttk.Treeview(self.page_table, columns=("ip", "alive", "rtt", "hostname", "mac", "ports"), show="headings", height=20)
        for col, text in (
            ("ip", "IP"),
            ("alive", "Alive"),
            ("rtt", "RTT ms"),
            ("hostname", "Hostname"),
            ("mac", "MAC"),
            ("ports", "Open Ports"),
        ):
            self.tree.heading(col, text=text)
            width = 200 if col == "hostname" else (160 if col == "ports" else 120)
            self.tree.column(col, width=width, anchor=tk.W)
        self.tree.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Map page canvas
        right = ttk.Frame(self.page_map)
        self.canvas_widget = None
        self.figure = None
        self.figure_canvas = None
        self.draw_bundle = None
        self._dragging_node = None
        right.pack(fill=tk.BOTH, expand=True)
        self.right = right

        # Toolbar + export buttons under graph
        tools = ttk.Frame(self.page_map)
        tools.pack(fill=tk.X, padx=10)
        try:
            from matplotlib.backends.backend_tkagg import NavigationToolbar2Tk
            self.toolbar = None
            def _attach_toolbar():
                if self.figure_canvas is None:
                    return
                if self.toolbar:
                    self.toolbar.destroy()
                self.toolbar = NavigationToolbar2Tk(self.figure_canvas, tools)
                self.toolbar.update()
            self._attach_toolbar = _attach_toolbar
        except Exception:
            self._attach_toolbar = lambda: None

        exp_btns = ttk.Frame(tools)
        exp_btns.pack(side=tk.RIGHT)
        ttk.Button(exp_btns, text="Export PNG", command=self._export_png).pack(side=tk.LEFT, padx=4)
        ttk.Button(exp_btns, text="Export CSV", command=self._export_csv).pack(side=tk.LEFT, padx=4)
        ttk.Button(exp_btns, text="Export JSON", command=self._export_json).pack(side=tk.LEFT, padx=4)
        ttk.Button(exp_btns, text="Save Layout", command=self._save_layout).pack(side=tk.LEFT, padx=4)
        ttk.Button(exp_btns, text="Load Layout", command=self._load_layout).pack(side=tk.LEFT, padx=4)

        # Nmap controls
        nmap_frame = ttk.Frame(self.page_home)
        nmap_frame.pack(fill=tk.X, padx=10, pady=(0,8))
        self.nmap_avail = nmap_available()
        self.use_nmap_var = tk.BooleanVar(value=False)
        chk = ttk.Checkbutton(nmap_frame, text=f"Use Nmap ({'available' if self.nmap_avail else 'not found'})", variable=self.use_nmap_var)
        chk.pack(side=tk.LEFT)
        self.nmap_alive_only_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(nmap_frame, text="Alive only", variable=self.nmap_alive_only_var).pack(side=tk.LEFT, padx=(8,0))
        ttk.Label(nmap_frame, text="Options").pack(side=tk.LEFT, padx=(10,2))
        self.nmap_opts_var = tk.StringVar(value="-sV -T4 -Pn")
        ttk.Entry(nmap_frame, textvariable=self.nmap_opts_var, width=20).pack(side=tk.LEFT)
        ttk.Label(nmap_frame, text="Ports").pack(side=tk.LEFT, padx=(10,2))
        self.nmap_ports_var = tk.StringVar(value="80,443,445,3389")
        ttk.Entry(nmap_frame, textvariable=self.nmap_ports_var, width=20).pack(side=tk.LEFT)
        ttk.Button(nmap_frame, text="Run Nmap", command=self._start_nmap).pack(side=tk.LEFT, padx=8)
        if not self.nmap_avail:
            chk.state(["disabled"])  # type: ignore

        # Passive listener controls
        sniff_frame = ttk.Frame(self.page_home)
        sniff_frame.pack(fill=tk.X, padx=10, pady=(0,8))
        self.sniff_avail = sniff_available() or tcpdump_available()
        ttk.Label(sniff_frame, text=f"Passive Listener ({'available' if self.sniff_avail else 'requires scapy/npcap'})").pack(side=tk.LEFT)
        ttk.Label(sniff_frame, text="Iface").pack(side=tk.LEFT, padx=(10,2))
        self.sniff_iface_var = tk.StringVar()
        self.sniff_iface_combo = ttk.Combobox(sniff_frame, textvariable=self.sniff_iface_var, width=45, state="readonly")
        self.sniff_iface_map = {}
        if self.sniff_avail:
            try:
                items = get_capture_interfaces_detailed()
            except Exception:
                items = []
            disp = [it["display"] for it in items]
            self.sniff_iface_map = {it["display"]: it["scapy"] for it in items}
            self.sniff_iface_combo["values"] = disp
            if disp:
                # Prefer 'any (all interfaces)' on Linux for reliability
                try:
                    import platform as _plat
                    if _plat.system().lower() == "linux" and "any (all interfaces)" in disp:
                        self.sniff_iface_combo.current(disp.index("any (all interfaces)"))
                    else:
                        self.sniff_iface_combo.current(0)
                except Exception:
                    self.sniff_iface_combo.current(0)
        self.sniff_iface_combo.pack(side=tk.LEFT)
        ttk.Button(sniff_frame, text="Refresh", command=self._refresh_sniff_ifaces).pack(side=tk.LEFT, padx=6)
        ttk.Label(sniff_frame, text="Protocols").pack(side=tk.LEFT, padx=(10,2))
        self._init_sniff_presets()
        self.sniff_filter_combo = ttk.Combobox(
            sniff_frame,
            values=list(self.sniff_filter_presets.keys()),
            width=28,
            state="normal",
        )
        self.sniff_filter_combo.set("All TCP/UDP")
        self.sniff_filter_combo.pack(side=tk.LEFT)
        # Backend toggle
        # On Linux default to tcpdump backend if available
        try:
            import platform as _plat
            _linux = _plat.system().lower() == "linux"
        except Exception:
            _linux = False
        self.tcpdump_var = tk.BooleanVar(value=(tcpdump_available() and (_linux or not sniff_available())))
        tcpdump_chk = ttk.Checkbutton(sniff_frame, text="Use tcpdump backend", variable=self.tcpdump_var)
        tcpdump_chk.pack(side=tk.LEFT, padx=8)
        if not tcpdump_available():
            tcpdump_chk.state(["disabled"])  # type: ignore
        self.sniff_btn = ttk.Button(sniff_frame, text="Start Listen", command=self._start_listen, state=(tk.NORMAL if self.sniff_avail else tk.DISABLED))
        self.sniff_btn.pack(side=tk.LEFT, padx=6)
        self.sniff_stop_btn = ttk.Button(sniff_frame, text="Stop Listen", command=self._stop_listen, state=tk.DISABLED)
        self.sniff_stop_btn.pack(side=tk.LEFT)
        ttk.Button(sniff_frame, text="Test Capture", command=self._test_capture).pack(side=tk.LEFT, padx=6)
        self.sniff_status = tk.StringVar(value="Packets: 0")
        ttk.Label(sniff_frame, textvariable=self.sniff_status).pack(side=tk.RIGHT)

        # Timer to poll progress
        self.after(200, self._poll_progress)
        # Apply initial theme
        self._apply_theme()

    def _use_local(self):
        nets = get_local_ipv4_networks()
        if nets:
            self.subnet_var.set(str(nets[0]))
        else:
            messagebox.showwarning("No local subnet", "Could not detect a local IPv4 subnet.")
        # Refresh interface list after updating subnet
        try:
            self._populate_ifaces()
        except Exception:
            pass

    def _populate_ifaces(self):
        items = get_local_ipv4_networks_detailed()
        display = [f"{it['ifname']}: {it['cidr']}" for it in items]
        self.iface_items = items
        if display:
            self.iface_combo["values"] = display
            # Select the item matching current subnet if present
            cur = self.subnet_var.get().strip()
            idx = next((i for i, it in enumerate(items) if it["cidr"] == cur), 0)
            self.iface_combo.current(idx)

    def _on_iface_selected(self, event=None):
        try:
            idx = self.iface_combo.current()
            item = self.iface_items[idx]
            self.subnet_var.set(item["cidr"])
        except Exception:
            pass

    def _start_scan(self):
        subnet = self.subnet_var.get().strip()
        if not subnet:
            messagebox.showerror("Missing subnet", "Enter a subnet in CIDR notation, e.g., 192.168.1.0/24")
            return
        if self._scan_thread and self._scan_thread.is_alive():
            return
        self._stop.clear()
        self.scan_btn.configure(state=tk.DISABLED)
        self.stop_btn.configure(state=tk.NORMAL)
        self.status_var.set("Scanning…")
        self.progress.configure(value=0)
        for row in self.tree.get_children():
            self.tree.delete(row)
        self.nmap_results = {}

        def progress_cb(done: int, total: int):
            self._progress_queue.put((done, total))

        def worker():
            try:
                results = scan_subnet(
                    subnet,
                    timeout_ms=300,
                    max_workers=128,
                    do_dns=self.dns_var.get(),
                    progress_cb=progress_cb,
                    include_arp_only=self.arp_var.get(),
                )
                gw = get_default_gateway()
                # Update UI with results
                self.after(0, self._scan_complete, subnet, results, gw)
            except Exception as e:
                self.after(0, self._scan_error, str(e))

        self._scan_thread = threading.Thread(target=worker, daemon=True)
        self._scan_thread.start()

    def _stop_scan(self):
        # Current scanner runs per-IP jobs and finishes quickly; implement a flag for future long ops
        self._stop.set()
        self.scan_btn.configure(state=tk.NORMAL)
        self.stop_btn.configure(state=tk.DISABLED)
        self.status_var.set("Stopped")

    def _scan_complete(self, subnet: str, results, gateway: Optional[str]):
        self.scan_btn.configure(state=tk.NORMAL)
        self.stop_btn.configure(state=tk.DISABLED)
        self.status_var.set(f"Done: {sum(1 for r in results if r['alive']=='yes')} alive")
        self.last_results = results
        self.last_subnet = subnet
        self.last_gateway = gateway
        # Populate table
        for r in results:
            ports = self._format_ports(self.nmap_results.get(r.get("ip"), [])) if self.nmap_results else ""
            self.tree.insert("", tk.END, values=(r.get("ip"), r.get("alive"), r.get("rtt_ms"), r.get("hostname"), r.get("mac"), ports))

        # Draw graph
        try:
            g = build_graph(subnet, results, gateway_ip=gateway)
            bundle = draw_graph(g, theme=("dark" if self.dark_var.get() else "light"))
            self._render_figure(bundle)
            try:
                self.nb.select(self.page_map)
            except Exception:
                pass
            # Try auto-load saved layout for this subnet
            self._auto_load_layout()
        except Exception as e:
            messagebox.showerror("Graph error", str(e))

    def _scan_error(self, msg: str):
        self.scan_btn.configure(state=tk.NORMAL)
        self.stop_btn.configure(state=tk.DISABLED)
        self.status_var.set("Error")
        messagebox.showerror("Scan error", msg)

    def _render_figure(self, fig_or_bundle):
        if FigureCanvasTkAgg is None:
            messagebox.showwarning("Matplotlib missing", "Matplotlib backend not available for Tkinter.")
            return
        if self.figure_canvas is not None:
            self.figure_canvas.get_tk_widget().destroy()
        if isinstance(fig_or_bundle, dict):
            self.draw_bundle = fig_or_bundle
            self.figure = fig_or_bundle.get("fig")
        else:
            self.draw_bundle = None
            self.figure = fig_or_bundle
        self.figure_canvas = FigureCanvasTkAgg(self.figure, master=self.right)
        widget = self.figure_canvas.get_tk_widget()
        widget.pack(fill=tk.BOTH, expand=True)
        self.figure_canvas.draw()
        try:
            self._attach_toolbar()
        except Exception:
            pass
        self._setup_dragging()
        # Apply current theme to plot if supported
        try:
            if self.draw_bundle and self.draw_bundle.get("set_theme"):
                self.draw_bundle["set_theme"]("dark" if self.dark_var.get() else "light")
                self.figure_canvas.draw_idle()
        except Exception:
            pass

    def _poll_progress(self):
        try:
            while True:
                done, total = self._progress_queue.get_nowait()
                pct = 0 if total == 0 else int(done * 100 / total)
                self.progress.configure(value=pct)
            
            while True:
                ip, p = self._sniff_queue.get_nowait()
                if not ip:
                    continue
                s = self.passive_ports.setdefault(ip, set())
                s.add(p)
                self._sniff_count += 1
            
            while True:
                err = self._sniff_err_queue.get_nowait()
                if err:
                    self.status_var.set(f"Listen error: {err}")

            # unreachable unless queues drained, but keeps structure simple
        except queue.Empty:
            pass
        
        if self.passive_ports:
            for iid in self.tree.get_children():
                vals = list(self.tree.item(iid, "values"))
                ip = vals[0]
                merged = []
                if self.nmap_results.get(ip):
                    merged.extend(self.nmap_results[ip])
                if self.passive_ports.get(ip):
                    merged.extend(sorted((pp, "") for pp in self.passive_ports[ip]))
                if merged:
                    vals[-1] = self._format_ports(merged)
                    self.tree.item(iid, values=vals)
        self.sniff_status.set(f"Packets: {self._sniff_count}")
        self.after(200, self._poll_progress)

    def _format_ports(self, items):
        return ", ".join(f"{p} {s}" if s else p for p, s in items[:12])

    def _start_nmap(self):
        if not self.nmap_avail:
            messagebox.showwarning("Nmap not found", "Install nmap to enable scanning.")
            return
        if not self.last_results:
            messagebox.showwarning("No hosts", "Run a scan first.")
            return
        if self.nmap_alive_only_var.get():
            targets = [r.get("ip") for r in self.last_results if r.get("alive") == "yes" and r.get("ip")]
        else:
            targets = [r.get("ip") for r in self.last_results if r.get("ip")]
        if not targets:
            messagebox.showwarning("No alive hosts", "No alive hosts to scan with nmap.")
            return
        opts = self.nmap_opts_var.get().strip()
        ports = self.nmap_ports_var.get().strip()
        self.status_var.set("Running nmap...")

        def worker():
            res = run_nmap_xml(targets, opts, ports, timeout=900)
            self.after(0, self._nmap_complete, res)

        threading.Thread(target=worker, daemon=True).start()

    def _nmap_complete(self, results):
        self.nmap_results = results or {}
        # Update table ports column
        for iid in self.tree.get_children():
            vals = list(self.tree.item(iid, "values"))
            ip = vals[0]
            vals[-1] = self._format_ports(self.nmap_results.get(ip, []))
            self.tree.item(iid, values=vals)
        # Redraw labels unchanged
        if self.draw_bundle:
            try:
                self.figure_canvas.draw_idle()
            except Exception:
                pass
        self.status_var.set("Nmap complete")

    def _start_listen(self):
        if not self.sniff_avail:
            messagebox.showwarning("Unavailable", "Install scapy and Npcap (Windows) to enable listening.")
            return
        if self._sniff_thread and self._sniff_thread.is_alive():
            return
        disp = self.sniff_iface_var.get().strip()
        iface = self.sniff_iface_map.get(disp, disp) or None
        sel = self.sniff_filter_combo.get().strip()
        bpf = self.sniff_filter_presets.get(sel, sel)
        if bpf is None:
            bpf = "tcp or udp"
        self._sniff_stop.clear()
        self.sniff_btn.configure(state=tk.DISABLED)
        self.sniff_stop_btn.configure(state=tk.NORMAL)
        self._sniff_count = 0

        def _cb(ip: str, port: str):
            try:
                self._sniff_queue.put((ip, port))
            except Exception:
                pass

        def worker():
            try:
                if self.tcpdump_var.get():
                    run_tcpdump(iface, bpf, _cb, self._sniff_stop, err_cb=lambda e: self._sniff_err_queue.put(e))
                else:
                    sniff_packets(iface, bpf, _cb, self._sniff_stop, err_cb=lambda e: self._sniff_err_queue.put(e))
            finally:
                self.after(0, self._listen_stopped)

        self._sniff_thread = threading.Thread(target=worker, daemon=True)
        self._sniff_thread.start()
        self.status_var.set("Listening...")

    def _stop_listen(self):
        self._sniff_stop.set()

    def _listen_stopped(self):
        self.sniff_btn.configure(state=tk.NORMAL)
        self.sniff_stop_btn.configure(state=tk.DISABLED)
        self.status_var.set("Listener stopped")

    def _refresh_sniff_ifaces(self):
        if not self.sniff_avail:
            return
        try:
            items = get_capture_interfaces_detailed()
        except Exception:
            items = []
        disp = [it["display"] for it in items]
        self.sniff_iface_map = {it["display"]: it["scapy"] for it in items}
        self.sniff_iface_combo["values"] = disp
        if disp:
            self.sniff_iface_combo.current(0)

    def _apply_theme(self):
        try:
            style = ttk.Style()
            # Switch to a theme that honors style options across platforms
            try:
                style.theme_use("clam")
            except Exception:
                pass
            dark = self.dark_var.get()
            bg = "#0f1115" if dark else "#ffffff"
            fg = "#e6e6e6" if dark else "#000000"
            altbg = "#1a1d23" if dark else "#f5f5f5"
            sel = "#314a7e" if dark else "#cde1ff"
            self.configure(bg=bg)
            style.configure("TFrame", background=bg)
            style.configure("TLabel", background=bg, foreground=fg)
            style.configure("TButton", background=altbg, foreground=fg)
            style.configure("TCheckbutton", background=bg, foreground=fg)
            style.configure("TEntry", fieldbackground=altbg, foreground=fg, background=altbg)
            style.configure("TProgressbar", background="#5b8ff9")
            # Treeview
            style.configure("Treeview", background=altbg, fieldbackground=altbg, foreground=fg)
            style.configure("Treeview.Heading", background=bg, foreground=fg)
            # Panedwindow
            style.configure("TPanedwindow", background=bg)
            # Force redraw
            self.update_idletasks()
            # Update plot theme if present
            if self.draw_bundle and self.draw_bundle.get("set_theme"):
                self.draw_bundle["set_theme"]("dark" if dark else "light")
                if self.figure_canvas:
                    self.figure_canvas.draw_idle()
        except Exception:
            pass

    def _test_capture(self):
        # Run a 2-second capture with no filter to validate the interface
        if not self.sniff_avail:
            messagebox.showwarning("Unavailable", "Install scapy and libpcap/Npcap to enable listening.")
            return
        disp = self.sniff_iface_var.get().strip()
        iface = self.sniff_iface_map.get(disp, disp) or None
        tmp_stop = threading.Event()
        start_count = self._sniff_count

        def _cb(ip: str, port: str):
            try:
                self._sniff_queue.put((ip, port))
            except Exception:
                pass

        def _err(msg: str):
            try:
                self._sniff_err_queue.put(msg)
            except Exception:
                pass

        def worker():
            try:
                if self.tcpdump_var.get():
                    run_tcpdump(iface, "", _cb, tmp_stop, err_cb=_err)
                else:
                    sniff_packets(iface, "", _cb, tmp_stop, err_cb=_err)
            finally:
                tmp_stop.set()

        t = threading.Thread(target=worker, daemon=True)
        t.start()
        # Stop after ~2 seconds
        self.after(2000, lambda: tmp_stop.set())
        # Poll shortly after to show results
        def _report():
            got = self._sniff_count - start_count
            if got <= 0:
                messagebox.showwarning("No packets detected", "No traffic captured. Try interface 'any' (Linux), run as root/Admin, or generate traffic.")
            else:
                messagebox.showinfo("Capture OK", f"Captured ~{got} packets in 2s on '{disp or iface}'.")
        self.after(2400, _report)

    def _init_sniff_presets(self):
        # Display name -> BPF filter string (or empty for no filter)
        self.sniff_filter_presets = {
            "All TCP/UDP": "tcp or udp",
            "Web (80,443)": "tcp and (port 80 or port 443)",
            "DNS": "udp and port 53",
            "SMB": "tcp and port 445",
            "RDP": "tcp and port 3389",
            "ICMP": "icmp",
            "DHCP": "udp and (port 67 or port 68)",
            "mDNS": "udp and port 5353",
            "LLMNR": "udp and port 5355",
            "NetBIOS-NS": "udp and port 137",
            "No filter": "",
        }

    def _layout_path(self):
        if not self.last_subnet:
            return None
        fname = self.last_subnet.replace("/", "_").replace(" ", "_") + ".layout.json"
        folder = os.path.join(os.path.dirname(__file__), "layouts")
        os.makedirs(folder, exist_ok=True)
        return os.path.join(folder, fname)

    def _save_layout(self):
        if not self.draw_bundle or not self.last_subnet:
            messagebox.showwarning("No layout", "Draw a map before saving layout.")
            return
        data = {
            "subnet": self.last_subnet,
            "positions": {k: [float(x), float(y)] for k, (x, y) in self.draw_bundle.get("pos", {}).items()},
        }
        path = filedialog.asksaveasfilename(defaultextension=".json", initialfile=os.path.basename(self._layout_path() or "layout.json"), filetypes=[["JSON", "*.json"]])
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
            messagebox.showinfo("Saved", f"Saved layout to: {path}")
        except Exception as e:
            messagebox.showerror("Save error", str(e))

    def _load_layout(self):
        if not self.draw_bundle:
            messagebox.showwarning("No graph", "Draw a map before loading layout.")
            return
        path = filedialog.askopenfilename(filetypes=[["JSON", "*.json"]])
        if not path:
            return
        self._apply_layout_file(path)

    def _auto_load_layout(self):
        path = self._layout_path()
        if path and os.path.exists(path):
            self._apply_layout_file(path, quiet=True)

    def _apply_layout_file(self, path, quiet: bool = False):
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            pos = self.draw_bundle.get("pos")
            for node_id, xy in data.get("positions", {}).items():
                if node_id in pos:
                    pos[node_id] = (float(xy[0]), float(xy[1]))
            redraw = self.draw_bundle.get("redraw")
            ax = self.draw_bundle.get("ax")
            redraw(ax, pos)
            self.figure_canvas.draw_idle()
            if not quiet:
                messagebox.showinfo("Loaded", f"Applied layout from: {path}")
        except Exception as e:
            if not quiet:
                messagebox.showerror("Load error", str(e))

    def _setup_dragging(self):
        if not self.figure or not self.draw_bundle:
            return
        canvas = self.figure_canvas.get_tk_widget()
        fig = self.figure
        # Disconnect previous connections if any
        for attr in ("_cid_press", "_cid_release", "_cid_motion"):
            cid = getattr(self, attr, None)
            if cid is not None:
                try:
                    fig.canvas.mpl_disconnect(cid)
                except Exception:
                    pass
                setattr(self, attr, None)

        self._cid_press = fig.canvas.mpl_connect("button_press_event", self._on_press)
        self._cid_release = fig.canvas.mpl_connect("button_release_event", self._on_release)
        self._cid_motion = fig.canvas.mpl_connect("motion_notify_event", self._on_motion)

    def _toolbar_mode(self):
        try:
            return getattr(self, "toolbar", None).mode if getattr(self, "toolbar", None) else None
        except Exception:
            return None

    def _on_press(self, event):
        if not self.draw_bundle:
            return
        if event.inaxes != self.draw_bundle.get("ax"):
            return
        if self._toolbar_mode():
            return
        node = self._hit_test_node(event)
        if node:
            self._dragging_node = node

    def _on_release(self, event):
        self._dragging_node = None

    def _on_motion(self, event):
        if not self.draw_bundle or not self._dragging_node:
            return
        if event.inaxes != self.draw_bundle.get("ax"):
            return
        if event.xdata is None or event.ydata is None:
            return
        pos = self.draw_bundle.get("pos")
        pos[self._dragging_node] = (
            max(0.02, min(0.98, event.xdata)),
            max(0.02, min(0.98, event.ydata)),
        )
        redraw = self.draw_bundle.get("redraw")
        ax = self.draw_bundle.get("ax")
        try:
            redraw(ax, pos)
            self.figure_canvas.draw_idle()
        except Exception:
            pass

    def _hit_test_node(self, event):
        # Find closest node within 12 px
        ax = self.draw_bundle.get("ax")
        pos = self.draw_bundle.get("pos")
        inv = ax.transData
        best = None
        best_d2 = 12 * 12
        for n, (x, y) in pos.items():
            sx, sy = inv.transform((x, y))
            dx = event.x - sx
            dy = event.y - sy
            d2 = dx * dx + dy * dy
            if d2 < best_d2:
                best = n
                best_d2 = d2
        return best

    def _export_png(self):
        if not self.figure:
            messagebox.showwarning("No graph", "Run a scan before exporting a PNG.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".png", filetypes=[["PNG Image", "*.png"]])
        if not path:
            return
        try:
            self.figure.savefig(path, dpi=150)
            messagebox.showinfo("Saved", f"Saved graph to: {path}")
        except Exception as e:
            messagebox.showerror("Export error", str(e))

    def _export_csv(self):
        if not self.last_results:
            messagebox.showwarning("No data", "Run a scan before exporting CSV.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[["CSV", "*.csv"]])
        if not path:
            return
        try:
            import csv
            with open(path, "w", newline="", encoding="utf-8") as f:
                w = csv.writer(f)
                w.writerow(["ip", "alive", "rtt_ms", "hostname", "mac", "type"])
                for r in self.last_results:
                    dtype = classify_device(r, gateway_ip=self.last_gateway)
                    w.writerow([r.get("ip"), r.get("alive"), r.get("rtt_ms"), r.get("hostname"), r.get("mac"), dtype])
            messagebox.showinfo("Saved", f"Saved CSV to: {path}")
        except Exception as e:
            messagebox.showerror("Export error", str(e))

    def _export_json(self):
        if not self.last_results:
            messagebox.showwarning("No data", "Run a scan before exporting JSON.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[["JSON", "*.json"]])
        if not path:
            return
        try:
            data = {
                "subnet": self.last_subnet,
                "gateway": self.last_gateway,
                "hosts": [
                    {
                        **r,
                        "type": classify_device(r, gateway_ip=self.last_gateway),
                        "ports": self.nmap_results.get(r.get("ip"), []),
                    }
                    for r in self.last_results
                ],
                "positions": {k: [float(x), float(y)] for k, (x, y) in (self.draw_bundle.get("pos") if self.draw_bundle else {}).items()},
            }
            with open(path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
            messagebox.showinfo("Saved", f"Saved JSON to: {path}")
        except Exception as e:
            messagebox.showerror("Export error", str(e))


if __name__ == "__main__":
    app = NetMapperApp()
    app.mainloop()
