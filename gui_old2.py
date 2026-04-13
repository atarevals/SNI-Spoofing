"""SNI Spoofer – Windows GUI v2.0

Connection modes
~~~~~~~~~~~~~~~~
* **SNI Only**   – Xray (Trojan-WS) tunnelled through the SNI spoofer.
* **SNI + Warp** – warp-plus (gool / TLS) tunnelled through the SNI spoofer.
* **Gaming**     – Same as *SNI Only* with aggressive low-latency tuning.
"""
import ctypes
import os
import sys
import threading
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox

# ── Admin elevation (WinDivert requires it) ──────────────────────────────────

def _ensure_admin():
    if sys.platform != "win32":
        return
    try:
        if ctypes.windll.shell32.IsUserAnAdmin():
            return
    except Exception:
        return
    if getattr(sys, "frozen", False):
        exe = sys.executable
        params = ""
    else:
        exe = sys.executable
        params = '"' + '" "'.join(sys.argv) + '"'
    ctypes.windll.shell32.ShellExecuteW(None, "runas", exe, params, None, 1)
    sys.exit(0)

_ensure_admin()

# ── Imports that need admin or project modules ───────────────────────────────

from main import ProxyServer, load_config, save_config, get_exe_dir  # noqa: E402
from core.xray_manager import XrayManager                            # noqa: E402
from core.warp_manager import WarpManager                            # noqa: E402

# ── Constants ────────────────────────────────────────────────────────────────

DEFAULT_SNIS = [
    "www.speedtest.net",
    "www.samsung.com",
    "www.canva.com",
    "cdn.jsdelivr.net",
    "update.microsoft.com",
    "www.mozilla.org",
    "www.asus.com",
    "www.lenovo.com",
    "dl.google.com",
    "www.dell.com",
    "www.hp.com",
]

MODES = ["SNI Only", "SNI + Warp", "Gaming Mode"]

TRANSPORTS = ["ws", "grpc"]

# Common Cloudflare WARP gateway IPs (gool / TLS on 443)
WARP_ENDPOINTS = [
    "162.159.192.1",
    "162.159.193.1",
    "188.114.97.1",
    "188.114.98.1",
]

# ── GUI ──────────────────────────────────────────────────────────────────────

class SNIProxyGUI:
    BG       = "#1e1e2e"
    FG       = "#cdd6f4"
    ACCENT   = "#89b4fa"
    SURFACE  = "#313244"
    GREEN    = "#a6e3a1"
    RED      = "#f38ba8"
    YELLOW   = "#f9e2af"
    OVERLAY  = "#45475a"

    def __init__(self):
        self.root = tk.Tk()
        self.root.title("SNI Spoofer v2.0")
        self.root.geometry("720x780")
        self.root.minsize(640, 680)
        self.root.configure(bg=self.BG)

        try:
            ctypes.windll.shcore.SetProcessDpiAwareness(1)
        except Exception:
            pass

        self.config_path = os.path.join(get_exe_dir(), "config.json")

        # Managed objects
        self.server: ProxyServer | None = None
        self.xray: XrayManager | None = None
        self.warp: WarpManager | None = None

        self._setup_styles()
        self._build_ui()
        self._load_config()
        self._on_mode_change()  # show/hide sections

        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

    # ══════════════════════════════════════════════════════════════════════════
    #  Styles
    # ══════════════════════════════════════════════════════════════════════════

    def _setup_styles(self):
        s = ttk.Style()
        s.theme_use("clam")
        s.configure("TFrame",            background=self.BG)
        s.configure("TLabel",            background=self.BG, foreground=self.FG,
                    font=("Segoe UI", 10))
        s.configure("Header.TLabel",     background=self.BG, foreground=self.ACCENT,
                    font=("Segoe UI", 16, "bold"))
        s.configure("Stats.TLabel",      background=self.BG, foreground=self.YELLOW,
                    font=("Segoe UI", 10))
        s.configure("TLabelframe",       background=self.BG, foreground=self.ACCENT)
        s.configure("TLabelframe.Label", background=self.BG,
                    foreground=self.ACCENT, font=("Segoe UI", 10, "bold"))
        s.configure("TEntry",
                    fieldbackground=self.SURFACE, foreground=self.FG,
                    insertcolor=self.FG)
        s.map("TEntry",
              fieldbackground=[("disabled", "#252536")],
              foreground=[("disabled", "#6c7086")])
        s.configure("TCombobox",
                    fieldbackground=self.SURFACE, foreground=self.FG,
                    selectbackground=self.ACCENT, selectforeground="#1e1e2e",
                    arrowcolor=self.ACCENT)
        s.map("TCombobox",
              fieldbackground=[("disabled", "#252536")],
              foreground=[("disabled", "#6c7086")])
        s.configure("TNotebook",         background=self.BG)
        s.configure("TNotebook.Tab",     background=self.SURFACE,
                    foreground=self.FG, padding=[12, 4],
                    font=("Segoe UI", 10))
        s.map("TNotebook.Tab",
              background=[("selected", self.BG)],
              foreground=[("selected", self.ACCENT)])

    # ══════════════════════════════════════════════════════════════════════════
    #  Layout
    # ══════════════════════════════════════════════════════════════════════════

    def _build_ui(self):
        # ── Header ────────────────────────────────────────────────────────
        hdr = ttk.Frame(self.root)
        hdr.pack(fill="x", padx=16, pady=(10, 2))
        ttk.Label(hdr, text="\U0001f6e1  SNI Spoofer v2.0",
                  style="Header.TLabel").pack(side="left")
        self.status_label = ttk.Label(hdr, text="\u25cf Stopped",
                                      foreground=self.RED,
                                      font=("Segoe UI", 11, "bold"))
        self.status_label.pack(side="right")

        # ── Notebook ──────────────────────────────────────────────────────
        nb = ttk.Notebook(self.root)
        nb.pack(fill="both", expand=True, padx=12, pady=6)

        tab_settings = ttk.Frame(nb)
        tab_log      = ttk.Frame(nb)
        nb.add(tab_settings, text="  Settings  ")
        nb.add(tab_log,      text="  Log  ")

        self._build_settings(tab_settings)
        self._build_log(tab_log)

        # ── Footer ────────────────────────────────────────────────────────
        ttk.Label(
            self.root,
            text="USDT (BEP20): 0x76a768B53Ca77B43086946315f0BDF21156bF424  |  @patterniha",
            font=("Segoe UI", 8),
        ).pack(pady=(0, 4))

    # ── Settings tab ──────────────────────────────────────────────────────

    def _build_settings(self, parent):
        # Scrollable canvas
        canvas = tk.Canvas(parent, bg=self.BG, highlightthickness=0)
        vscroll = ttk.Scrollbar(parent, orient="vertical", command=canvas.yview)
        self._sf = sf = ttk.Frame(canvas)

        sf.bind("<Configure>",
                lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=sf, anchor="nw")
        canvas.configure(yscrollcommand=vscroll.set)
        canvas.pack(side="left", fill="both", expand=True)
        vscroll.pack(side="right", fill="y")
        canvas.bind_all("<MouseWheel>",
                        lambda e: canvas.yview_scroll(int(-1 * (e.delta / 120)), "units"))

        # ── Mode & Controls ───────────────────────────────────────────────
        top = ttk.Frame(sf)
        top.pack(fill="x", padx=10, pady=(10, 4))

        ttk.Label(top, text="Mode:").grid(row=0, column=0, padx=(0, 4), sticky="w")
        self.mode_var = tk.StringVar(value="SNI Only")
        mode_cb = ttk.Combobox(top, textvariable=self.mode_var,
                               values=MODES, state="readonly", width=16)
        mode_cb.grid(row=0, column=1, padx=(0, 12))
        mode_cb.bind("<<ComboboxSelected>>", self._on_mode_change)

        self.start_btn = tk.Button(
            top, text="\u25b6  Start", font=("Segoe UI", 11, "bold"),
            bg=self.GREEN, fg="#1e1e2e", activebackground="#94d88f",
            relief="flat", padx=14, pady=3, cursor="hand2",
            command=self._start)
        self.start_btn.grid(row=0, column=2, padx=(0, 6))

        self.stop_btn = tk.Button(
            top, text="\u25a0  Stop", font=("Segoe UI", 11, "bold"),
            bg=self.RED, fg="#1e1e2e", activebackground="#e07a96",
            relief="flat", padx=14, pady=3, cursor="hand2",
            command=self._stop, state="disabled")
        self.stop_btn.grid(row=0, column=3, padx=(0, 6))

        self.copy_btn = tk.Button(
            top, text="\U0001f4cb Copy Proxy", font=("Segoe UI", 9),
            bg=self.OVERLAY, fg=self.FG, relief="flat", padx=8, pady=3,
            cursor="hand2", command=self._copy_proxy)
        self.copy_btn.grid(row=0, column=4)

        self.conn_label = ttk.Label(top, text="Active: 0 | Total: 0",
                                    style="Stats.TLabel")
        self.conn_label.grid(row=0, column=5, padx=(12, 0))

        # ── Proxy Output ──────────────────────────────────────────────────
        prx = ttk.LabelFrame(sf, text="Proxy Output")
        prx.pack(fill="x", padx=10, pady=4)
        ttk.Label(prx, text="SOCKS5 Port:").grid(row=0, column=0, padx=(10, 4), pady=3, sticky="w")
        self.e_socks = ttk.Entry(prx, width=10)
        self.e_socks.grid(row=0, column=1, padx=(0, 16), pady=3, sticky="w")
        ttk.Label(prx, text="HTTP Port:").grid(row=0, column=2, padx=(0, 4), pady=3, sticky="w")
        self.e_http = ttk.Entry(prx, width=10)
        self.e_http.grid(row=0, column=3, padx=(0, 10), pady=3, sticky="w")

        # ── DPI Bypass ────────────────────────────────────────────────────
        self._dpi_frame = dpi = ttk.LabelFrame(sf, text="DPI Bypass (SNI Spoofer)")
        dpi.pack(fill="x", padx=10, pady=4)
        dpi.columnconfigure(1, weight=1)

        ttk.Label(dpi, text="Fake SNI:").grid(row=0, column=0, padx=(10, 4), pady=3, sticky="w")
        self.sni_var = tk.StringVar()
        self.sni_combo = ttk.Combobox(dpi, textvariable=self.sni_var,
                                      values=DEFAULT_SNIS + ["Custom …"],
                                      width=36)
        self.sni_combo.grid(row=0, column=1, columnspan=3, padx=(0, 10), pady=3, sticky="ew")
        self.sni_combo.bind("<<ComboboxSelected>>", self._on_sni_selection)

        self.custom_sni_label = ttk.Label(dpi, text="Custom SNI:")
        self.custom_sni_label.grid(row=1, column=0, padx=(10, 4), pady=3, sticky="w")
        self.e_custom_sni = ttk.Entry(dpi, width=36)
        self.e_custom_sni.grid(row=1, column=1, columnspan=3, padx=(0, 10), pady=3, sticky="ew")
        self.custom_sni_label.grid_remove()
        self.e_custom_sni.grid_remove()

        ttk.Label(dpi, text="CDN / Endpoint IP:").grid(row=2, column=0, padx=(10, 4), pady=3, sticky="w")
        self.e_cdn_ip = ttk.Entry(dpi, width=20)
        self.e_cdn_ip.grid(row=2, column=1, padx=(0, 12), pady=3, sticky="w")
        ttk.Label(dpi, text="Port:").grid(row=2, column=2, padx=(0, 4), pady=3, sticky="w")
        self.e_cdn_port = ttk.Entry(dpi, width=8)
        self.e_cdn_port.grid(row=2, column=3, padx=(0, 10), pady=3, sticky="w")

        # ── V2Ray Server (SNI Only & Gaming) ──────────────────────────────
        self.v2_frame = ttk.LabelFrame(sf, text="V2Ray Server (Trojan)")
        self.v2_frame.pack(fill="x", padx=10, pady=4)
        self.v2_frame.columnconfigure(1, weight=1)
        v2_fields = [
            ("Password:",   "e_password"),
            ("Server SNI:", "e_server_sni"),
            ("Transport:",  None),
            ("Path:",       "e_path"),
            ("Host:",       "e_host"),
        ]
        for i, (lbl, attr) in enumerate(v2_fields):
            ttk.Label(self.v2_frame, text=lbl).grid(
                row=i, column=0, padx=(10, 4), pady=3, sticky="w")
            if attr:
                e = ttk.Entry(self.v2_frame, width=38)
                e.grid(row=i, column=1, padx=(0, 10), pady=3, sticky="ew")
                setattr(self, attr, e)
            else:
                self.transport_var = tk.StringVar(value="ws")
                cb = ttk.Combobox(self.v2_frame, textvariable=self.transport_var,
                                  values=TRANSPORTS, state="readonly", width=12)
                cb.grid(row=i, column=1, padx=(0, 10), pady=3, sticky="w")

        # ── Warp Settings (SNI + Warp) ────────────────────────────────────
        self.warp_frame = ttk.LabelFrame(sf, text="Warp Settings")
        # Starts hidden – _on_mode_change will show it when needed
        self.warp_frame.columnconfigure(1, weight=1)

        ttk.Label(self.warp_frame, text="Warp Endpoint:").grid(
            row=0, column=0, padx=(10, 4), pady=3, sticky="w")
        self.warp_ep_var = tk.StringVar()
        wep = ttk.Combobox(self.warp_frame, textvariable=self.warp_ep_var,
                           values=WARP_ENDPOINTS, width=22)
        wep.grid(row=0, column=1, padx=(0, 10), pady=3, sticky="w")

        ttk.Label(self.warp_frame, text="License Key:").grid(
            row=1, column=0, padx=(10, 4), pady=3, sticky="w")
        self.e_warp_license = ttk.Entry(self.warp_frame, width=38)
        self.e_warp_license.grid(row=1, column=1, padx=(0, 10), pady=3, sticky="ew")

        ttk.Label(self.warp_frame, text="(optional – for WARP+ accounts)",
                  foreground="#6c7086", font=("Segoe UI", 8)).grid(
            row=2, column=1, padx=(0, 10), sticky="w")

    # ── Log tab ───────────────────────────────────────────────────────────

    def _build_log(self, parent):
        self.log_text = scrolledtext.ScrolledText(
            parent, bg=self.SURFACE, fg=self.FG,
            insertbackground=self.FG, font=("Consolas", 9),
            relief="flat", wrap="word", state="disabled",
            selectbackground=self.ACCENT, selectforeground="#1e1e2e")
        self.log_text.pack(fill="both", expand=True, padx=8, pady=8)

    # ══════════════════════════════════════════════════════════════════════════
    #  Config load / save
    # ══════════════════════════════════════════════════════════════════════════

    def _load_config(self):
        try:
            c = load_config(self.config_path)
        except Exception:
            c = {}

        def _set(entry, val):
            entry.delete(0, "end")
            entry.insert(0, str(val))

        self.mode_var.set(c.get("connection_mode", "SNI Only"))
        _set(self.e_socks,      c.get("socks_port", 10808))
        _set(self.e_http,       c.get("http_port", 10809))
        _set(self.e_cdn_ip,     c.get("CONNECT_IP", "188.114.98.0"))
        _set(self.e_cdn_port,   c.get("CONNECT_PORT", 443))

        # Fake SNI
        fake_sni = c.get("FAKE_SNI", "www.speedtest.net")
        if fake_sni in DEFAULT_SNIS:
            self.sni_var.set(fake_sni)
        else:
            self.sni_var.set("Custom …")
            _set(self.e_custom_sni, fake_sni)
            self.custom_sni_label.grid()
            self.e_custom_sni.grid()

        # V2Ray
        _set(self.e_password,    c.get("trojan_password", "humanity"))
        _set(self.e_server_sni,  c.get("trojan_sni", "www.creationlong.org"))
        self.transport_var.set(   c.get("trojan_transport", "ws"))
        _set(self.e_path,        c.get("trojan_path", "/assignment"))
        _set(self.e_host,        c.get("trojan_host", "www.creationlong.org"))

        # Warp
        self.warp_ep_var.set(    c.get("warp_endpoint", "162.159.192.1"))
        _set(self.e_warp_license, c.get("warp_license", ""))

    def _read_config(self) -> dict:
        sni = self.sni_var.get()
        if sni == "Custom …":
            sni = self.e_custom_sni.get().strip()
        if not sni:
            raise ValueError("Fake SNI is required")
        try:
            sp = int(self.e_socks.get())
            hp = int(self.e_http.get())
            cp = int(self.e_cdn_port.get())
        except ValueError:
            raise ValueError("Ports must be integers")
        return {
            "connection_mode": self.mode_var.get(),
            "LISTEN_HOST": "0.0.0.0",
            "LISTEN_PORT": 40443,
            "CONNECT_IP":  self.e_cdn_ip.get().strip(),
            "CONNECT_PORT": cp,
            "FAKE_SNI": sni,
            "socks_port": sp,
            "http_port": hp,
            "trojan_password": self.e_password.get().strip(),
            "trojan_sni": self.e_server_sni.get().strip(),
            "trojan_transport": self.transport_var.get(),
            "trojan_path": self.e_path.get().strip(),
            "trojan_host": self.e_host.get().strip(),
            "warp_endpoint": self.warp_ep_var.get().strip(),
            "warp_license": self.e_warp_license.get().strip(),
        }

    # ══════════════════════════════════════════════════════════════════════════
    #  UI helpers
    # ══════════════════════════════════════════════════════════════════════════

    def _append_log(self, msg: str):
        def _do():
            self.log_text.configure(state="normal")
            self.log_text.insert("end", msg + "\n")
            self.log_text.see("end")
            self.log_text.configure(state="disabled")
        self.root.after(0, _do)

    def _set_ui_running(self, running: bool):
        def _do():
            if running:
                self.status_label.configure(text="\u25cf Running",
                                            foreground=self.GREEN)
                self.start_btn.configure(state="disabled")
                self.stop_btn.configure(state="normal")
            else:
                self.status_label.configure(text="\u25cf Stopped",
                                            foreground=self.RED)
                self.start_btn.configure(state="normal")
                self.stop_btn.configure(state="disabled")
        self.root.after(0, _do)

    def _update_counts(self, active: int, total: int):
        self.root.after(
            0, lambda: self.conn_label.configure(
                text=f"Active: {active} | Total: {total}"))

    def _on_mode_change(self, *_args):
        mode = self.mode_var.get()
        if mode in ("SNI Only", "Gaming Mode"):
            # Show V2Ray, hide Warp
            self.warp_frame.pack_forget()
            self.v2_frame.pack(fill="x", padx=10, pady=4,
                               after=self._dpi_frame)
        elif mode == "SNI + Warp":
            # Hide V2Ray, show Warp
            self.v2_frame.pack_forget()
            self.warp_frame.pack(fill="x", padx=10, pady=4,
                                 after=self._dpi_frame)

    def _on_sni_selection(self, *_args):
        if self.sni_var.get() == "Custom …":
            self.custom_sni_label.grid()
            self.e_custom_sni.grid()
        else:
            self.custom_sni_label.grid_remove()
            self.e_custom_sni.grid_remove()

    def _copy_proxy(self):
        try:
            port = int(self.e_socks.get())
        except ValueError:
            port = 10808
        text = f"socks5://127.0.0.1:{port}"
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        self._append_log(f"Copied to clipboard: {text}")

    # ══════════════════════════════════════════════════════════════════════════
    #  Start / Stop
    # ══════════════════════════════════════════════════════════════════════════

    def _start(self):
        try:
            cfg = self._read_config()
        except ValueError as exc:
            messagebox.showerror("Config Error", str(exc))
            return
        if not cfg["CONNECT_IP"]:
            messagebox.showerror("Config Error", "CDN / Endpoint IP is required")
            return

        try:
            save_config(cfg, self.config_path)
        except Exception as exc:
            self._append_log(f"Could not save config: {exc}")

        mode = cfg["connection_mode"]
        gaming = mode == "Gaming Mode"

        # ── Start SNI spoofer (always needed) ─────────────────────────────
        proxy_cfg = {
            "LISTEN_HOST": cfg["LISTEN_HOST"],
            "LISTEN_PORT": cfg["LISTEN_PORT"],
            "CONNECT_IP":  cfg["CONNECT_IP"],
            "CONNECT_PORT": cfg["CONNECT_PORT"],
            "FAKE_SNI":    cfg["FAKE_SNI"],
            "gaming_mode": gaming,
        }
        self.server = ProxyServer(proxy_cfg)
        self.server.on_log = self._append_log
        self.server.on_status_change = self._set_ui_running
        self.server.on_connection_count_change = self._update_counts
        self.server.start()

        # ── Mode-specific services ────────────────────────────────────────
        if mode in ("SNI Only", "Gaming Mode"):
            if not cfg["trojan_password"]:
                messagebox.showerror("Config Error", "V2Ray password is required")
                self.server.stop(); self.server = None
                return
            self.xray = XrayManager(
                socks_port=cfg["socks_port"],
                http_port=cfg["http_port"],
                server_address="127.0.0.1",
                server_port=cfg["LISTEN_PORT"],
                password=cfg["trojan_password"],
                sni=cfg["trojan_sni"],
                transport=cfg["trojan_transport"],
                ws_path=cfg["trojan_path"],
                host=cfg["trojan_host"],
                gaming_mode=gaming,
            )
            self.xray.on_log = self._append_log
            threading.Thread(target=self.xray.start, daemon=True).start()

        elif mode == "SNI + Warp":
            self.warp = WarpManager(
                bind_port=cfg["socks_port"],
                endpoint=f"127.0.0.1:{cfg['LISTEN_PORT']}",
                license_key=cfg["warp_license"],
            )
            self.warp.on_log = self._append_log
            threading.Thread(target=self.warp.start, daemon=True).start()

        self._append_log(f"Mode: {mode}")
        self._append_log(
            f"User proxy  \u2192  SOCKS5 127.0.0.1:{cfg['socks_port']}"
            f"  |  HTTP 127.0.0.1:{cfg['http_port']}")

    def _stop(self):
        def _do_stop():
            if self.xray:
                self.xray.stop()
                self.xray = None
            if self.warp:
                self.warp.stop()
                self.warp = None
            if self.server:
                self.server.stop()
                self.server = None
        threading.Thread(target=_do_stop, daemon=True).start()

    def _on_close(self):
        if self.server and self.server.is_running:
            self._stop()
        self.root.after(600, self.root.destroy)

    # ══════════════════════════════════════════════════════════════════════════

    def run(self):
        self.root.mainloop()


# ── Entry point ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    app = SNIProxyGUI()
    app.run()
