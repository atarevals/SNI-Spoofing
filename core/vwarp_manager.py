"""Manage Vwarp (warp-plus fork with Psiphon) subprocess.

Vwarp modes
~~~~~~~~~~~
* **warp**     – basic Cloudflare WARP connection
* **psiphon**  – WARP + Psiphon chaining (``--cfon --country XX``)
* **gool**     – warp-in-warp double-hop (``--gool``)

Architecture: All Vwarp traffic is routed through an upstream SOCKS5 proxy
(provided by Xray) so that Cloudflare API registration and WireGuard traffic
pass through the SNI-spoofed tunnel.

  User → Vwarp (SOCKS5) → Xray (SOCKS5 internal) → SNI Spoofer → Internet

The binary is bundled inside the exe; no download required at runtime.
"""
import os
import subprocess
import sys
import threading

from core.binary_utils import get_bin_dir


class VwarpManager:
    EXE_NAME = "vwarp.exe"

    def __init__(
        self,
        bind_port: int = 10820,
        endpoint: str = "162.159.192.1:443",
        license_key: str = "",
        mode: str = "warp",          # "warp" | "psiphon" | "gool"
        psiphon_country: str = "US",
        upstream_proxy: str = "",     # e.g. "socks5://127.0.0.1:10820"
    ):
        self.bind_port = bind_port
        self.endpoint = endpoint
        self.license_key = license_key
        self.mode = mode
        self.psiphon_country = psiphon_country
        self.upstream_proxy = upstream_proxy

        self._exe_path = os.path.join(get_bin_dir(), self.EXE_NAME)
        self._process: subprocess.Popen | None = None
        self.on_log = None

    def _log(self, msg: str):
        if self.on_log:
            self.on_log(msg)

    @property
    def is_available(self) -> bool:
        return os.path.isfile(self._exe_path)

    @property
    def is_running(self) -> bool:
        return self._process is not None and self._process.poll() is None

    def start(self):
        if self.is_running:
            self._log("Vwarp already running")
            return
        if not self.is_available:
            self._log("ERROR: vwarp.exe not found (binary not bundled)")
            return

        cmd = [self._exe_path, "--proxy socks5://127.0.0.1:10808 -b", f"127.0.0.1:{self.bind_port}"]

        if self.mode == "gool":
            cmd.append("--gool")
        elif self.mode == "psiphon":
            cmd += ["--cfon", "--country", self.psiphon_country]
        

        if self.endpoint:
            cmd += ["-e", self.endpoint]

        cmd.append("-4")

        if self.license_key:
            cmd += ["-k", self.license_key]

        # Build environment: force ALL traffic (including API registration
        # to api.cloudflareclient.com) through the upstream SOCKS proxy.
        env = None
        if self.upstream_proxy:
            env = os.environ.copy()
            env["HTTP_PROXY"] = self.upstream_proxy
            env["HTTPS_PROXY"] = self.upstream_proxy
            env["ALL_PROXY"] = self.upstream_proxy

        try:
            si = subprocess.STARTUPINFO()
            si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            si.wShowWindow = subprocess.SW_HIDE
            self._process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                startupinfo=si,
                creationflags=subprocess.CREATE_NO_WINDOW,
                env=env,
            )
            threading.Thread(target=self._pump_output, daemon=True).start()
            mode_label = self.mode.upper()
            if self.mode == "psiphon":
                mode_label += f" ({self.psiphon_country})"
            self._log(
                f"Vwarp [{mode_label}] started → SOCKS5 127.0.0.1:{self.bind_port}"
            )
            if self.upstream_proxy:
                self._log(f"  upstream proxy: {self.upstream_proxy}")
        except Exception as exc:
            self._log(f"Failed to start Vwarp: {exc}")

    def _pump_output(self):
        proc = self._process
        if not proc or not proc.stdout:
            return
        try:
            for raw in proc.stdout:
                line = raw.decode("utf-8", errors="replace").strip()
                if line:
                    self._log(f"[vwarp] {line}")
        except Exception:
            pass

    def stop(self):
        if self._process:
            try:
                self._process.terminate()
                self._process.wait(timeout=5)
            except Exception:
                try:
                    self._process.kill()
                except Exception:
                    pass
            self._process = None
            self._log("Vwarp stopped")
