"""Configure and manage an Xray-core subprocess.

The xray.exe binary is bundled inside the application – no download needed.
"""
import json
import os
import subprocess
import sys
import threading

from core.binary_utils import get_bin_dir, get_runtime_dir


class XrayManager:

    def __init__(
        self,
        socks_port: int = 10808,
        http_port: int = 10809,
        server_address: str = "127.0.0.1",
        server_port: int = 40443,
        password: str = "",
        sni: str = "",
        transport: str = "ws",
        ws_path: str = "/",
        host: str = "",
        gaming_mode: bool = False,
    ):
        self.socks_port = socks_port
        self.http_port = http_port
        self.server_address = server_address
        self.server_port = server_port
        self.password = password
        self.sni = sni
        self.transport = transport
        self.ws_path = ws_path
        self.host = host or sni
        self.gaming_mode = gaming_mode

        self.xray_exe = os.path.join(get_bin_dir(), "xray.exe")
        self.config_path = os.path.join(get_runtime_dir(), "xray_config.json")
        self._process: subprocess.Popen | None = None
        self.on_log = None

    # ----------------------------------------------------------------

    def _log(self, msg: str):
        if self.on_log:
            self.on_log(msg)

    @property
    def is_available(self) -> bool:
        return os.path.isfile(self.xray_exe)

    # ----------------------------------------------------------------

    def generate_config(self) -> str:
        """Write an xray JSON config and return its path."""
        stream: dict = {
            "network": self.transport,
            "security": "tls",
            "tlsSettings": {
                "serverName": self.sni,
                "allowInsecure": True,
                "fingerprint": "chrome",
            },
        }
        if self.transport == "ws":
            stream["wsSettings"] = {
                "path": self.ws_path,
                "headers": {"Host": self.host},
            }
        elif self.transport == "grpc":
            stream["grpcSettings"] = {
                "serviceName": self.ws_path.strip("/"),
                "multiMode": not self.gaming_mode,
            }

        if self.gaming_mode:
            stream["sockopt"] = {
                "tcpNoDelay": True,
                "tcpFastOpen": True,
                "tcpKeepAliveInterval": 5,
            }

        outbound: dict = {
            "tag": "proxy",
            "protocol": "trojan",
            "settings": {
                "servers": [{
                    "address": self.server_address,
                    "port": self.server_port,
                    "password": self.password,
                }],
            },
            "streamSettings": stream,
            "mux": {"enabled": False},
        }

        config = {
            "log": {"loglevel": "warning"},
            "inbounds": [
                {
                    "tag": "socks-in",
                    "port": self.socks_port,
                    "listen": "127.0.0.1",
                    "protocol": "socks",
                    "settings": {"auth": "noauth", "udp": True},
                    "sniffing": {
                        "enabled": not self.gaming_mode,
                        "destOverride": ["http", "tls"],
                    },
                },
                {
                    "tag": "http-in",
                    "port": self.http_port,
                    "listen": "127.0.0.1",
                    "protocol": "http",
                    "settings": {},
                },
            ],
            "outbounds": [
                outbound,
                {"tag": "direct", "protocol": "freedom"},
                {"tag": "block", "protocol": "blackhole"},
            ],
        }

        with open(self.config_path, "w") as fp:
            json.dump(config, fp, indent=2)
        return self.config_path

    # ----------------------------------------------------------------

    def start(self):
        if self.is_running:
            self._log("Xray already running")
            return
        if not self.is_available:
            self._log("ERROR: xray.exe not found (binary not bundled)")
            return

        self.generate_config()
        try:
            si = subprocess.STARTUPINFO()
            si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            si.wShowWindow = subprocess.SW_HIDE
            self._process = subprocess.Popen(
                [self.xray_exe, "run", "-config", self.config_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                startupinfo=si,
                creationflags=subprocess.CREATE_NO_WINDOW,
            )
            threading.Thread(target=self._pump_output, daemon=True).start()
            self._log(
                f"Xray started  →  SOCKS5 127.0.0.1:{self.socks_port}"
                f"  |  HTTP 127.0.0.1:{self.http_port}")
        except Exception as exc:
            self._log(f"Failed to start Xray: {exc}")

    def _pump_output(self):
        proc = self._process
        if not proc or not proc.stdout:
            return
        try:
            for raw in proc.stdout:
                line = raw.decode("utf-8", errors="replace").strip()
                if line:
                    self._log(f"[xray] {line}")
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
            self._log("Xray stopped")

    @property
    def is_running(self) -> bool:
        return self._process is not None and self._process.poll() is None
