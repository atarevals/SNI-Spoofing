"""Download and manage warp-plus (bepass-org) subprocess.

warp-plus in ``-gool`` mode wraps WireGuard inside gRPC/TLS on port 443,
which lets the SNI spoofer inject a fake ClientHello on the same TCP flow.
"""
import os
import subprocess
import threading

from core.binary_utils import (
    get_bin_dir, download_file, extract_zip, get_github_release_url,
)


class WarpManager:
    REPO = "bepass-org/warp-plus"
    ASSET_KW = ["windows", "amd64"]

    def __init__(
        self,
        bind_port: int = 10808,
        endpoint: str = "127.0.0.1:40443",
        license_key: str = "",
    ):
        self.bind_port = bind_port
        self.endpoint = endpoint
        self.license_key = license_key

        self.bin_dir = get_bin_dir()
        self._exe_path = os.path.join(self.bin_dir, "warp-plus.exe")
        self._process: subprocess.Popen | None = None
        self.on_log = None

    def _log(self, msg: str):
        if self.on_log:
            self.on_log(msg)

    @property
    def is_downloaded(self) -> bool:
        return os.path.isfile(self._exe_path)

    # ----------------------------------------------------------------

    def download(self, progress_cb=None) -> bool:
        if self.is_downloaded:
            self._log("warp-plus already available")
            return True
        try:
            self._log("Fetching latest warp-plus release …")
            url, name = get_github_release_url(self.REPO, self.ASSET_KW)
            if name.lower().endswith(".zip"):
                zip_path = os.path.join(self.bin_dir, name)
                download_file(url, zip_path, progress_cb)
                extract_zip(zip_path, self.bin_dir)
                try:
                    os.remove(zip_path)
                except OSError:
                    pass
                # Rename the extracted exe to a known name
                for fn in os.listdir(self.bin_dir):
                    if "warp" in fn.lower() and fn.endswith(".exe") and fn != "warp-plus.exe":
                        os.rename(
                            os.path.join(self.bin_dir, fn), self._exe_path)
                        break
            else:
                self._log(f"Downloading {name} …")
                download_file(url, self._exe_path, progress_cb)
            if not self.is_downloaded:
                raise FileNotFoundError("warp-plus.exe not found after download")
            self._log("warp-plus ready")
            return True
        except Exception as exc:
            self._log(f"warp-plus download failed: {exc}")
            return False

    # ----------------------------------------------------------------

    def start(self):
        if self.is_running:
            self._log("warp-plus already running")
            return
        if not self.is_downloaded:
            if not self.download():
                return
        cmd = [
            self._exe_path,
            "-gool",
            "-b", f"127.0.0.1:{self.bind_port}",
            "-e", self.endpoint,
            "-4",
        ]
        if self.license_key:
            cmd += ["-k", self.license_key]
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
            )
            threading.Thread(target=self._pump_output, daemon=True).start()
            self._log(f"warp-plus started  →  SOCKS5 127.0.0.1:{self.bind_port}")
        except Exception as exc:
            self._log(f"Failed to start warp-plus: {exc}")

    def _pump_output(self):
        proc = self._process
        if not proc or not proc.stdout:
            return
        try:
            for raw in proc.stdout:
                line = raw.decode("utf-8", errors="replace").strip()
                if line:
                    self._log(f"[warp] {line}")
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
            self._log("warp-plus stopped")

    @property
    def is_running(self) -> bool:
        return self._process is not None and self._process.poll() is None
