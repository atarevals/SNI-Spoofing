"""Utilities for downloading and managing external binaries."""
import io
import json
import os
import ssl
import sys
import urllib.request
import zipfile


def get_bin_dir() -> str:
    """Return the ``bin/`` directory containing bundled binaries.

    When running from a PyInstaller ``--onefile`` bundle the binaries live
    inside the temporary ``_MEIPASS`` directory.  During development they
    sit in the project-root ``bin/`` folder.
    """
    if getattr(sys, "frozen", False):
        # PyInstaller bundles --add-data "bin;bin" into _MEIPASS/bin
        d = os.path.join(getattr(sys, "_MEIPASS", os.path.dirname(sys.executable)), "bin")
    else:
        base = os.path.dirname(os.path.abspath(__file__))
        base = os.path.dirname(base)  # up from core/
        d = os.path.join(base, "bin")
    os.makedirs(d, exist_ok=True)
    return d


def get_runtime_dir() -> str:
    """Writable directory next to the exe (or project root in dev).

    Use for config files and logs that need to persist across runs.
    """
    if getattr(sys, "frozen", False):
        d = os.path.dirname(sys.executable)
    else:
        d = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return d


def _ssl_context() -> ssl.SSLContext:
    return ssl.create_default_context()


def download_file(url: str, dest_path: str, progress_cb=None) -> str:
    """Download *url* to *dest_path*.  ``progress_cb(downloaded, total)``."""
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    ctx = _ssl_context()
    with urllib.request.urlopen(req, context=ctx, timeout=120) as resp:
        total = int(resp.headers.get("Content-Length", 0))
        downloaded = 0
        with open(dest_path, "wb") as fp:
            while True:
                chunk = resp.read(65536)
                if not chunk:
                    break
                fp.write(chunk)
                downloaded += len(chunk)
                if progress_cb and total:
                    progress_cb(downloaded, total)
    return dest_path


def extract_zip(zip_path: str, dest_dir: str):
    with zipfile.ZipFile(zip_path, "r") as zf:
        zf.extractall(dest_dir)


def get_github_release_url(repo: str, asset_keywords: list[str]):
    """Return ``(download_url, asset_name)`` for the latest release asset
    whose name contains *all* keywords (case-insensitive)."""
    api = f"https://api.github.com/repos/{repo}/releases/latest"
    req = urllib.request.Request(api, headers={
        "User-Agent": "Mozilla/5.0",
        "Accept": "application/vnd.github.v3+json",
    })
    ctx = _ssl_context()
    with urllib.request.urlopen(req, context=ctx, timeout=30) as resp:
        data = json.loads(resp.read().decode())
    for asset in data.get("assets", []):
        name_lower = asset["name"].lower()
        if all(k.lower() in name_lower for k in asset_keywords):
            return asset["browser_download_url"], asset["name"]
    raise FileNotFoundError(
        f"No asset matching {asset_keywords} in {repo} latest release")
