#!/usr/bin/env python3
"""Download Xray-core and Vwarp Windows-amd64 binaries into ``bin/``.

Run this before ``pyinstaller`` so the binaries get bundled into the exe.
Can also be used in GitHub Actions CI.
"""
import io
import json
import os
import ssl
import sys
import urllib.request
import zipfile

BIN_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "bin")

ASSETS = [
    {
        "repo": "XTLS/Xray-core",
        "keywords": ["xray", "windows", "64"],
        "rename": {"xray.exe": "xray.exe"},  # keep name
    },
    {
        "repo": "voidr3aper-anon/Vwarp",
        "keywords": ["windows", "amd64"],
        "rename": {},  # will rename any .exe → vwarp.exe
        "target_exe": "vwarp.exe",
    },
]


def _ctx() -> ssl.SSLContext:
    return ssl.create_default_context()


def get_latest_asset(repo: str, keywords: list[str]):
    api = f"https://api.github.com/repos/{repo}/releases/latest"
    req = urllib.request.Request(api, headers={
        "User-Agent": "Mozilla/5.0",
        "Accept": "application/vnd.github.v3+json",
    })
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        req.add_header("Authorization", f"token {token}")
    with urllib.request.urlopen(req, context=_ctx(), timeout=60) as r:
        data = json.loads(r.read().decode())
    for asset in data.get("assets", []):
        name = asset["name"].lower()
        if all(k.lower() in name for k in keywords):
            return asset["browser_download_url"], asset["name"]
    raise FileNotFoundError(f"No asset matching {keywords} in {repo}")


def download(url: str, dest: str):
    print(f"  Downloading: {url}")
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        req.add_header("Authorization", f"token {token}")
    with urllib.request.urlopen(req, context=_ctx(), timeout=300) as r:
        data = r.read()
    with open(dest, "wb") as f:
        f.write(data)
    print(f"  Saved: {dest} ({len(data) / 1048576:.1f} MB)")


def extract_zip(zip_path: str, dest_dir: str):
    with zipfile.ZipFile(zip_path, "r") as zf:
        zf.extractall(dest_dir)


def main():
    os.makedirs(BIN_DIR, exist_ok=True)
    print(f"Binary directory: {BIN_DIR}\n")

    for spec in ASSETS:
        repo = spec["repo"]
        print(f"[{repo}]")
        url, name = get_latest_asset(repo, spec["keywords"])

        zip_path = os.path.join(BIN_DIR, name)
        download(url, zip_path)

        if name.lower().endswith(".zip"):
            print(f"  Extracting {name} …")
            extract_zip(zip_path, BIN_DIR)
            os.remove(zip_path)

        # Handle renames
        target_exe = spec.get("target_exe")
        if target_exe:
            target_path = os.path.join(BIN_DIR, target_exe)
            if not os.path.isfile(target_path):
                for fn in os.listdir(BIN_DIR):
                    if fn.lower().endswith(".exe") and fn != target_exe:
                        src = os.path.join(BIN_DIR, fn)
                        if repo.split("/")[-1].lower() in fn.lower() or "warp" in fn.lower():
                            os.rename(src, target_path)
                            print(f"  Renamed {fn} → {target_exe}")
                            break

        for rn_from, rn_to in spec.get("rename", {}).items():
            src = os.path.join(BIN_DIR, rn_from)
            dst = os.path.join(BIN_DIR, rn_to)
            if os.path.isfile(src) and src != dst:
                os.rename(src, dst)
                print(f"  Renamed {rn_from} → {rn_to}")

        print()

    # Verify
    expected = ["xray.exe", "vwarp.exe"]
    missing = [e for e in expected if not os.path.isfile(os.path.join(BIN_DIR, e))]
    if missing:
        print(f"WARNING: Missing binaries: {missing}")
        sys.exit(1)
    else:
        print("All binaries ready:")
        for e in expected:
            size = os.path.getsize(os.path.join(BIN_DIR, e))
            print(f"  {e}  ({size / 1048576:.1f} MB)")


if __name__ == "__main__":
    main()
