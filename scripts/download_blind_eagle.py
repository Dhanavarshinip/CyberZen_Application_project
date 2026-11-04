import os
import sys
import json
import urllib.request
from pathlib import Path

DEST_DIR = Path("data/blind_eagle")
DEST_DIR.mkdir(parents=True, exist_ok=True)

GITHUB_API_BASE = "https://api.github.com/repos/attackevals/ael/contents/Enterprise/blind_eagle"
HEADERS = {"User-Agent": "CyberThreat-Downloader"}

def fetch_contents(api_url, local_dir: Path):
    local_dir.mkdir(parents=True, exist_ok=True)
    req = urllib.request.Request(api_url, headers=HEADERS)
    try:
        with urllib.request.urlopen(req) as resp:
            items = json.loads(resp.read().decode())
    except Exception as e:
        print(f"Failed to fetch {api_url}: {e}")
        return

    if not isinstance(items, list):
        print(f"Unexpected response from {api_url}: {items}")
        return

    for item in items:
        name = item.get("name")
        item_type = item.get("type")
        download_url = item.get("download_url")
        item_api_url = item.get("url")

        if item_type == "file":
            local_file = local_dir / name
            print(f"Downloading file: {name} -> {local_file}")
            if download_url:
                try:
                    file_req = urllib.request.Request(download_url, headers=HEADERS)
                    with urllib.request.urlopen(file_req) as f_in, open(local_file, "wb") as f_out:
                        f_out.write(f_in.read())
                    print(f"  [+] Saved {local_file} ({local_file.stat().st_size} bytes)")
                except Exception as err:
                    print(f"  [-] Failed to download {download_url}: {err}")
        elif item_type == "dir":
            sub_local = local_dir / name
            print(f"Entering directory: {name}...")
            fetch_contents(item_api_url, sub_local)

if __name__ == "__main__":
    print(f"Starting download of blind_eagle into {DEST_DIR.resolve()}...")
    fetch_contents(GITHUB_API_BASE, DEST_DIR)
    print("Download completed!")
