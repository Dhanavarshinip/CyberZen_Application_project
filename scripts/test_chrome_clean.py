import subprocess
import time
import json
import urllib.request
import asyncio
import websockets
import os

ext_path = os.path.abspath("chrome_extension")
test_profile = os.path.join(os.environ.get("TEMP", "."), "chrome_clean_test_dir")

cmd = [
    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    f"--load-extension={ext_path}",
    f"--disable-extensions-except={ext_path}",
    f"--user-data-dir={test_profile}",
    "--remote-debugging-port=9224",
    "--no-first-run",
    "--no-default-browser-check",
    "about:blank"
]

print("Launching Chrome...")
p = subprocess.Popen(cmd)
time.sleep(3)

async def check():
    try:
        with urllib.request.urlopen("http://127.0.0.1:9224/json") as resp:
            targets = json.loads(resp.read().decode())
        print(f"Total targets ({len(targets)}):")
        for t in targets:
            print(f"  [{t.get('type')}] {t.get('title')} -> {t.get('url')}")

        pages = [t for t in targets if t.get("type") == "page"]
        if not pages:
            print("No page target!")
            return
        page = pages[0]
        
        async with websockets.connect(page["webSocketDebuggerUrl"]) as ws:
            print("\nNavigating page to https://example.com...")
            await ws.send(json.dumps({
                "id": 1,
                "method": "Page.navigate",
                "params": {"url": "https://example.com"}
            }))
            await ws.recv()
            await asyncio.sleep(3)

            # Check if overlay was created in page DOM
            await ws.send(json.dumps({
                "id": 2,
                "method": "Runtime.evaluate",
                "params": {"expression": "document.getElementById('cyberthreat-ai-security-overlay-root') ? 'OVERLAY_FOUND' : 'OVERLAY_NOT_FOUND'"}
            }))
            res = await ws.recv()
            print("DOM check:", json.loads(res)["result"]["result"]["value"])

    except Exception as e:
        print("Error:", e)
    finally:
        p.terminate()

asyncio.run(check())
