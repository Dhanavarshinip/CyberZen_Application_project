import subprocess
import time
import json
import urllib.request
import asyncio
import websockets
import os

ext_path = os.path.abspath("chrome_extension")
test_profile = os.path.join(os.environ.get("TEMP", "."), "chrome_test_profile")

cmd = [
    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    f"--load-extension={ext_path}",
    f"--user-data-dir={test_profile}",
    "--enable-automation",
    "--remote-debugging-port=9223",
    "--no-first-run",
    "--no-default-browser-check",
    "about:blank"
]

p = subprocess.Popen(cmd)
time.sleep(3)

async def check():
    try:
        with urllib.request.urlopen("http://127.0.0.1:9223/json") as resp:
            targets = json.loads(resp.read().decode())
        sws = [t for t in targets if "background.js" in t.get("url", "")]
        print("Found background targets:", len(sws))
        for t in targets:
            print("Target:", t.get("type"), t.get("title"), t.get("url"))

        pages = [t for t in targets if t.get("type") == "page"]
        page = pages[0]
        ws_url = page["webSocketDebuggerUrl"]
        
        async with websockets.connect(ws_url) as ws:
            print("Navigating to https://example.com...")
            await ws.send(json.dumps({
                "id": 1,
                "method": "Page.navigate",
                "params": {"url": "https://example.com"}
            }))
            await ws.recv()
            await asyncio.sleep(2)

            # Check overlay root
            await ws.send(json.dumps({
                "id": 2,
                "method": "Runtime.evaluate",
                "params": {"expression": "document.getElementById('cyberthreat-ai-security-overlay-root') ? 'FOUND' : 'NOT_FOUND'"}
            }))
            res = await ws.recv()
            print("Overlay root:", res)

    except Exception as e:
        print("Error:", e)
    finally:
        p.terminate()

asyncio.run(check())
