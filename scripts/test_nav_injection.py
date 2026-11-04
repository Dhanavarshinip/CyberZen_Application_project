import subprocess
import time
import json
import urllib.request
import asyncio
import websockets
import os

ext_path = os.path.abspath("chrome_extension")
test_profile = os.path.join(os.environ.get("TEMP", "."), "edge_test_profile")

cmd = [
    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    f"--load-extension={ext_path}",
    f"--user-data-dir={test_profile}",
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
        pages = [t for t in targets if t.get("type") == "page"]
        page = pages[0]
        ws_url = page["webSocketDebuggerUrl"]
        
        async with websockets.connect(ws_url) as ws:
            # Navigate to example.com
            print("Navigating to https://example.com...")
            await ws.send(json.dumps({
                "id": 1,
                "method": "Page.navigate",
                "params": {"url": "https://example.com"}
            }))
            res_nav = await ws.recv()
            print("Page.navigate:", res_nav)

            # Wait for page to load
            await asyncio.sleep(2)

            # Check injection
            await ws.send(json.dumps({
                "id": 2,
                "method": "Runtime.evaluate",
                "params": {"expression": "window.__CYBERTHREAT_AI_INJECTED__"}
            }))
            res_inj = await ws.recv()
            print("window.__CYBERTHREAT_AI_INJECTED__:", res_inj)

            # Check overlay root
            await ws.send(json.dumps({
                "id": 3,
                "method": "Runtime.evaluate",
                "params": {"expression": "document.getElementById('cyberthreat-ai-security-overlay-root') ? document.getElementById('cyberthreat-ai-security-overlay-root').shadowRoot.innerHTML : 'NOT_FOUND'"}
            }))
            res_root = await ws.recv()
            print("Overlay Shadow DOM HTML:", res_root[:400])

    except Exception as e:
        print("Error:", e)
    finally:
        p.terminate()

asyncio.run(check())
