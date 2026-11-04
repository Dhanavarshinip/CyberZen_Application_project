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
    f"--disable-extensions-except={ext_path}",
    f"--user-data-dir={test_profile}",
    "--remote-debugging-port=9222",
    "--no-first-run",
    "--no-default-browser-check",
    "http://example.com"
]

print("Launching Chrome with args:", cmd)
p = subprocess.Popen(cmd)
time.sleep(3)

async def check():
    try:
        with urllib.request.urlopen("http://127.0.0.1:9222/json") as resp:
            targets = json.loads(resp.read().decode())
        print("Total targets:", len(targets))
        for t in targets:
            print("Target:", t.get("type"), t.get("title"), t.get("url"))

        pages = [t for t in targets if t.get("type") == "page"]
        if not pages:
            print("No page target found!")
            return
        
        page = pages[0]
        ws_url = page["webSocketDebuggerUrl"]
        print("Connecting to page:", ws_url)
        async with websockets.connect(ws_url) as ws:
            # Check injected
            await ws.send(json.dumps({
                "id": 1,
                "method": "Runtime.evaluate",
                "params": {"expression": "window.__CYBERTHREAT_AI_INJECTED__"}
            }))
            res = await ws.recv()
            print("window.__CYBERTHREAT_AI_INJECTED__:", res)

            # Check overlay
            await ws.send(json.dumps({
                "id": 2,
                "method": "Runtime.evaluate",
                "params": {"expression": "document.getElementById('cyberthreat-ai-security-overlay-root') ? document.getElementById('cyberthreat-ai-security-overlay-root').outerHTML.substring(0, 200) : 'NOT_FOUND'"}
            }))
            res2 = await ws.recv()
            print("Overlay root HTML:", res2)

    except Exception as e:
        print("Error during check:", e)
    finally:
        p.terminate()

asyncio.run(check())
