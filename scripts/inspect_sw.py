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
    r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
    f"--load-extension={ext_path}",
    f"--user-data-dir={test_profile}",
    "--remote-debugging-port=9223",
    "--no-first-run",
    "--no-default-browser-check",
    "http://example.com"
]

p = subprocess.Popen(cmd)
time.sleep(3)

async def check():
    try:
        with urllib.request.urlopen("http://127.0.0.1:9223/json") as resp:
            targets = json.loads(resp.read().decode())
        sws = [t for t in targets if "meljfnndcgobijakafkkjichfpncbpme" in t.get("url", "")]
        if not sws:
            print("Extension service worker not found!")
            return
        
        sw = sws[0]
        print("Found Extension Service Worker:", sw["title"], sw["url"])
        ws_url = sw["webSocketDebuggerUrl"]
        async with websockets.connect(ws_url) as ws:
            # Enable Log and Runtime
            await ws.send(json.dumps({"id": 1, "method": "Runtime.enable"}))
            res = await ws.recv()
            print("Runtime.enable:", res)

            # Check service worker status
            await ws.send(json.dumps({
                "id": 2,
                "method": "Runtime.evaluate",
                "params": {"expression": "typeof evaluateUrl"}
            }))
            res2 = await ws.recv()
            print("typeof evaluateUrl:", res2)

    except Exception as e:
        print("Error:", e)
    finally:
        p.terminate()

asyncio.run(check())
