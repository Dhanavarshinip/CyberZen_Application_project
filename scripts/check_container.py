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
            print("Navigating to http://httpbin.org/html...")
            await ws.send(json.dumps({
                "id": 1,
                "method": "Page.navigate",
                "params": {"url": "http://httpbin.org/html"}
            }))
            await ws.recv()
            await asyncio.sleep(3)

            # Get full shadow DOM innerHTML
            await ws.send(json.dumps({
                "id": 2,
                "method": "Runtime.evaluate",
                "params": {"expression": "document.getElementById('cyberthreat-ai-security-overlay-root') ? document.getElementById('cyberthreat-ai-security-overlay-root').shadowRoot.querySelector('.ct-container').innerHTML : 'NO_CONTAINER'"}
            }))
            res = await ws.recv()
            val = json.loads(res)["result"]["result"]["value"]
            print("Container length:", len(val))

            await ws.send(json.dumps({
                "id": 3,
                "method": "Runtime.evaluate",
                "params": {"expression": "document.getElementById('cyberthreat-ai-security-overlay-root').shadowRoot.querySelector('.ct-badge-title') ? document.getElementById('cyberthreat-ai-security-overlay-root').shadowRoot.querySelector('.ct-badge-title').textContent : 'NO_TITLE'"}
            }))
            res_title = await ws.recv()
            title_text = json.loads(res_title)["result"]["result"]["value"]
            print("Rendered Badge Title:", title_text.encode('ascii', errors='replace').decode('ascii'))

            await ws.send(json.dumps({
                "id": 4,
                "method": "Runtime.evaluate",
                "params": {"expression": "document.getElementById('cyberthreat-ai-security-overlay-root').shadowRoot.querySelector('.ct-hostname') ? document.getElementById('cyberthreat-ai-security-overlay-root').shadowRoot.querySelector('.ct-hostname').textContent : 'NO_HOST'"}
            }))
            res_host = await ws.recv()
            print("Rendered Hostname:", json.loads(res_host)["result"]["result"]["value"])

            await ws.send(json.dumps({
                "id": 5,
                "method": "Runtime.evaluate",
                "params": {"expression": "document.getElementById('cyberthreat-ai-security-overlay-root').shadowRoot.querySelector('.ct-details') ? document.getElementById('cyberthreat-ai-security-overlay-root').shadowRoot.querySelector('.ct-details').textContent.trim() : 'NO_DETAILS'"}
            }))
            res_det = await ws.recv()
            det_text = json.loads(res_det)["result"]["result"]["value"]
            print("Rendered Details:", det_text.encode('ascii', errors='replace').decode('ascii'))

    except Exception as e:
        print("Error:", e)
    finally:
        p.terminate()

asyncio.run(check())
