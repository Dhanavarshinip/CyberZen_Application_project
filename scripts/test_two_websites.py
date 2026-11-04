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

print("Starting browser with extension...")
p = subprocess.Popen(cmd)
time.sleep(3)

async def run_tests():
    try:
        with urllib.request.urlopen("http://127.0.0.1:9223/json") as resp:
            targets = json.loads(resp.read().decode())
        page = next(t for t in targets if t.get("type") == "page")
        ws_url = page["webSocketDebuggerUrl"]

        test_urls = [
            ("Website 1 (Ordinary Safe)", "https://example.com"),
            ("Website 2 (Ordinary Safe / Reputable)", "https://httpbin.org/html"),
            ("Website 3 (Phishing Threat)", "http://httpbin.org/get?action=login-verify&redirect=http://account.zip")
        ]

        async with websockets.connect(ws_url) as ws:
            for label, url in test_urls:
                print(f"\n==========================================")
                print(f"Testing {label}: {url}")
                print(f"==========================================")
                
                # Navigate to the website without clicking anything
                await ws.send(json.dumps({
                    "id": 1,
                    "method": "Page.navigate",
                    "params": {"url": url}
                }))
                await ws.recv()

                # Wait for load & analysis
                await asyncio.sleep(2.5)

                # 1. Verify overlay exists in DOM
                await ws.send(json.dumps({
                    "id": 2,
                    "method": "Runtime.evaluate",
                    "params": {"expression": "!!document.getElementById('cyberthreat-ai-security-overlay-root')"}
                }))
                res_has_root = json.loads(await ws.recv())["result"]["result"]["value"]
                print(f"[+] Overlay Host Mounted in DOM: {res_has_root}")

                # 2. Verify badge title
                await ws.send(json.dumps({
                    "id": 3,
                    "method": "Runtime.evaluate",
                    "params": {"expression": "document.getElementById('cyberthreat-ai-security-overlay-root').shadowRoot.querySelector('.ct-badge-title') ? document.getElementById('cyberthreat-ai-security-overlay-root').shadowRoot.querySelector('.ct-badge-title').textContent : 'NONE'"}
                }))
                badge_title = json.loads(await ws.recv())["result"]["result"]["value"]
                print(f"[+] Rendered Verdict Badge: {badge_title.encode('ascii', errors='replace').decode('ascii')}")

                # 3. Verify hostname displayed
                await ws.send(json.dumps({
                    "id": 4,
                    "method": "Runtime.evaluate",
                    "params": {"expression": "document.getElementById('cyberthreat-ai-security-overlay-root').shadowRoot.querySelector('.ct-hostname') ? document.getElementById('cyberthreat-ai-security-overlay-root').shadowRoot.querySelector('.ct-hostname').textContent : 'NONE'"}
                }))
                hostname = json.loads(await ws.recv())["result"]["result"]["value"]
                print(f"[+] Rendered Hostname: {hostname}")

                # 4. Verify risk score & details
                await ws.send(json.dumps({
                    "id": 5,
                    "method": "Runtime.evaluate",
                    "params": {"expression": "document.getElementById('cyberthreat-ai-security-overlay-root').shadowRoot.querySelector('.ct-details') ? document.getElementById('cyberthreat-ai-security-overlay-root').shadowRoot.querySelector('.ct-details').textContent.trim() : 'NONE'"}
                }))
                details = json.loads(await ws.recv())["result"]["result"]["value"]
                print(f"[+] Rendered Risk Details: {details.encode('ascii', errors='replace').decode('ascii')}")

                assert res_has_root is True, f"Failed: overlay not mounted for {url}"
                assert "NONE" not in badge_title, f"Failed: badge title missing for {url}"

    except Exception as e:
        print("Test error:", e)
    finally:
        p.terminate()

asyncio.run(run_tests())
