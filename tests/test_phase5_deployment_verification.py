"""
Phase 5 Verification: Installer, Performance & Deployment
Tests verify:
1. Packaging and release metadata endpoint (/api/download/info)
2. Chrome download warning analysis & Authenticode EV signing guidance (/api/download/signing-guidance)
3. Electron single-instance lock and duplicate backend process prevention
4. Clean process tree termination on exit in electron/main.js
5. Desktop shortcut configuration (create_desktop_shortcut.ps1)
6. Production frontend bundle build integrity (dist/index.html & assets)
"""

import os
from pathlib import Path
from fastapi.testclient import TestClient

from backend.main import app

def test_download_info_metadata():
    client = TestClient(app)
    resp = client.get("/api/download/info")
    assert resp.status_code == 200
    data = resp.json()
    assert "version" in data
    assert "filename" in data
    assert "sha256_checksum" in data
    assert "publisher_signing_status" in data
    assert "download_url" in data

def test_chrome_warning_and_ev_signing_guidance():
    client = TestClient(app)
    resp = client.get("/api/download/signing-guidance")
    assert resp.status_code == 200
    data = resp.json()
    assert "root_cause_analysis" in data
    assert "chrome_download_warning" in data["root_cause_analysis"]
    assert "smartscreen_warning" in data["root_cause_analysis"]
    assert "production_resolution" in data
    assert "ev_code_signing" in data["production_resolution"]
    assert "timestamping" in data["production_resolution"]

def test_electron_single_instance_lock_and_process_safety():
    main_js_path = Path("electron/main.js")
    assert main_js_path.exists(), "electron/main.js must exist"
    content = main_js_path.read_text(encoding="utf-8")

    # 1. Verify single-instance lock
    assert "app.requestSingleInstanceLock()" in content, "electron/main.js must enforce single-instance lock"
    assert "second-instance" in content, "electron/main.js must focus existing window on second-instance"

    # 2. Verify backend attachment before spawn to prevent duplicates
    assert "ensureBackendRunning" in content
    assert "http://127.0.0.1:8000/api/health" in content

    # 3. Verify clean process termination on exit
    assert "taskkill" in content or "SIGTERM" in content, "electron/main.js must cleanly terminate backend on exit"

def test_desktop_shortcut_script_integrity():
    ps1_path = Path("create_desktop_shortcut.ps1")
    assert ps1_path.exists(), "create_desktop_shortcut.ps1 must exist"
    content = ps1_path.read_text(encoding="utf-8")
    assert "CyberZen Operations Center.lnk" in content or "CyberThreat AI Operations Center.lnk" in content
    assert "CreateShortcut" in content

def test_production_bundle_integrity():
    dist_html = Path("dist/index.html")
    assert dist_html.exists(), "dist/index.html must exist after vite build"
    html_content = dist_html.read_text(encoding="utf-8")
    assert len(html_content) > 100
    assert "<div id=\"root\">" in html_content or "<script" in html_content

    dist_assets = Path("dist/assets")
    assert dist_assets.exists() and dist_assets.is_dir()
    js_files = list(dist_assets.glob("*.js"))
    css_files = list(dist_assets.glob("*.css"))
    assert len(js_files) > 0, "Production bundle must contain compiled JS assets"
    assert len(css_files) > 0, "Production bundle must contain compiled CSS assets"
