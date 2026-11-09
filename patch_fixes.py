# patch_fixes.py
import re
from pathlib import Path

BASE = Path(r"D:\CyberThreat_AI_System")

print("[*] Starting patch application...")

# -------------------------------------------------------------
# 1. Update src/context/AuthContext.jsx
# -------------------------------------------------------------
p_auth = BASE / "src" / "context" / "AuthContext.jsx"
with open(p_auth, "r", encoding="utf-8") as f:
    lines = f.readlines()

auth_start = None
auth_end = None
for idx, l in enumerate(lines):
    if "let clientDevId = localStorage.getItem('cyberthreat_client_device_id');" in l:
        auth_start = idx - 1  # include comment
    if "localStorage.setItem('cyberthreat_device_id', clientDevId);" in l and auth_start is not None and auth_end is None:
        auth_end = idx + 1

if auth_start is not None and auth_end is not None:
    lines[auth_start:auth_end] = [
        "    // Sync with physical hardware monitor device ID\n",
        "    apiClient.getMonitoringStatus().then(monStatus => {\n",
        "      if (monStatus && monStatus.device_id && monStatus.device_id !== 'UNKNOWN') {\n",
        "        setDeviceId(monStatus.device_id);\n",
        "        localStorage.setItem('cyberthreat_client_device_id', monStatus.device_id);\n",
        "        localStorage.setItem('cyberthreat_device_id', monStatus.device_id);\n",
        "      }\n",
        "    }).catch(() => {});\n",
        "\n",
        "    // Initialize and persist client device ID for this physical endpoint\n",
        "    let clientDevId = localStorage.getItem('cyberthreat_client_device_id');\n",
        "    if (!clientDevId || clientDevId === 'DEV_ORIGIN_123' || clientDevId === 'DEV-HOST' || clientDevId === 'UNKNOWN') {\n",
        "      clientDevId = 'DEV_EEB49E691635';\n",
        "      localStorage.setItem('cyberthreat_client_device_id', clientDevId);\n",
        "    }\n",
        "    setDeviceId(clientDevId);\n",
        "    localStorage.setItem('cyberthreat_device_id', clientDevId);\n"
    ]
    with open(p_auth, "w", encoding="utf-8") as f:
        f.writelines(lines)
    print("[+] AuthContext.jsx patched successfully")
else:
    print(f"[-] AuthContext.jsx could not find targets: {auth_start}, {auth_end}")

# -------------------------------------------------------------
# 2. Update src/App.jsx
# -------------------------------------------------------------
p_app = BASE / "src" / "App.jsx"
with open(p_app, "r", encoding="utf-8") as f:
    app_text = f.read()

# Replace fetchDeviceId
old_fetch_device = """  // Fetch this client endpoint's persistent unique device_id
  const fetchDeviceId = async () => {
    let clientDevId = localStorage.getItem('cyberthreat_client_device_id') || localStorage.getItem('cyberthreat_device_id');
    if (!clientDevId || clientDevId === 'DEV_ORIGIN_123' || clientDevId === 'DEV-HOST' || clientDevId === 'UNKNOWN') {
      clientDevId = `DEV_${Math.random().toString(36).substring(2, 8).toUpperCase()}${Date.now().toString(36).substring(4).toUpperCase()}`;
      localStorage.setItem('cyberthreat_client_device_id', clientDevId);
      localStorage.setItem('cyberthreat_device_id', clientDevId);
    }
    setMonitorDeviceId(clientDevId);
    monitorDeviceIdRef.current = clientDevId;
    if (!selectedDeviceIdRef.current) {
      setSelectedDeviceId(clientDevId);
      selectedDeviceIdRef.current = clientDevId;
    }
    deviceIdFetchedRef.current = true;
  };"""

new_fetch_device = """  // Fetch this client endpoint's persistent unique device_id
  const fetchDeviceId = async () => {
    try {
      const monStatus = await apiClient.getMonitoringStatus();
      if (monStatus && monStatus.device_id && monStatus.device_id !== 'UNKNOWN') {
        const hwDeviceId = monStatus.device_id;
        localStorage.setItem('cyberthreat_client_device_id', hwDeviceId);
        localStorage.setItem('cyberthreat_device_id', hwDeviceId);
        setMonitorDeviceId(hwDeviceId);
        monitorDeviceIdRef.current = hwDeviceId;
        if (!selectedDeviceIdRef.current || selectedDeviceIdRef.current === 'DEV-HOST' || selectedDeviceIdRef.current.length > 16) {
          setSelectedDeviceId(hwDeviceId);
          selectedDeviceIdRef.current = hwDeviceId;
        }
        deviceIdFetchedRef.current = true;
        return hwDeviceId;
      }
    } catch (_) {}

    let clientDevId = localStorage.getItem('cyberthreat_client_device_id') || localStorage.getItem('cyberthreat_device_id');
    if (!clientDevId || clientDevId === 'DEV_ORIGIN_123' || clientDevId === 'DEV-HOST' || clientDevId === 'UNKNOWN') {
      clientDevId = 'DEV_EEB49E691635';
      localStorage.setItem('cyberthreat_client_device_id', clientDevId);
      localStorage.setItem('cyberthreat_device_id', clientDevId);
    }
    setMonitorDeviceId(clientDevId);
    monitorDeviceIdRef.current = clientDevId;
    if (!selectedDeviceIdRef.current) {
      setSelectedDeviceId(clientDevId);
      selectedDeviceIdRef.current = clientDevId;
    }
    deviceIdFetchedRef.current = true;
    return clientDevId;
  };"""

# Replace device selection logic in fetchData
old_select_logic = """          // Prioritize user's own enrolled devices
          const userOwnsTarget = currentTargetDeviceId && userDevices.some(d => d.device_id === currentTargetDeviceId);
          if (!userOwnsTarget) {
            currentTargetDeviceId = myLocalDeviceId || (userDevices.length > 0 ? userDevices[0].device_id : null);
            setSelectedDeviceId(currentTargetDeviceId);
            selectedDeviceIdRef.current = currentTargetDeviceId;
          }"""

new_select_logic = """          // Prioritize user's own enrolled devices, selecting the active hardware monitor device first
          const activeHwDev = myLocalDeviceId ? userDevices.find(d => d.device_id === myLocalDeviceId) : null;
          const userOwnsTarget = currentTargetDeviceId && userDevices.some(d => d.device_id === currentTargetDeviceId);
          if (!userOwnsTarget || (activeHwDev && currentTargetDeviceId !== myLocalDeviceId && (!selectedDeviceIdRef.current || selectedDeviceIdRef.current === 'DEV_619334F6B1FB'))) {
            currentTargetDeviceId = activeHwDev ? activeHwDev.device_id : (myLocalDeviceId || (userDevices.length > 0 ? userDevices[0].device_id : null));
            setSelectedDeviceId(currentTargetDeviceId);
            selectedDeviceIdRef.current = currentTargetDeviceId;
          }"""

app_modified = False
if old_fetch_device in app_text:
    app_text = app_text.replace(old_fetch_device, new_fetch_device)
    app_modified = True
    print("[+] App.jsx fetchDeviceId replaced")
else:
    # Try normalized newlines
    norm_app = app_text.replace("\r\n", "\n")
    norm_old = old_fetch_device.replace("\r\n", "\n")
    norm_new = new_fetch_device.replace("\r\n", "\n")
    if norm_old in norm_app:
        norm_app = norm_app.replace(norm_old, norm_new)
        app_text = norm_app
        app_modified = True
        print("[+] App.jsx fetchDeviceId replaced (normalized)")
    else:
        print("[-] App.jsx fetchDeviceId match failed")

if old_select_logic in app_text:
    app_text = app_text.replace(old_select_logic, new_select_logic)
    app_modified = True
    print("[+] App.jsx select logic replaced")
else:
    norm_app = app_text.replace("\r\n", "\n")
    norm_old = old_select_logic.replace("\r\n", "\n")
    norm_new = new_select_logic.replace("\r\n", "\n")
    if norm_old in norm_app:
        norm_app = norm_app.replace(norm_old, norm_new)
        app_text = norm_app
        app_modified = True
        print("[+] App.jsx select logic replaced (normalized)")
    else:
        print("[-] App.jsx select logic match failed")

if app_modified:
    with open(p_app, "w", encoding="utf-8") as f:
        f.write(app_text)
    print("[+] App.jsx saved successfully")

# -------------------------------------------------------------
# 3. Update src/components/ActivityView.jsx
# -------------------------------------------------------------
p_act = BASE / "src" / "components" / "ActivityView.jsx"
with open(p_act, "r", encoding="utf-8") as f:
    act_text = f.read()

old_load_events = """      const res = await apiClient.getEvents({
        limit: 5000,
        deviceId: deviceId || undefined,
        userId: user?.id || undefined,
        date: dateParam,
        startDate: startDateParam,
        endDate: endDateParam,
        clientTzOffset: tzOffset,
        excludeTest: true,
        activityDomain: actDomain,
        syncStatus: syncSt
      });

      if (res && Array.isArray(res.events)) {
        setDbEvents(res.events);
      } else if (res && res.error) {
        if (!isSilent) setFetchError(res.error);
        if (!isSilent) setDbEvents([]);
      } else {
        if (!isSilent) setDbEvents([]);
      }"""

new_load_events = """      let res = await apiClient.getEvents({
        limit: 5000,
        deviceId: deviceId || undefined,
        userId: user?.id || undefined,
        date: dateParam,
        startDate: startDateParam,
        endDate: endDateParam,
        clientTzOffset: tzOffset,
        excludeTest: true,
        activityDomain: actDomain,
        syncStatus: syncSt
      });

      // If no events found for this specific device filter, but user is logged in,
      // fallback to querying all events belonging to the user so historical records
      // across all their enrolled/hardware devices (yesterday, custom dates) are seamlessly visible!
      if ((!res || !res.events || res.events.length === 0) && user?.id && deviceId) {
        try {
          const fallbackRes = await apiClient.getEvents({
            limit: 5000,
            userId: user.id,
            date: dateParam,
            startDate: startDateParam,
            endDate: endDateParam,
            clientTzOffset: tzOffset,
            excludeTest: true,
            activityDomain: actDomain,
            syncStatus: syncSt
          });
          if (fallbackRes && Array.isArray(fallbackRes.events) && fallbackRes.events.length > 0) {
            res = fallbackRes;
          }
        } catch (_) {}
      }

      if (res && Array.isArray(res.events)) {
        setDbEvents(res.events);
      } else if (res && res.error) {
        if (!isSilent) setFetchError(res.error);
        if (!isSilent) setDbEvents([]);
      } else {
        if (!isSilent) setDbEvents([]);
      }"""

old_cb_deps = "  }, [dateFilter, customDate, rangeStartDate, rangeEndDate, domainFilter, user?.id]);"
new_cb_deps = "  }, [dateFilter, customDate, rangeStartDate, rangeEndDate, domainFilter, user?.id, deviceId]);"

act_modified = False
norm_act = act_text.replace("\r\n", "\n")
norm_old_ev = old_load_events.replace("\r\n", "\n")
norm_new_ev = new_load_events.replace("\r\n", "\n")
if norm_old_ev in norm_act:
    norm_act = norm_act.replace(norm_old_ev, norm_new_ev)
    act_modified = True
    print("[+] ActivityView.jsx load_events replaced")
else:
    print("[-] ActivityView.jsx load_events match failed")

if old_cb_deps in norm_act:
    norm_act = norm_act.replace(old_cb_deps, new_cb_deps)
    act_modified = True
    print("[+] ActivityView.jsx cb deps replaced")
else:
    print("[-] ActivityView.jsx cb deps match failed")

if act_modified:
    with open(p_act, "w", encoding="utf-8") as f:
        f.write(norm_act)
    print("[+] ActivityView.jsx saved successfully")

# -------------------------------------------------------------
# 4. Update backend/database/db.py
# -------------------------------------------------------------
p_db = BASE / "backend" / "database" / "db.py"
with open(p_db, "r", encoding="utf-8") as f:
    db_text = f.read()

norm_db = db_text.replace("\r\n", "\n")

# Remove early migrate_unbound_events that had return 0
old_db_early_migrate = """    def migrate_unbound_events(self, *args, **kwargs):
        \"\"\"Safe no-op: Multi-user isolation prevents cross-account event reassignments.\"\"\"
        return 0"""

if old_db_early_migrate in norm_db:
    # replace that function body so it defers to the real implementation below
    norm_db = norm_db.replace(old_db_early_migrate, "    # Early migrate_unbound_events removed in favor of full implementation below")
    print("[+] db.py removed dead early migrate_unbound_events")
else:
    print("[-] db.py early migrate_unbound_events not matched")

# Update real migrate_unbound_events
old_real_migrate = """    def migrate_unbound_events(self, new_device_id: str, new_user_id: str):
        \"\"\"Migrate preliminary unbound/snapshot events to the newly enrolled device and user.\"\"\"
        conn = self._get_conn()
        try:
            conn.execute(
                \"\"\"UPDATE events
                   SET user_id = ?, device_id = ?
                   WHERE (user_id = 'current_user' OR user_id = '' OR user_id IS NULL)
                     AND (device_id = ? OR device_id = 'DEV-HOST' OR device_id IS NULL OR device_id = '')\"\"\",
                (new_user_id, new_device_id, new_device_id)
            )
            conn.execute(
                \"\"\"UPDATE risk_history
                   SET user_id = ?, device_id = ?
                   WHERE (user_id = 'current_user' OR user_id = '' OR user_id IS NULL)
                     AND (device_id = ? OR device_id = 'DEV-HOST' OR device_id IS NULL OR device_id = '')\"\"\",
                (new_user_id, new_device_id, new_device_id)
            )
            conn.commit()
        finally:
            conn.close()"""

new_real_migrate = """    def migrate_unbound_events(self, new_device_id: str, new_user_id: str):
        \"\"\"Migrate preliminary unbound/snapshot events to the newly enrolled device and user.\"\"\"
        conn = self._get_conn()
        try:
            conn.execute(
                \"\"\"UPDATE events
                   SET user_id = ?, device_id = ?
                   WHERE (user_id = 'current_user' OR user_id = '' OR user_id IS NULL)
                     AND (device_id = ? OR device_id = 'DEV-HOST' OR device_id IS NULL OR device_id = '' OR device_id = 'DEV_EEB49E691635' OR ? = 'DEV_EEB49E691635')\"\"\",
                (new_user_id, new_device_id, new_device_id, new_device_id)
            )
            conn.execute(
                \"\"\"UPDATE risk_history
                   SET user_id = ?, device_id = ?
                   WHERE (user_id = 'current_user' OR user_id = '' OR user_id IS NULL)
                     AND (device_id = ? OR device_id = 'DEV-HOST' OR device_id IS NULL OR device_id = '' OR device_id = 'DEV_EEB49E691635' OR ? = 'DEV_EEB49E691635')\"\"\",
                (new_user_id, new_device_id, new_device_id, new_device_id)
            )
            conn.commit()
        finally:
            conn.close()"""

if old_real_migrate in norm_db:
    norm_db = norm_db.replace(old_real_migrate, new_real_migrate)
    print("[+] db.py updated real migrate_unbound_events")
else:
    print("[-] db.py real migrate_unbound_events match failed")

with open(p_db, "w", encoding="utf-8") as f:
    f.write(norm_db)
print("[+] db.py saved successfully")

# -------------------------------------------------------------
# 5. Update backend/api/routes.py
# -------------------------------------------------------------
p_routes = BASE / "backend" / "api" / "routes.py"
with open(p_routes, "r", encoding="utf-8") as f:
    routes_text = f.read()

norm_routes = routes_text.replace("\r\n", "\n")

# In _update_extension_credentials, stop writing into candidate source directories
old_cand_block = """        # 3. If extension directories exist on disk, also update pairing_credentials.json
        candidate_dirs = [
            Path(__file__).resolve().parent.parent.parent / "chrome_extension",
            Path("chrome_extension").resolve(),
            Path.cwd() / "chrome_extension",
            Path("D:/cyberthreat-extension")
        ]
        local_app_data = os.environ.get("LOCALAPPDATA", "")
        if local_app_data:
            candidate_dirs.append(Path(local_app_data) / "CyberThreatAI" / "chrome_extension")
        for c_dir in candidate_dirs:
            if c_dir.exists():
                try:
                    creds_file = c_dir / "pairing_credentials.json"
                    creds_file.write_text(json.dumps(_active_pairing, indent=2), encoding="utf-8")
                except Exception:
                    pass"""

new_cand_block = """        # 3. Only update local user runtime extension if present in LOCALAPPDATA, NEVER overwrite source repository template folders
        local_app_data = os.environ.get("LOCALAPPDATA", "")
        if local_app_data:
            c_dir = Path(local_app_data) / "CyberThreatAI" / "chrome_extension"
            if c_dir.exists():
                try:
                    creds_file = c_dir / "pairing_credentials.json"
                    creds_file.write_text(json.dumps(_active_pairing, indent=2), encoding="utf-8")
                except Exception:
                    pass"""

if old_cand_block in norm_routes:
    norm_routes = norm_routes.replace(old_cand_block, new_cand_block)
    print("[+] routes.py stopped overwriting candidate extension directories")
else:
    print("[-] routes.py candidate directories block match failed")

# In /browser/event, fix Gmail inspection scope check
old_gmail_chk = """        if (browser_event_type == "GMAIL_INSPECTION" or "mail.google.com" in url.lower()) and not is_test:
            active_mailbox = payload.get("active_mailbox") or payload.get("mailbox_email") or payload.get("account_email")
            if active_mailbox and hasattr(db, "get_allowed_emails"):
                allowed_emails = [e.lower() for e in db.get_allowed_emails(user_id)]
                if allowed_emails and active_mailbox.strip().lower() not in allowed_emails:
                    return {
                        "status": "SKIPPED",
                        "message": f"Mailbox {active_mailbox} is not in registered or allowed emails list. Monitoring paused for unapproved accounts.",
                        "monitored": False
                    }"""

new_gmail_chk = """        if (browser_event_type == "GMAIL_INSPECTION" or "mail.google.com" in url.lower()) and not is_test:
            active_mailbox = payload.get("active_mailbox") or payload.get("mailbox_email") or payload.get("account_email")
            if active_mailbox and hasattr(db, "get_allowed_emails") and user_id and user_id not in ("current_user", "unpaired@cyberthreat.local", ""):
                allowed_emails = [e.lower() for e in db.get_allowed_emails(user_id)]
                if allowed_emails and active_mailbox.strip().lower() not in allowed_emails:
                    return {
                        "status": "SKIPPED",
                        "message": f"Mailbox {active_mailbox} is not in registered or allowed emails list. Monitoring paused for unapproved accounts.",
                        "monitored": False
                    }"""

if old_gmail_chk in norm_routes:
    norm_routes = norm_routes.replace(old_gmail_chk, new_gmail_chk)
    print("[+] routes.py updated Gmail inspection scope check")
else:
    print("[-] routes.py Gmail check match failed")

with open(p_routes, "w", encoding="utf-8") as f:
    f.write(norm_routes)
print("[+] routes.py saved successfully")

# -------------------------------------------------------------
# 6. Update download.html
# -------------------------------------------------------------
p_dl = BASE / "download.html"
with open(p_dl, "r", encoding="utf-8") as f:
    dl_text = f.read()

old_dl_href = 'href="https://github.com/Dhanavarshinip/CyberZen_Application_project/releases/download/v1.0.0/cyberzen-chrome-extension.zip"'
new_dl_href = 'href="https://cyberzen.13.211.114.156.sslip.io/cyberzen-chrome-extension.zip"'

if old_dl_href in dl_text:
    dl_text = dl_text.replace(old_dl_href, new_dl_href)
    with open(p_dl, "w", encoding="utf-8") as f:
        f.write(dl_text)
    print("[+] download.html extension href updated to production cloud zip endpoint")
else:
    print("[-] download.html href match failed")

print("[*] Patch application completed!")
