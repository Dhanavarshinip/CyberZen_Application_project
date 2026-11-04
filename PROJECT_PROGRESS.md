# CYBERTHREAT AI — PROJECT PROGRESS & CONTINUATION CHECKPOINT

## Stage 1: Completed — Activity Flowchart Removal & Persistent Date-Wise History (2026-10-11)
- **Work Completed**:
  1. *Removed Activity Flowchart completely*: Eliminated the “Activity Flowchart & Causal Timeline” and the flowchart toggle button from the Activity page. (Diagrammatic reconstruction moved to Incidents page in Stage 2).
  2. *Implemented Date Filters*: Added active filters for "Today", "Yesterday", "Custom Date" (interactive datepicker), and "All Dates".
  3. *Date-wise Grouping*: Telemetry events are categorized and displayed in grouped date sections with human-readable headers (e.g., "Today — Sunday, October 11, 2026") and event count badges.
  4. *Accurate Local Date & Timestamp*: Replaced generic or relative times with accurate local time display (`HH:mm:ss`) and full timestamps in details inspection.
  5. *Rich Activity Attributes*: Each row cleanly displays application/domain, description, event type, collector source, device identity, measured duration, and security verdict badge.
  6. *Category Filters & Search*: Maintained high-performance filtering across Apps, Websites, Downloads, Network, and Security with real-time text search.
  7. *Pagination & Scalable Loading*: Added configurable pagination (25 items/page, Page X of Y, Previous/Next controls) preventing memory issues with large historical logs.
  8. *Clean Dark Theme*: Applied unified professional near-black dark theme (`#090d16` background, `#0f172a`/`#131b2e` cards, `#1e293b` borders, readable `#f8fafc` text) across index.css, Navbar, App, and Activity.
  9. *Backend Persistence Support*: Updated `backend/database/db.py` and `backend/api/routes.py` with `start_date`, `end_date`, and `offset` parameters for SQL query filtering, preserving permanent SQLite history across app restarts.
- **Files Changed**:
  - `src/components/ActivityView.jsx`: Completely redesigned without flowchart, with date filters, date grouping, pagination, and dark theme.
  - `src/components/Navbar.jsx`: Styled to match unified near-black dark theme.
  - `src/index.css`: Theme variables updated to sleek near-black palette.
  - `src/App.jsx`: Root container background set to `#090d16` and text `#f8fafc`.
  - `src/services/apiClient.js`: Added `getEvents` method with date and pagination parameters.
  - `backend/database/db.py`: `get_events` updated with `start_date`, `end_date`, `offset`.
  - `backend/api/routes.py`: `/telemetry/events` updated with date filter queries and pagination.
- **Test Results**:
  - `python -m pytest tests/ -v`: **22 passed out of 22** in 25.60s.
  - `npm run build`: **PASS** — compiled cleanly in 440ms.

---

## Stage 2: Completed — Move Diagrammatic Incident Reconstruction & Fix Disappearing Incidents (2026-10-11)
- **Work Completed**:
  1. *Identified & Resolved Root Cause of Disappearing Incident Bug*:
     - Root cause: `backend/database/db.py` was missing the `save_incident()` method called by `reconstructor.py`, throwing an `AttributeError` on persistence. Moreover, `/api/incidents` only reconstructed dynamic clusters in memory from active event windows without querying persisted SQLite incidents.
     - Fixed `backend/database/db.py`: Added automatic SQLite schema migration adding `details_json TEXT` to `incidents`, implemented `save_incident(incident)` to persist full incident records, anomaly details, drift scores, entities, and event links.
     - Fixed `backend/api/routes.py`: `/api/incidents` now queries SQLite via `db.get_incidents()`, merges in reconstructed clusters, and persists newly recognized incidents automatically without duplicate IDs.
  2. *Interactive Connected Diagrammatic Reconstruction*:
     - Moved the causal reconstruction visualization into `src/components/IncidentsView.jsx`.
     - Built an interactive causal chain: **User Activity & Telemetry → Anomaly Detected (Isolation Forest) → Behavioral Drift Identified → Risk Evolution → Knowledge Graph Correlation → Incident & Adaptive Response**.
     - Each step is clickable to reveal deep underlying telemetry, timestamp, anomaly dimension contributions, drift vectors, and graph triples.
  3. *Stable Selection & State Preservation*:
     - Incident selection now tracks a stable `selectedIncidentId` rather than a volatile array index.
     - Details are fetched from backend and kept persistently open across 2.5s dashboard polling refreshes until dismissed by user.
  4. *Unified Dark Theme*:
     - Restyled `IncidentsView.jsx` with the near-black dark theme, high-contrast typography, and subtle status badges.
- **Files Changed**:
  - `backend/database/db.py`: Added `details_json` column, `save_incident`, and enhanced `get_incident` / `get_incidents`.
  - `backend/api/routes.py`: Updated `/incidents` endpoint to load and persist SQLite incidents.
  - `src/services/apiClient.js`: Added `getIncident(incidentId)` and enhanced `getIncidents`.
  - `src/components/IncidentsView.jsx`: Rebuilt with persistent selection, SQLite hydration, and interactive causal chain diagram.
- **Test Results**:
  - `python -m pytest tests/ -v`: **22 passed out of 22** in 25.57s.
  - `npm run build`: **PASS** — compiled cleanly in 410ms.

---

## Stage 3: Completed — Website Classification, Browser-to-Backend Communication, & Notifications (2026-10-11)
- **Work Completed**:
  1. *Fixed Zero-Risk Bug on Unverified Domains*:
     - Root cause: Unknown domains without matching heuristics defaulted to `risk_score: 0.0` with `status: UNKNOWN`. The frontend/extension treated this as "Safe" with "Risk: 0/100".
     - Fixed `backend/monitoring/domain_evaluator.py`: Unknown/unrated domains now return `status: "UNKNOWN"` and `risk_score: None`.
     - Explicitly distinguish `NO KNOWN THREAT` (verified reputable domains, risk: 0) from `UNVERIFIED WEBSITE — Proceed with caution` (unrated domains, risk: None/Unverified).
  2. *Separated Piracy Content Policy Advisories from Malware*:
     - Added `PIRACY_PATTERNS` regex and category `"Content Policy Advisory — Suspected Piracy"`. Piracy alone is flagged as policy advisory (`SUSPICIOUS` status) without claiming malware infection.
  3. *Browser Integration & Fallback Handling*:
     - Updated `chrome_extension/background.js`: Does not default unverified domains to 0; handles null risk scores gracefully; triggers native notifications on high-risk domains (`DANGEROUS` / `SUSPICIOUS`).
     - Updated `chrome_extension/popup.js`: Renders `⚪ UNVERIFIED (Not Rated)` instead of `0/100` for unknown domains, and `✓ NO KNOWN THREAT` for safe domains.
     - Updated `chrome_extension/content.js`: Renders `⚪ UNVERIFIED WEBSITE — Proceed with caution` with `Reputation: Unverified` badge instead of `Risk: 0/100`.
  4. *Real-time Notifications*:
     - Updated `backend/monitoring/engine.py` toast notification to include `⚪ UNVERIFIED WEBSITE` notifications alongside `SAFE`, `SUSPICIOUS`, and `DANGEROUS`.
- **Files Changed**:
  - `backend/monitoring/domain_evaluator.py`: Piracy patterns added; UNKNOWN domains return `risk_score: None`.
  - `backend/monitoring/engine.py`: Toast notifications for UNKNOWN; preserve None risk score.
  - `chrome_extension/background.js`: Proper risk score null handling and Chrome desktop notifications.
  - `chrome_extension/popup.js`: UI updated for UNVERIFIED status and No Known Threat.
  - `chrome_extension/content.js`: In-page banner updated for UNVERIFIED and Piracy policy advisories.
  - `tests/test_domain_eval.py`: Created test suite verifying SAFE, DANGEROUS, PIRACY, and UNKNOWN evaluations.
- **Test Results**:
  - `python -m pytest tests/test_domain_eval.py -v`: **1 passed out of 1** in 0.02s.
  - `python -m pytest tests/ -v`: **23 passed out of 23** in 26.10s.
  - `npm run build`: **PASS** — compiled cleanly in 410ms.

---

## Stage 4: Completed — Test Protection Button, Login/Agent Status, and Primary Device Selector (2026-10-11)
- **Work Completed**:
  1. *Resolved "Device Not Connected" after Login*:
     - Root cause: `AuthContext.jsx` generated a conflicting random `DEV-XXXXXXX` string in `localStorage`, while the backend host monitor had its persistent `DEVICE_A_...` device ID. The backend registered `DEV-XXXXXXX` with 0 events, and reported `NOT_CONNECTED`. Moreover, `apiClient.getHealth` was missing in `apiClient.js`, throwing `TypeError` in `App.jsx` during health polling and setting `isOnline = false`.
     - Fixed `apiClient.js`: Implemented `getHealth()` and `getDeviceStatus()`.
     - Fixed `AuthContext.jsx`: On mount, queries `/api/monitoring/status` to sync `deviceId` with the real host monitor ID.
     - Fixed `backend/api/routes.py`: In `/auth/login` and `/auth/signup`, automatically binds the real host monitor `device_id` to the authenticated user ID so the Primary Device is always enrolled and recognized.
  2. *Single "Test Protection" Diagnostic Button*:
     - In `src/components/HomeView.jsx`, replaced separate test buttons with a single **Test Protection** button.
     - Controlled diagnostic test executes via `apiClient.runProtectionTest()`.
     - Loading spinner animation displayed during test execution.
     - Verified Safe result shows green checkmark (`CheckCircle2`), Dangerous shows red warning symbol (`AlertOctagon`), Suspicious shows amber symbol (`AlertTriangle`), and Failed/Unknown shows grey (`HelpCircle`).
     - Evidence breakdown displays ML Anomaly score A(t), Behavioral Drift B(t), Risk Evolution R(t), and verified subsystems checklist.
     - Test result stays visible until dismissed or another test begins, and includes a **Retry Test** button.
     - Test events are marked `is_test_event: true` and strictly isolated from real activity, incident statistics, and production device risk.
  3. *Distinct 4-State Connection & Monitoring Indicator*:
     - Distinguishes **Online**, **Offline but Monitoring Locally**, **Agent Disconnected**, and **Server Unavailable**.
     - Tracks and displays the last successful heartbeat time.
     - Keeps login authentication separate from agent connection; transient connection dropouts do not log out the user.
  4. *Primary Device Selector*:
     - Displays registered device name (e.g. "My Laptop"), shortened ID, connection status, and host marker `★`.
     - Strictly filters activity, incidents, risk, and sync queries by authenticated device ID.
  5. *Unified Dark Theme*:
     - Applied consistent near-black palette across `HomeView.jsx` and `Navbar.jsx`.
- **Files Changed**:
  - `src/components/HomeView.jsx`: Rebuilt with Test Protection button, loading/result cards, retry, and dark theme.
  - `src/components/Navbar.jsx`: Enhanced with 4-state connection indicator and detailed device switcher.
  - `src/App.jsx`: Added 4-state connection logic, heartbeat tracking, and device propagation.
  - `src/services/apiClient.js`: Added `getHealth()` and `getDeviceStatus()`.
  - `src/context/AuthContext.jsx`: Synced `deviceId` with host monitor.
  - `backend/api/routes.py`: Auto-registered host device for user upon login/signup; added `/api/protection/test` tests.
  - `tests/test_api.py`: Added tests for `test_api_protection_test` and `test_api_device_status`.
- **Test Results**:
  - `python -m pytest tests/test_api.py -v`: **11 passed out of 11** in 30.49s.
  - `npm run build`: **PASS** — compiled cleanly in 1.20s.

---

## Stage 5: Completed — Whole-Computer Monitoring & Local Offline Synchronization (2026-10-11)
- **Work Completed**:
  1. *Whole-Computer Windows Monitoring*:
     - Verified `ProcessMonitor`: live Windows process enumeration, application classification, background noise filtering, temp/unusual folder execution evaluation.
     - Verified `FileMonitor`: Downloads/Desktop watcher, SHA256 checksumming, double extension detection, EICAR test signature detection.
     - Verified `NetworkMonitor`: live socket inspection via psutil, remote IP/port mapping, RFC 1918 private address classification, suspicious egress port flagging.
     - Verified `RealSystemMonitor`: starts/stops cleanly, auto-snapshots running apps on startup, heartbeat loop in SQLite maintains ONLINE status.
  2. *Offline Monitoring & Idempotent Synchronization*:
     - Fixed `backend/sync/engine.py` sync logic: correctly transitions local `PENDING` events to `SYNCHRONIZED` without treating them as duplicates.
     - Preserves original event timestamps and device IDs throughout offline disconnection and synchronization.
     - Idempotent batch processing prevents duplicate records upon replayed transmissions.
     - Database persistence verified across restarts and sync cycles.
- **Files Changed**:
  - `backend/sync/engine.py`: Fixed handling of existing local PENDING events in `process_sync_batch`.
  - `tests/test_stage5_monitoring_sync.py`: Created test suite verifying host monitors and offline sync idempotency.
- **Test Results**:
  - `python -m pytest tests/test_stage5_monitoring_sync.py -v`: **2 passed out of 2** in 0.21s.
  - `python -m pytest tests/ -v`: **27 passed out of 27** in 30.69s.
  - `python -m experiments.run_experiments`: **All 5 experiments passed (exit code 0)**.
  - `npm run build`: **PASS** — compiled cleanly in 504ms.

---

## Stage 8: Completed — Adware / Commercial Scareware Detection & Offline Activities Notifications (2026-10-12)
- **Work Completed**:
  1. *Identified Root Cause of Missing Notification on McAfee Ad*:
     - The ad shown (`"Issues found! Save on McAfee Protection."`) was spawned by McAfee Security Scan's WebView helper `mc-webview-cnt.exe` (parent: `SSScheduler.exe`).
     - Previously, `process_monitor.py` had no signatures for commercial scareware or adware upselling popups, classifying it as a generic `.exe` with `risk_score: 0.0` and `status: "INFO"`.
     - In `engine.py`, process monitoring previously only fired toast notifications for `status == "DANGEROUS"` and `status == "SUSPICIOUS"`, completely ignoring `SAFE`, `INFO`, and unclassified adware popups.
     - Additionally, any processes already active before monitor start were dumped into `_seen_pids` without being evaluated for adware alerts.
  2. *Dedicated Adware / Commercial Scareware Detection Engine*:
     - Added `ADWARE_PATTERNS` in `ProcessMonitor` targeting `mc-webview-cnt.exe`, `SSScheduler.exe`, `McCHSvc.exe`, `McUpdaterModule.exe`, `mcafee security scan`, `webadvisor`, `cleanmypc`, `bytefence`, and common adware/popunder/nagware patterns.
     - Automatically flags matched processes as `is_adware: True`, `status: "SUSPICIOUS"`, `risk_score: 45.0` with clear reasons: `"Commercial adware / promotional scareware popup detected... Verdict: Safe from virus/malware, but unsolicited commercial scareware ad."`
     - Implemented `find_active_adware_processes()` to scan active processes for currently visible adware/scareware popups.
  3. *Comprehensive "Safe or Not" Notifications for Offline Activities*:
     - In `RealSystemMonitor._monitor_loop()`, added rich debounced toast notifications for all offline process activities:
       - 🔴 **Dangerous**: `🔴 CyberThreat AI: Dangerous Process — Threat detected in executable. Action recommended.`
       - 🟠 **Adware / Commercial Ad**: `🟠 CyberThreat AI: Adware / Promotional Ad Detected — [Name] Verdict: Commercial scareware / promotional ad popup. Safe from malware, but aggressive upsell alert.`
       - 🟠 **Suspicious**: `🟠 CyberThreat AI: Suspicious Activity — Suspicious offline activity detected.`
       - 🟢 **Safe Application**: `🟢 CyberThreat AI: Safe Application — [Name] opened — Activity verified safe — No threats detected.`
       - ⚪ **Unverified**: `⚪ CyberThreat AI: Unverified Activity — Unverified offline activity.`
     - Active adware popups are scanned periodically and on startup, ensuring notifications fire even if the ad popup was already open on screen.
  4. *Electron Automatic Backend Startup*:
     - Updated `electron/main.js` with `ensureBackendRunning()`: if FastAPI is not yet running on `127.0.0.1:8000`, Electron automatically spawns `python -m uvicorn backend.main:app` and waits for `/api/health` before loading the UI. Gracefully cleans up child process on exit.
  5. *UI Status Badge Support*:
     - Updated `src/components/ActivityView.jsx` `getStatusConfig()` to render distinct `ADWARE / PROMO` (orange) and `SAFE` (green) badges.
- **Files Changed**:
  - `backend/monitoring/process_monitor.py`: Added `ADWARE_PATTERNS`, adware evaluation, and `find_active_adware_processes()`.
  - `backend/monitoring/engine.py`: Added startup & periodic adware scan, and comprehensive "Safe or Not" offline process notifications.
  - `electron/main.js`: Auto-spawns Python backend if not running.
  - `src/components/ActivityView.jsx`: Added `ADWARE / PROMO` and `SAFE` badge styling.
  - `tests/test_adware_offline_notifications.py`: Added test suite verifying adware detection and safe application evaluation.
- **Test Results**:
  - `python -m pytest tests/test_adware_offline_notifications.py -v`: **2 passed out of 2** in 0.05s.
  - `python -m pytest tests/ -v`: **29 passed out of 29** in 47.60s.
  - `npm run build`: **PASS** — compiled cleanly in 1.93s.

---

## Stage 9: Completed — Activity Permanent Date-Wise History, Back Navigation, & Real Home Security Status (2026-10-12)
- **Work Completed**:
  1. *Resolved Root Cause of Broken Activity Date Filters*:
     - **Duplicate API Client Definition**: Discovered that `src/services/apiClient.js` had two conflicting declarations of `getEvents`. The second definition with positional parameters overwrote the first, sending `limit=[object Object]` to FastAPI and returning HTTP 422 Unprocessable Entity.
     - **In-Memory Poll Leakage**: `ActivityView` was falling back to the 100 live-polling events passed via `events` prop (all from today). Selecting Yesterday or Custom Date with 0 events matching today's list caused the view to appear empty, giving the impression that historical events were deleted after 30 seconds.
     - **Timezone Boundary Handling**: Fixed `backend/database/db.py` and `backend/api/routes.py` with `date`, `client_tz_offset`, and normalized `datetime(...)` comparisons. Yesterday and custom dates are now queried using the user's exact local calendar day converted to UTC offsets.
     - **Strict Empty State**: A date without events cleanly returns 0 records and displays a descriptive empty state, never falling back to today's records.
     - **Strict Test Mode Isolation**: Test-mode events are explicitly flagged (`is_test_event: True`, `TEST_` prefixes, `TEST_ENDPOINT`) and filtered in SQL and API routes, preventing test events from ever contaminating real Activity feeds.
  2. *Added Professional Back Navigation*:
     - Added an accessible, visible Back Arrow button to the application header in `src/components/Navbar.jsx`.
     - Integrated a historical navigation stack (`navHistory`) in `src/App.jsx` supporting back navigation across Activity, Incidents, Devices, and Settings.
     - Gracefully returns to the previous view, or to Home if no previous in-app view exists.
     - Prevents application closing, logout, navigation loops, or blank screens.
  3. *Fixed Home Page — Real Security Posture Display*:
     - Completely removed random, placeholder, or mock status values.
     - Implemented the 6 required mutually-exclusive security states derived from actual backend health, monitoring agent activity, completed assessments, and recorded events:
       - **PROTECTED — NO KNOWN THREAT**: Host monitoring active, ML baseline normal, no threats detected.
       - **THREAT DETECTED**: Confirmed threat or critical incident detected.
       - **SUSPICIOUS ACTIVITY**: Evidence of unusual behavior or behavioral drift flagged.
       - **UNKNOWN / CHECK FAILED**: Assessment incomplete, agent disconnected, or insufficient evidence.
       - **MONITORING OFFLINE**: Local monitoring agent stopped.
       - **OFFLINE — MONITORING LOCALLY**: Internet unavailable, but local monitoring running and persisting to SQLite.
     - Clearly distinguishes monitoring agent health from internet connection status.
     - Features a single **Test Protection** button running a harmless diagnostic pipeline (`/api/protection/test`) with green checkmark for SAFE, red for DANGEROUS, amber for SUSPICIOUS, grey for UNKNOWN, visibly labeled as TEST without modifying real stats.
     - Added a clean preview list of recent genuine activities and confirmed incidents with direct navigation links.
- **Files Changed**:
  - `backend/database/db.py`: Enhanced `get_events` with `date`, `client_tz_offset`, normalized datetime boundaries, and added `get_events_count()`.
  - `backend/api/routes.py`: Updated `/telemetry/events` with date/offset query params, and redesigned `/device/status` to evaluate the 6 real protection states.
  - `src/services/apiClient.js`: Consolidated `getEvents` to support options object with full date filtering, removed duplicate `getHealth` and `getEvents`.
  - `src/components/ActivityView.jsx`: Fixed data flow pipeline, added active date badge, loading spinner, error banner, and accurate empty state.
  - `src/components/Navbar.jsx`: Added consistent Back Arrow button with hover states.
  - `src/components/HomeView.jsx`: Completely rebuilt with the 6 real protection states, Test Protection diagnostic card, agent/network indicators, and recent activity previews.
  - `src/App.jsx`: Added `navHistory` state, `navigateToTab`, and `navigateBack` handlers.
  - `tests/test_date_filters_and_home_status.py`: Created automated test suite covering timezone midnight boundaries, date queries, empty dates, device isolation, and home protection states.
- **Test Results**:
  - `python -m pytest tests/test_date_filters_and_home_status.py -v`: **7 passed out of 7** in 2.46s.
  - `python -m pytest tests/ -v`: **36 passed out of 36** in 42.70s.
  - `npm run build`: **PASS** — compiled cleanly in 557ms.

---

### Stage 10: Desktop Shortcuts & Production Application Launch
- **Date**: 2026-10-12
- **Objective**: Create updated desktop shortcuts across both local profile and OneDrive desktop folders, configure fallback launcher paths, and run the full CyberThreat AI application with active backend and Electron operations center.
- **Key Enhancements**:
  1. *Launcher & Startup Script Optimization*:
     - Updated `start_cyberthreat_ai.bat` with automated Python 3.14 path detection (`C:\Python314\python.exe`), active health probing on `http://127.0.0.1:8000/api/health`, and clean Electron launching.
     - Updated `electron/main.js` to resolve the Python interpreter fallback cleanly.
  2. *Desktop Shortcut Generation*:
     - Updated `create_desktop_shortcut.ps1` to create `CyberThreat AI.lnk` and `CyberThreat AI System.lnk` in both user profile desktop (`C:\Users\HP\Desktop`) and OneDrive desktop (`C:\Users\HP\OneDrive\Desktop`).
     - Embedded Electron application icon into the shortcuts.
  3. *Application Launch Verification*:
     - Python FastAPI research backend running on `http://127.0.0.1:8000`.
     - Electron Desktop Operations Center launched and active.

---

### Stage 11: Rich Activity Details, YouTube Video Capture & Browser Info Display
- **Date**: 2026-10-12
- **Objective**: Ensure detailed video, browsing, and process context is displayed when viewing Activity Info (e.g. YouTube video titles, full target URLs, and exact user actions in Google Chrome).
- **Key Enhancements**:
  1. *Activity Record Details Modal Redesign*:
     - Added prominent **Observed Activity & Action** banner at the top of the details modal.
     - Added dedicated **Web Navigation & YouTube Video Information** card displaying the video/page title, full target URL with a clickable "Open" link, domain, and Chrome browser badge.
     - Added dedicated **Host Process Details** card showing executable path, command line, and PID for application events.
  2. *Chrome Extension Title & YouTube SPA Support*:
     - Updated `chrome_extension/content.js` to send `document.title` on navigation and hooked into `yt-navigate-finish` for YouTube SPA transitions.
     - Updated `chrome_extension/background.js` to extract `tab.title` and send `{ url, title, user_id }` to `/api/browser/event`.
  3. *Backend Browser Navigation Pipeline*:
     - Updated `backend/monitoring/engine.py` and `backend/api/routes.py` to extract titles, detect YouTube videos and shorts, and generate human-readable descriptions (e.g. `Watched YouTube video: "Video Title"`).
     - Enhanced native Windows toast notification to reflect the watched video name.
- **Verification**:
  - `npm run build`: **PASS** in 388ms.
  - Automated tests: **7 passed out of 7** in 2.76s.
  - Test event verification: Successfully stored and retrieved rich YouTube video details (`evt_web_ffad579e09`).

---

### Stage 12: Complete Installation and Onboarding Workflow (2026-10-29)
- **Objective**: Implement a complete, user-friendly installation and onboarding workflow with public website, verified Windows packaging, secure registration with consent, robust device enrollment with credential issuance, transparent permissions flow, real host monitoring connection, and cloud architecture deployment preparation.
- **Key Enhancements**:
  1. *Public Responsive Website*:
     - Created `src/components/public/PublicWebsiteLayout.jsx`, `PublicHomeView.jsx`, `FeaturesView.jsx`, and `DownloadView.jsx`.
     - **Home Page**: Explains CyberThreat AI, AI detection models (Isolation Forest, Behavioral Digital Twin, Temporal Knowledge Graph), composite risk formula $R(t) = 0.4A(t) + 0.4B(t) + 0.2H(t)$, and quick call-to-actions.
     - **Features Page**: In-depth architecture breakdown of the 4 supported host collectors (Process Monitor, File/Download Watcher with EICAR detection, Network Socket Inspector, Browser Extension), ML anomaly scoring, drift calculations, and causal incident reconstruction.
     - **Download Page**: Displays official Windows standalone package (`CyberThreat AI Operations Center 1.0.0.exe`), version `1.0.0`, verified size (89.76 MB), published SHA-256 checksum, step-by-step installation instructions, and honest publisher signing notice.
     - **Future Platforms**: Android and iOS clearly presented as *In Development* targets for future stages; not presented as downloadable or mock-functional.
  2. *User Registration & Cryptographic Authentication*:
     - Updated `src/components/auth/SignupForm.jsx` with mandatory Privacy Notice & Monitoring Consent checkbox, password matching validation, and minimum character constraints.
     - Built `backend/security/auth.py` providing PBKDF2-HMAC-SHA256 password hashing (100,000 rounds, 16-byte random salts) and cryptographically signed HMAC-SHA256 Bearer Session Tokens (JWT format).
     - Added `consent_accepted` and `consent_timestamp` columns to the `users` table via automatic schema migrations in `backend/database/db.py`.
     - Protected authenticated endpoints (`/api/devices`, `/api/telemetry/events`, `/api/incidents`) with token decoding and account verification.
  3. *Secure Device Enrollment & Authorization*:
     - Built `POST /api/devices/enroll`: Generates a persistent unique device ID (`DEV_...`), associates it with the authenticated user ID, and issues a cryptographically secure random device key (`dk_...`).
     - Built `PUT /api/devices/{device_id}`: Renames device, strictly enforcing user ownership.
     - Built `POST /api/devices/{device_id}/revoke`: Revokes device credentials, blocking further telemetry ingestion while safely preserving all historical events and incidents.
     - Built `DELETE /api/devices/{device_id}`: Removes device from registry, strictly enforcing account ownership.
     - Rebuilt `src/components/DevicesView.jsx` with dark theme styling, device enrollment modal, copyable secret key dialog, rename/revoke controls, and account isolation badges.
  4. *Windows Packaging & Verified Download Integrity*:
     - Configured `package.json` for electron-builder x64 Windows distribution.
     - Built standalone executable: `release/CyberThreat AI Operations Center 1.0.0.exe` (94,116,547 bytes / 89.76 MB).
     - Computed and published cryptographic SHA-256 hash: `D2E3D211464C83C591C417AA43221DC70C59B322ECF154235DEB7833413A2A3B`.
     - Built `GET /api/download/windows` streaming the official binary with proper MIME type and Content-Disposition headers.
     - Built `GET /api/download/info` serving version, file size, SHA-256 checksum, and honest self-signed SmartScreen disclosure.
  5. *Transparent Permission & First-Launch Onboarding*:
     - Built `src/components/onboarding/FirstLaunchOnboardingModal.jsx`: Displays on first launch or via header Help button.
     - Explains what is monitored (Processes, Downloads/Files, Sockets, URLs) and why (zero-day detection, ransomware prevention, phishing blocking).
     - Explains where data is stored: Local SQLite WAL database (`%LOCALAPPDATA%/CyberThreatAI/data/cyberthreat.db`), synced to cloud when connected.
     - Explicit privacy pledge: Zero keystroke logging, no screen recording, no mic/webcam access, no reading private messages or files.
     - Windows permissions disclosure: Standard user privileges for normal monitoring; UAC elevation only for system-wide socket inspection.
     - Monitoring controls: Pause/resume monitoring, consent withdrawal, and safe application shutdown.
  6. *Cloud Architecture & Security*:
     - Retained SQLite for local offline persistence with Write-Ahead Logging.
     - Prepared PostgreSQL for shared cloud records via `DATABASE_URL` environment variable.
     - Created `docker-compose.yml`, `Dockerfile.backend`, `Dockerfile.frontend`, and `.env.production.example`.
     - Created `backend/security/safe_logger.py` redacting passwords, tokens, API keys, and device secrets.
     - Created `scripts/backup_db.py` for atomic SQLite backups using SQLite's backup API and WAL checkpointing.
- **Files Changed**:
  - `backend/security/auth.py`: Cryptographic authentication and JWT-style tokens.
  - `backend/security/safe_logger.py`: Credential and token scrubbing log filter.
  - `backend/security/__init__.py`: Package export.
  - `backend/database/db.py`: Migrations for consent and device credentials, device enrollment, rename, revoke, and ownership verification.
  - `backend/api/routes.py`: Auth endpoints, device enrollment/rename/revoke endpoints, download streaming, and download metadata.
  - `backend/config.py`: Dynamic writable data directory, production CORS, and database URL resolution.
  - `src/services/apiClient.js`: Bearer token management, device enrollment, rename, revoke, and download info methods.
  - `src/context/AuthContext.jsx`: Session verification, consent recording, token persistence.
  - `src/components/auth/SignupForm.jsx`: Monitoring consent and privacy notice checkbox with form validation.
  - `src/components/public/PublicWebsiteLayout.jsx`: Responsive public website with header, navigation, and footer.
  - `src/components/public/PublicHomeView.jsx`: Product overview, architecture, formula breakdown, and CTAs.
  - `src/components/public/FeaturesView.jsx`: In-depth breakdown of collectors, models, drift, and causal reconstruction.
  - `src/components/public/DownloadView.jsx`: Windows installer card with verified size, SHA-256 checksum, instructions, and future roadmap.
  - `src/components/onboarding/FirstLaunchOnboardingModal.jsx`: Guided first-launch permission and consent modal.
  - `src/components/Navbar.jsx`: Restyled with dark theme, Downloads button, Permissions button, and device switcher.
  - `src/components/DevicesView.jsx`: Rebuilt with dark theme, device enrollment, secret key dialog, rename, and revoke.
  - `src/App.jsx`: Integrated public website switching, onboarding modal, and dark theme background.
  - `scripts/build_windows_release.ps1`: Release packaging pipeline script with SHA-256 verification.
  - `scripts/backup_db.py`: Atomic database backup script.
  - `package.json`: Configured electron-builder for Windows target and version 1.0.0.
  - `docker-compose.yml`, `Dockerfile.backend`, `Dockerfile.frontend`, `.env.production.example`: Cloud production architecture.
  - `tests/test_installation_and_onboarding_workflow.py`: Comprehensive test suite covering all 12 testing requirements.
- **Test Results**:
  - `python -m pytest tests/test_installation_and_onboarding_workflow.py -v`: **10 passed out of 10** in 3.88s.
  - `python -m pytest tests/ -v`: **60 passed out of 60** in 41.99s.
  - `npm run build`: **PASS** in 661ms.
- **Release Artifacts**:
  - Binary: `release/CyberThreat AI Operations Center 1.0.0.exe`
  - Size: 94,116,547 bytes (89.76 MB)
  - SHA-256 Checksum: `D2E3D211464C83C591C417AA43221DC70C59B322ECF154235DEB7833413A2A3B`

---

### Stage 13: Project Title Harmonization, Download Delivery Fix, Formula Section Removal & Transactional Email Pipeline (2026-10-30)
- **Objective**: Implement project corrections strictly according to official specifications:
  1. Set official project title: *"Intelligent Real-Time Digital Threat Detection, Prevention and Incident Reconstruction"*.
  2. Fix website download button to trigger true browser downloads with fallback links.
  3. Remove unwanted composite risk formula presentation cards from user view.
  4. Implement transactional email service covering Account Verification, Welcome/Installation, Installation Success, and Setup Incomplete alerts.
  5. Complete incident reconstruction causal evidence chain (`USER → INITIATED → PROCESS`, `PROCESS → ACCESSED → FILE`, `EVENT → CONTRIBUTED_TO → INCIDENT`).
- **Files Changed**:
  - `src/components/public/DownloadView.jsx`: Dynamic absolute API download URL resolution, native programmatic anchor download, direct download link, and error banners.
  - `src/components/public/PublicHomeView.jsx`: Removed formula presentation container $R(t) = 0.4A(t) + 0.4B(t) + 0.2H(t)$ and 3 formula cards; updated title.
  - `src/components/HomeView.jsx`: Replaced formula label with clean "Threat Risk Assessment Engine" text.
  - `src/components/Navbar.jsx`, `src/components/public/PublicWebsiteLayout.jsx`, `src/components/auth/AuthLayout.jsx`, `src/components/onboarding/FirstLaunchOnboardingModal.jsx`, `index.html`, `electron/main.js`, `backend/main.py`: Official project title updated consistently.
  - `backend/security/email_service.py`: Transactional email service supporting Resend, Brevo, SMTP, and safe development logging.
  - `backend/database/db.py`: Migrations for `email_verified`, `verification_otp`, and `otp_created_at`; added `verify_user_email()` and `set_user_verification_otp()`.
  - `backend/api/routes.py`: Added `/api/auth/verify-email` and `/api/auth/resend-verification`; integrated verification email dispatch on signup and installation success dispatch on device enrollment.
  - `src/services/apiClient.js`: Added `getApiBase()`, `verifyEmail()`, and `resendVerification()`.
  - `src/components/auth/SignupForm.jsx`: Integrated in-place 6-digit OTP verification screen with resend option.
  - `src/components/IncidentsView.jsx`: Added Temporal Knowledge Graph causal entity chain card distinguishing confirmed facts from AI correlations.
- **Test Results**:
  - `npm run build`: **PASS** in 735ms.
  - `python -m pytest tests/test_installation_and_onboarding_workflow.py -v`: **10 passed out of 10** in 4.23s.
  - `python -m pytest tests/ -v`: **60 passed out of 60** in 53.07s.

---

### Stage 15: Critical Electron Installation Fix & First-Launch Routing Correction (2026-10-31)
- **Problem Statement**:
  When downloading and installing the application, the launched application previously displayed the website's Download Application page again instead of functioning as a desktop security application.
- **Root Causes Identified**:
  1. *Unauthenticated Routing Fallback*: In `src/App.jsx`, `AuthConsumer` defaulted to rendering `<PublicWebsiteLayout initialPage="home" />` whenever `isAuthenticated` was false. When launched inside Electron for the first time, users were unauthenticated and were presented with the public website landing page ("Download CyberThreat AI for Windows").
  2. *ASAR Packaging Process Isolation*: In `package.json`, default `asar: true` packed the Python backend code into `app.asar`. Python (`uvicorn`) cannot execute modules or access files inside binary ASAR archives, causing backend spawn failure in packaged production.
  3. *Static Server Packaging Pathing*: `electron/main.js` lacked dynamic runtime root resolution for packaged mode (`process.resourcesPath/app`), and hardcoded a single Python path rather than scanning standard Windows install locations.
  4. *Missing Import in SignupForm*: In `src/components/auth/SignupForm.jsx`, `apiClient` was not imported, throwing a reference error when verifying the 6-digit email OTP.
  5. *Windows EPERM Lock in Electron-Builder*: `electron-builder` attempted atomic folder rename on Windows while `lockfile` held open file handles; resolved with lock release and safe copy fallback.
- **Work Completed**:
  1. *Desktop Context Detection & Native Routing*:
     - Created `electron/preload.js` exposing `window.cyberthreatDesktop = { isDesktop: true, appVersion: '1.0.0', platform: process.platform }`.
     - Appended `?app_mode=desktop` to `mainWindow.loadURL()` in `electron/main.js`.
     - Updated `src/App.jsx` (`isDesktopEnvironment`): If running in desktop mode and unauthenticated, it directly renders `<AuthLayout defaultMode="signup" />`. The public Download page is NEVER rendered to an installed desktop user.
  2. *Production Packaging with Unpacked Resources*:
     - Set `"asar": false` in `package.json` ensuring `backend/`, `dist/`, and `models/` remain real filesystem directories in `resources/app/` for Python and SQLite.
     - Added `getProjectRoot()` and `getDistDir()` in `electron/main.js` checking `process.resourcesPath/app` when `app.isPackaged`.
     - Implemented `findPythonExecutable()` scanning Python 3.10 through 3.14 across `C:\Python*`, `%LOCALAPPDATA%\Programs\Python\*`, and `%ProgramFiles%\Python*`.
  3. *Auth & Onboarding Workflow*:
     - Fixed `apiClient` import in `src/components/auth/SignupForm.jsx` for 6-digit OTP verification.
     - Enhanced `src/components/auth/AuthLayout.jsx` with Windows Operations Center identity and mode switcher (Create Account / Sign In).
     - Verified `FirstLaunchOnboardingModal.jsx` for transparent Windows permissions, local SQLite WAL disclosure, and privacy pledge.
  4. *Executable Packaging & Metadata*:
     - Fresh production build compiled via `npm run build` in 636ms.
     - Generated standalone executable: `release/CyberThreat AI Operations Center 1.0.0.exe` (93,963,840 bytes, 89.61 MB).
     - Computed SHA-256: `581FF4BED048BE713F50D2123D0C2F7CA759B2670C3C22A3B6B023749FE72703`.
     - Updated `release/release_metadata.json` and download endpoint.
- **Verification Results**:
  - `npm run build`: **PASS** in 636ms.
  - `pytest tests/test_installation_and_onboarding_workflow.py -v`: **10 passed out of 10** in 4.04s.
  - `pytest tests/ -v`: **60 passed out of 60** in 49.08s.
  - Desktop shortcuts updated on Desktop and OneDrive Desktop pointing to `CyberThreat AI Operations Center`.

---

### Stage 16: Complete Device Enrollment, Activities Pipeline & Offline Monitoring Correction (2026-10-31)
- **Problem Statement**:
  1. *Activities Tab Glitch on Friend's Laptop*: When tested on another laptop, activities did not display reliably. Telemetry collected by the host background engine was attributed to a hardcoded host device ID and dummy `user_id = 'current_user'`, causing legitimate user queries to return 0 activities or leak host telemetry across accounts.
  2. *Device Enrollment Contamination*: In `backend/api/routes.py`, `GET /devices` previously exposed all devices in the database if `user_id` was absent, and clients could query other users' devices without ownership validation.
  3. *Offline Activity Collection & Telemetry Attribution*: Offline telemetry lacked persistent user and hardware identity binding on background observation loops.
  4. *Monitoring Health & Data Quality Metrics*: Lack of dedicated endpoint tracking live collector states, latency, and captured/persisted counters.
- **Root Causes Identified & Fixed**:
  1. *Host Device ID Decoupling*: Created dynamic hardware detection and binding in `backend/monitoring/engine.py` (`RealSystemMonitor.bind_enrolled_device`) and `backend/database/db.py` (`migrate_unbound_events`), ensuring events recorded during startup are automatically bound to the authenticated user and enrolled device upon registration.
  2. *Strict 403 Cross-Account Device Isolation*: Updated `backend/api/routes.py` (`/telemetry/events`, `/incidents`) to reject unowned device queries with HTTP 403 Forbidden. Updated `GET /devices` to return `[]` when unauthenticated, preventing cross-user leakage.
  3. *Client-side Dynamic Device ID Resolution*: In `src/context/AuthContext.jsx`, remote/browser clients generate persistent UUIDs in localStorage rather than inheriting the server host machine ID. In `src/App.jsx`, selected device ID is strictly validated against `userDevices`.
  4. *Activities Tab Real SQLite Querying*: Enhanced `src/components/ActivityView.jsx` to query user-isolated events and date summary using client timezone offsets. Added one-click sample event recorder for empty database states.
  5. *Hardware Detection & First-Launch Modal*: Rebuilt `src/components/onboarding/FirstLaunchOnboardingModal.jsx` with an explicit Device Enrollment step showing detected hardware identity, customizable device name, and explicit enrollment confirmation before monitoring starts.
  6. *Phase 4 Monitoring Health Metrics*: Implemented `GET /api/monitoring/health` and `GET /api/monitoring/health-metrics` reporting `events_captured_total`, `events_persisted_total`, `events_failed_total`, `collector_uptime_seconds`, `last_write_latency_ms`, `pending_sync_queue_size`, and real collector states (`Active`, `Inactive`, `Waiting for Events`). Added interactive live dashboard in `src/components/SettingsView.jsx`.
  7. *Phase 6 UI Polish*: Cleaned `src/components/HomeView.jsx` to ensure a minimal layout with 1 Test Protection button and clear Safe/Danger verdict without visible formula panels. Removed visible OS/installer type/SHA-256 panel from `src/components/public/DownloadView.jsx`.
  8. *Phase 7 Installer Delivery*: Configured `GET /api/download/windows` with `Content-Type: application/octet-stream`, `Content-Disposition: attachment; filename="CyberThreat AI Operations Center 1.0.0.exe"`, and `X-Content-Type-Options: nosniff`.
---

### Stage 17: Complete Application Correction, Enhancement, and Verification Across All 11 Phases (2026-10-31)
- **Work Completed**:
  1. *Phase 1 — Individual User Accounts and Device Enrollment*:
     - Created `backend/monitoring/hardware_id.py` providing `get_physical_hardware_id()`, querying Windows Registry `MachineGuid` (`HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography\MachineGuid`) with fallback to MAC-node SHA-256 hash formatted as persistent `DEV_HW_<12-HEX-CHARS>` or `DEV_<HEX>`.
     - Fixed `backend/database/db.py` `register_device`: Eliminated silent ownership takeover; attempting to enroll a device already owned by another account raises `ValueError` requiring explicit unenrollment.
     - Implemented `remove_device(device_id, user_id)`: Enforces ownership authentication (`PermissionError`), deletes device registration while preserving historical telemetry and reconstructed incidents.
     - Fixed `backend/database/db.py` `get_incidents`: Added strict `user_id` filtering alongside `device_id` to prevent cross-account incident leakage.
     - Fixed `src/services/apiClient.js` `enrollDevice`: Normalized parameter handling so both options object and positional arguments succeed without generating null IDs.
  2. *Phase 2 — Activities Tab Overhaul & Date-wise Retrieval*:
     - Enhanced `src/components/ActivityView.jsx`: Implemented Date Range selection (`RANGE` filter with start and end date inputs), Chronological Sorting toggle (`sortOrder === 'DESC' ? 'Newest First' : 'Oldest First'`), and Windows System Events category tab (`SYSTEM`).
     - Added client timezone offset support to SQL date queries in `backend/database/db.py` and `backend/api/routes.py`, accurately retrieving genuine historical events for Today, Yesterday, and Custom Dates without fabricating fake activities.
  3. *Phase 3 — Real Offline Activity Monitoring & Persistence*:
     - Local SQLite WAL persistence guarantees offline computer events are recorded immediately regardless of internet connectivity.
     - Offline events are flagged `sync_status = "PENDING"` and enqueued in `sync_queue`.
     - On reconnection, `SyncEngine` flushes pending events idempotently; duplicate events are prevented via SQLite `ON CONFLICT` constraints, incrementing `duplicate_events_prevented_total`.
  4. *Phase 4 — Chrome Extension Pairing & Gmail/Web Threat Inspection*:
     - Rebuilt `chrome_extension/popup.html` and `popup.js`: Integrated authenticated account and device identity card with real-time pairing status, "Sync with App", and secure "Unpair" functionality.
     - Enhanced `chrome_extension/content.js`: Implemented `initGmailProtection()` detecting active Gmail account, warning users on account mismatch, inspecting emails for sender spoofing, deceptive links, and high-risk attachments (`.exe`, `.scr`, `.bat`, etc.), and emitting clear four-state verdicts: `SAFE`, `SUSPICIOUS`, `DANGER`, `UNKNOWN`.
  5. *Phase 5 — Monitoring Health Metrics & Collector States*:
     - Updated `backend/monitoring/engine.py` and `backend/sync/engine.py`: Implemented full telemetry health tracking: `events_captured_total`, `events_persisted_total`, `events_failed_total`, `events_dropped_total`, `collector_heartbeat_timestamp`, `collector_uptime_seconds`, `collector_error_total`, `sqlite_write_latency`, `pending_sync_queue_size`, `cloud_sync_latency`, `duplicate_events_prevented_total`, and `last_successful_event_timestamp`.
     - Standardized accurate collector states: `Active`, `Inactive`, `Permission Required`, `Waiting for Events`, `Offline Collection Active`, `Sync Pending`, and `Error`.
  6. *Phase 6 & 7 — AI Engine Preservation & Startup Performance Optimization*:
     - In `backend/anomaly_detection/model.py`: Added model persistence (`save` and `load` via `joblib`).
     - In `backend/main.py`: Lifespan checks for cached model (`models/isolation_forest.joblib`); loads pre-trained model on startup in <10ms instead of retraining 150 synthetic vectors on every boot. Reuses Behavioral Digital Twin baseline.
     - Frontend compiles with Vite in 542ms; lightweight bundle size (~439 kB gzip: 110 kB).
  7. *Phase 8 — Installer Security & Packaging Analysis*:
     - Configured `package.json` with NSIS setup installer target (`"target": ["nsis", "portable"]`), `"publisherName": "CyberThreat AI Research Lab"`, and Windows execution levels.
     - Documented root cause of Chrome download warning: Unsigned executable lacks an Authenticode EV Code Signing Certificate recognized by Microsoft SmartScreen and Google Safe Browsing. Explained commercial CA signing requirements and trusted delivery practices.
  8. *Phase 9 — Domain Availability & Deployment Architecture*:
     - Conducted actual registry lookups: `cyberthreatai.com` and `cyberguardai.com` are registered. Documented custom domain setup and recommended free-tier architecture (Vercel frontend, Render/Railway FastAPI backend, Neon PostgreSQL / SQLite local storage).
  9. *Phase 10 — UI Corrections Preserved*:
     - Verified `src/components/HomeView.jsx`: Minimal layout with 1 Test Protection button, clear Safe/Danger test outcome, clean status indicators, and no visible formula panels or A/B/H cards.
  10. *Phase 11 — Comprehensive Testing & Verification*:
      - Created `tests/test_complete_correction_verification.py` validating Tests A through E.
      - Ran complete test suite: **67 passed out of 67 tests** across all test suites in 36.21s.
      - Verified production frontend build: `npm run build` passed cleanly in 542ms.

---

### Stage 18: Phase 1 Completed — Core Monitoring System & Activity History (2026-11-01)
- **Objective**: Fix core monitoring system reliability failures before adding new features:
  1. Capture supported Windows online and offline activities (processes, files, network, docs).
  2. Store every event in SQLite immediately, even without internet.
  3. Display historical events using Today, Yesterday and Custom Date filters with timezone boundaries.
  4. Preserve timestamps and device IDs throughout offline-online cycles.
  5. Synchronize pending events after reconnection without duplicates.
  6. Separate test events from genuine user activities.
- **Failures Identified & Resolved**:
  1. *Active Application Startup Blindspot*: Previously, `ProcessMonitor` initialized by marking all current PIDs as seen, completely ignoring user applications (Chrome, VS Code, Word, Notepad, File Explorer) that were already running before backend launch.
     - *Fix*: Enhanced `_emit_startup_snapshot()` in `backend/monitoring/engine.py` to inspect `get_visible_window_pids()` and emit clean `APPLICATION_START` snapshot records for interactive user applications on launch.
  2. *Unbound Monitor Device on User Login*: Telemetry collected offline or prior to frontend login was attributed to fallback `user_id = 'current_user'`, causing legitimate user queries to show empty Activity feeds.
     - *Fix*: Updated `/auth/login` in `backend/api/routes.py` to auto-bind `real_monitor` to the authenticated user ID and execute `db.migrate_unbound_events(device_id, user["id"])`.
  3. *SQLite Date Filtering & Timezone Normalization*:
     - *Fix*: Standardized UTC ISO format (`datetime.now(timezone.utc).isoformat()`) across all SQLite write paths, replacing deprecated `datetime.utcnow()`.
     - Added first-class `db.get_date_summary()` in `backend/database/db.py` computing calendar day counts using client timezone offsets.
  4. *Idempotent Synchronization & Test Event Isolation*:
     - Reconnection triggers `SyncEngine.sync_pending_queue()` transitioning `PENDING` events to `SYNCHRONIZED` with preserved original timestamps and device IDs.
     - Strict `exclude_test=True` SQL filtering isolates synthetic benchmark and diagnostic test events (`TEST_*`, `is_test_event: true`, `TEST_ENDPOINT`).
- **Files Changed**:
  - `backend/monitoring/engine.py`: Enhanced `_emit_startup_snapshot()` to capture running interactive applications.
  - `backend/database/db.py`: Added `get_date_summary()` to `DatabaseManager`, replaced deprecated `utcnow()` calls with `datetime.now(timezone.utc)`.
  - `backend/api/routes.py`: Enhanced `/auth/login` with host monitor binding and event migration.
  - `tests/test_phase1_core_monitoring.py`: Created 5 automated tests validating all Phase 1 success criteria.
- **Verification Results**:
  - `pytest tests/test_phase1_core_monitoring.py -v`: **5 passed out of 5** in 0.63s.
  - `npm run build`: **PASS** in 1.14s.










