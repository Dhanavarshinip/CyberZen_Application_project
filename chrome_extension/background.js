/**
 * CyberThreat AI - Real-Time Browser Protection Service Worker (v1.2.0)
 * Dual-Engine Architecture: Auto-detects local high-speed engine (127.0.0.1:8000)
 * and seamlessly fails over to the global cloud API (cyberzen-security-api.onrender.com).
 * 
 * Works 100% out-of-the-box on any machine, even when local desktop app is not running.
 */

const LOCAL_API_BASE = "http://127.0.0.1:8000/api";
const CLOUD_API_BASE = "https://cyberzen.13.211.114.156.sslip.io/api";
const FETCH_TIMEOUT_MS = 6000;

// State management
let cachedApiBase = null;
let lastProbeTime = 0;
const PROBE_INTERVAL_MS = 15000; // Re-probe local availability every 15s

const recentVerdicts = new Map();
const tabLastEvaluatedUrl = new Map();
const inFlightEvaluations = new Map();

/**
 * Resolves the active backend API base URL.
 * Probes local 127.0.0.1:8000 first with a fast timeout (1200ms).
 * If unreachable or down, automatically fails over to Cloud API.
 */
async function getApiBase() {
  const now = Date.now();

  // 1. Check if user configured a manual override in storage
  try {
    const stored = await chrome.storage.local.get(["custom_api_base", "prefer_cloud"]);
    if (stored.custom_api_base) return stored.custom_api_base.replace(/\/+$/, "");
    if (stored.prefer_cloud) return CLOUD_API_BASE;
  } catch (_) {}

  // 2. Return cached backend if tested recently
  if (cachedApiBase && (now - lastProbeTime < PROBE_INTERVAL_MS)) {
    return cachedApiBase;
  }

  // 3. Fast-probe local desktop engine
  try {
    const probeController = new AbortController();
    const probeTimer = setTimeout(() => probeController.abort(), 1200);
    const res = await fetch(`${LOCAL_API_BASE}/health`, { signal: probeController.signal });
    clearTimeout(probeTimer);
    if (res.ok) {
      cachedApiBase = LOCAL_API_BASE;
      lastProbeTime = now;
      chrome.storage.local.set({
        active_backend: "LOCAL",
        active_api_url: LOCAL_API_BASE,
        backend_name: "Local Desktop Engine (127.0.0.1:8000)"
      }).catch(() => {});
      return LOCAL_API_BASE;
    }
  } catch (_) {}

  // 4. Default to Production Cloud Backend
  cachedApiBase = CLOUD_API_BASE;
  lastProbeTime = now;
  chrome.storage.local.set({
    active_backend: "CLOUD",
    active_api_url: CLOUD_API_BASE,
    backend_name: "CyberZen Cloud API (AWS Production)"
  }).catch(() => {});
  return CLOUD_API_BASE;
}

function shouldSkipUrl(url) {
  if (!url || typeof url !== "string") return true;
  try {
    const u = new URL(url);
    if (
      u.protocol === "chrome:" ||
      u.protocol === "about:" ||
      u.protocol === "chrome-extension:" ||
      u.protocol === "edge:" ||
      u.protocol === "data:" ||
      u.protocol === "javascript:" ||
      u.hostname === ""
    ) {
      return true;
    }
    // Skip CyberThreat AI's own local dashboard and dev server
    if (
      (u.hostname === "127.0.0.1" || u.hostname === "localhost") &&
      (u.port === "8000" || u.port === "5173")
    ) {
      return true;
    }
    return false;
  } catch {
    return true;
  }
}

async function fetchWithTimeout(resource, options, timeoutMs = FETCH_TIMEOUT_MS) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch(resource, { ...options, signal: controller.signal });
    clearTimeout(timer);
    return response;
  } catch (err) {
    clearTimeout(timer);
    throw err;
  }
}

/**
 * Main evaluation orchestrator:
 * Queries backend (Local or Cloud with automatic fallback), assigns badges, records verdicts.
 */
async function evaluateUrl(url, tabId = null, title = null) {
  if (shouldSkipUrl(url)) {
    return {
      status: "SKIPPED",
      domain: "",
      risk_score: 0,
      reasons: [],
      url
    };
  }

  let domain = "";
  try {
    domain = new URL(url).hostname;
  } catch {
    domain = url;
  }

  // Deduplicate rapid repeat queries (< 3.5 seconds) for identical URL
  const cached = recentVerdicts.get(url);
  if (cached && (Date.now() - cached.timestamp < 3500)) {
    updateBadge(cached.verdict.status, tabId);
    return cached.verdict;
  }

  // If already querying this URL, reuse in-flight promise
  if (inFlightEvaluations.has(url)) {
    return await inFlightEvaluations.get(url);
  }

  // Show evaluating indicator
  if (tabId) {
    try {
      chrome.action.setBadgeText({ text: "...", tabId });
      chrome.action.setBadgeBackgroundColor({ color: "#0284c7", tabId });
    } catch (_) {}
  }

  const evalPromise = (async () => {
    try {
      if (!title && tabId) {
        try {
          const tab = await chrome.tabs.get(tabId);
          if (tab && tab.title) title = tab.title;
        } catch (_) {}
      }

      // Retrieve paired credentials from storage
      const storage = await chrome.storage.local.get(["user_id", "device_id", "auth_token"]);
      const userId = storage.user_id || "current_user";
      const deviceId = storage.device_id || null;
      const headers = { "Content-Type": "application/json" };
      if (storage.auth_token) headers["Authorization"] = `Bearer ${storage.auth_token}`;

      const payload = JSON.stringify({
        url,
        title: title || "",
        user_id: userId,
        device_id: deviceId
      });

      // Resolve backend with automatic fallback
      let apiBase = await getApiBase();
      let response = null;

      try {
        response = await fetchWithTimeout(`${apiBase}/browser/event`, { method: "POST", headers, body: payload }, FETCH_TIMEOUT_MS);
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
      } catch (firstErr) {
        // If local engine failed, failover immediately to cloud
        if (apiBase.startsWith(LOCAL_API_BASE)) {
          console.warn("[CyberThreat AI] Local backend query failed, switching to cloud failover:", firstErr.message);
          apiBase = CLOUD_API_BASE;
          cachedApiBase = CLOUD_API_BASE;
          response = await fetchWithTimeout(`${apiBase}/browser/event`, { method: "POST", headers, body: payload }, FETCH_TIMEOUT_MS);
          if (!response.ok) throw new Error(`HTTP ${response.status}`);
        } else {
          throw firstErr;
        }
      }

      const data = await response.json();
      const rawStatus = (data.status || data.evaluation?.status || "UNKNOWN").toUpperCase();
      const status = ["SAFE", "DANGEROUS", "SUSPICIOUS", "UNKNOWN"].includes(rawStatus) ? rawStatus : "UNKNOWN";
      const rawScore = data.risk_score !== undefined ? data.risk_score : data.evaluation?.risk_score;
      const riskScore = (rawScore !== null && rawScore !== undefined) ? Math.round(rawScore) : null;
      const reasons = data.reasons || data.evaluation?.reasons || [];
      const reportedDomain = data.domain || data.evaluation?.domain || domain;

      const verdict = {
        status,
        domain: reportedDomain,
        risk_score: riskScore,
        reasons: reasons.length > 0 ? reasons : [`Standard threat analysis completed for ${reportedDomain}.`],
        url,
        backend: apiBase.includes("127.0.0.1") ? "LOCAL" : "CLOUD",
        timestamp: Date.now()
      };

      recentVerdicts.set(url, { timestamp: Date.now(), verdict });
      if (tabId) tabLastEvaluatedUrl.set(tabId, url);
      updateBadge(status, tabId);

      // Trigger desktop notification only for confirmed DANGEROUS threats
      if (status === "DANGEROUS") {
        try {
          chrome.notifications.create(`danger_${Date.now()}`, {
            type: "basic",
            iconUrl: "icon.png",
            title: "🚨 CyberThreat AI: Dangerous Website",
            message: `${reportedDomain}: ${reasons[0] || 'Malicious threat detected.'}`,
            priority: 2
          });
        } catch (_) {}
      }

      chrome.storage.local.set({
        latestEvaluation: verdict,
        lastUrl: url,
        lastChecked: new Date().toISOString()
      }).catch(() => {});

      return verdict;

    } catch (err) {
      const isTimeout = err.name === "AbortError";
      console.warn(`[CyberThreat AI] Threat analysis unavailable for ${domain}:`, err.message);

      const failVerdict = {
        status: "UNKNOWN",
        domain,
        risk_score: null,
        reasons: [
          isTimeout
            ? "Threat analysis query timed out. Network latency detected."
            : "Reconnecting to CyberZen Threat Intelligence Network..."
        ],
        check_failed: true,
        url,
        timestamp: Date.now()
      };

      recentVerdicts.set(url, { timestamp: Date.now(), verdict: failVerdict });
      updateBadge("UNKNOWN", tabId);

      chrome.storage.local.set({
        latestEvaluation: failVerdict,
        lastUrl: url,
        lastChecked: new Date().toISOString()
      }).catch(() => {});

      return failVerdict;
    }
  })();

  inFlightEvaluations.set(url, evalPromise);
  try {
    return await evalPromise;
  } finally {
    inFlightEvaluations.delete(url);
  }
}

function updateBadge(status, tabId) {
  if (!tabId) return;
  try {
    if (status === "DANGEROUS") {
      chrome.action.setBadgeText({ text: "!", tabId });
      chrome.action.setBadgeBackgroundColor({ color: "#EF4444", tabId });
    } else if (status === "SUSPICIOUS") {
      chrome.action.setBadgeText({ text: "!", tabId });
      chrome.action.setBadgeBackgroundColor({ color: "#F59E0B", tabId });
    } else if (status === "SAFE") {
      chrome.action.setBadgeText({ text: "OK", tabId });
      chrome.action.setBadgeBackgroundColor({ color: "#10B981", tabId });
    } else if (status === "UNKNOWN") {
      chrome.action.setBadgeText({ text: "?", tabId });
      chrome.action.setBadgeBackgroundColor({ color: "#64748B", tabId });
    } else {
      chrome.action.setBadgeText({ text: "", tabId });
    }
  } catch (_) {}
}

// 1. Message listener for direct content script queries and actions
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "ANALYZE_URL") {
    const tabId = sender.tab?.id || null;
    const title = request.title || sender.tab?.title || null;
    evaluateUrl(request.url, tabId, title).then((verdict) => {
      sendResponse(verdict);
    });
    return true;
  }

  // Content script calls this to record Gmail / web events without page CSP issues
  if (request.action === "RECORD_EVENT") {
    (async () => {
      try {
        const apiBase = await getApiBase();
        const storage = await chrome.storage.local.get(["user_id", "device_id", "auth_token"]);
        const headers = { "Content-Type": "application/json" };
        if (storage.auth_token) headers["Authorization"] = `Bearer ${storage.auth_token}`;

        const payload = {
          ...request.payload,
          user_id: request.payload?.user_id || storage.user_id || "current_user",
          device_id: request.payload?.device_id || storage.device_id || null
        };

        const res = await fetch(`${apiBase}/browser/event`, {
          method: "POST",
          headers,
          body: JSON.stringify(payload)
        });
        const data = await res.json().catch(() => ({}));
        sendResponse({ success: res.ok, data });
      } catch (err) {
        sendResponse({ success: false, error: err.message });
      }
    })();
    return true;
  }

  // Return pairing details to content script or popup
  if (request.action === "GET_PAIRING") {
    (async () => {
      const deviceId = await getOrCreateDeviceId();
      try {
        const apiBase = await getApiBase();
        const res = await fetch(`${apiBase}/extension/active-pairing?device_id=${encodeURIComponent(deviceId)}`, { signal: AbortSignal.timeout(3000) });
        if (res.ok) {
          const data = await res.json();
          if (data && data.is_paired) {
            sendResponse({ success: true, pairing: data });
            return;
          }
        }
      } catch (_) {}
      const stored = await chrome.storage.local.get(["user_email", "user_id", "allowed_emails"]);
      sendResponse({ success: !!stored.user_email, pairing: { ...stored, device_id: deviceId } });
    })();
    return true;
  }

  // Web console sync handler
  if (request.action === "SYNC_FROM_WEB_CONSOLE") {
    (async () => {
      try {
        const { email, user_id, token, device_id } = request.payload || {};
        const devId = device_id || (await getOrCreateDeviceId());
        if (email) {
          await chrome.storage.local.set({
            user_email: email,
            user_id: user_id || "current_user",
            device_id: devId,
            auth_token: token || "",
            allowed_emails: [email]
          });
          const apiBase = await getApiBase();
          await fetch(`${apiBase}/extension/pair`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ email, device_id: devId, user_id })
          }).catch(() => {});
          sendHeartbeat();
          sendResponse({ success: true, device_id: devId });
          return;
        }
        sendResponse({ success: false, error: "No email provided" });
      } catch (err) {
        sendResponse({ success: false, error: err.message });
      }
    })();
    return true;
  }

  if (request.action === "SYNC_PAIRING") {
    ensurePairedCredentials().then((paired) => sendResponse({ success: paired }));
    return true;
  }

  if (request.action === "GET_BACKEND_STATUS") {
    getApiBase().then((api) => {
      sendResponse({
        active_api_url: api,
        is_local: api.includes("127.0.0.1"),
        backend_name: api.includes("127.0.0.1") ? "Local Engine" : "Cloud API"
      });
    });
    return true;
  }
});

// 2. Navigation listener: onCommitted fires as soon as browser commits to new document
chrome.webNavigation.onCommitted.addListener((details) => {
  if (details.frameId === 0 && !shouldSkipUrl(details.url)) {
    chrome.tabs.get(details.tabId, (tab) => {
      const title = tab?.title || null;
      evaluateUrl(details.url, details.tabId, title).then((verdict) => {
        chrome.tabs.sendMessage(details.tabId, {
          action: "SECURITY_VERDICT",
          url: details.url,
          verdict
        }).catch(() => {});
      });
    });
  }
});

// 3. Tab update completion listener
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === "complete" && tab.url && !shouldSkipUrl(tab.url)) {
    const lastUrl = tabLastEvaluatedUrl.get(tabId);
    if (lastUrl !== tab.url) {
      evaluateUrl(tab.url, tabId, tab.title || null).then((verdict) => {
        chrome.tabs.sendMessage(tabId, {
          action: "SECURITY_VERDICT",
          url: tab.url,
          verdict
        }).catch(() => {});
      });
    }
  }
});

// 4. Tab switch listener
chrome.tabs.onActivated.addListener(async (activeInfo) => {
  try {
    const tab = await chrome.tabs.get(activeInfo.tabId);
    if (tab && tab.url && !shouldSkipUrl(tab.url)) {
      const cached = recentVerdicts.get(tab.url);
      if (cached) {
        updateBadge(cached.verdict.status, activeInfo.tabId);
      }
    }
  } catch (_) {}
});

chrome.tabs.onRemoved.addListener((tabId) => {
  tabLastEvaluatedUrl.delete(tabId);
});

// Helper to get or persist a stable, unique device identifier
async function getOrCreateDeviceId() {
  try {
    const stored = await chrome.storage.local.get(["device_id"]);
    if (stored.device_id && stored.device_id !== "DEV-LOCAL" && stored.device_id !== "DEV-HOST" && stored.device_id !== "DEV_HW_D51F7263411C" && stored.device_id !== "UNPAIRED") {
      return stored.device_id;
    }
    const newId = `DEV_${Math.random().toString(36).substring(2, 8).toUpperCase()}${Date.now().toString(36).substring(4).toUpperCase()}`;
    await chrome.storage.local.set({ device_id: newId });
    return newId;
  } catch (_) {
    return `DEV_${Math.random().toString(36).substring(2, 10).toUpperCase()}`;
  }
}

// Auto-sync pairing credentials on startup and periodically
async function ensurePairedCredentials() {
  const deviceId = await getOrCreateDeviceId();
  const apiBase = await getApiBase();

  // 1. Try querying active pairing endpoint from resolved backend with device_id
  try {
    const activeRes = await fetch(`${apiBase}/extension/active-pairing?device_id=${encodeURIComponent(deviceId)}`, { signal: AbortSignal.timeout(3000) });
    if (activeRes.ok) {
      const activeData = await activeRes.json();
      if (activeData && activeData.email && activeData.email !== "unpaired@cyberthreat.local" && activeData.is_paired) {
        await chrome.storage.local.set({
          user_email: activeData.email,
          user_id: activeData.user_id || "current_user",
          device_id: deviceId,
          allowed_emails: activeData.allowed_emails || [activeData.email]
        });
        sendHeartbeat();
        return true;
      }
    }
  } catch (_) {}

  // 2. Fallback to pairing_credentials.json if included in package
  try {
    const credsUrl = chrome.runtime.getURL("pairing_credentials.json");
    const credsRes = await fetch(credsUrl);
    if (credsRes.ok) {
      const creds = await credsRes.json();
      if (creds && creds.email && creds.email !== "unpaired@cyberthreat.local" && creds.email.trim() !== "") {
        await chrome.storage.local.set({
          user_email: creds.email,
          user_id: creds.user_id || "current_user",
          device_id: creds.device_id || deviceId,
          allowed_emails: [creds.email]
        });
        sendHeartbeat();
        return true;
      }
    }
  } catch (_) {}

  return false;
}

async function sendHeartbeat() {
  try {
    const deviceId = await getOrCreateDeviceId();
    const apiBase = await getApiBase();
    const storage = await chrome.storage.local.get(["user_email", "user_id"]);
    await fetch(`${apiBase}/extension/heartbeat`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        device_id: deviceId,
        user_id: storage.user_id || "current_user",
        email: storage.user_email || "",
        version: "1.2.0"
      })
    });
  } catch (_) {}
}

chrome.runtime.onInstalled.addListener(() => {
  ensurePairedCredentials();
});

chrome.runtime.onStartup.addListener(() => {
  ensurePairedCredentials();
});

// Periodic automated pairing & heartbeat check
ensurePairedCredentials();
sendHeartbeat();
setInterval(ensurePairedCredentials, 15000);
setInterval(sendHeartbeat, 30000);
