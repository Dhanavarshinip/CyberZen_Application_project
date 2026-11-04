/**
 * CyberThreat AI - Real-Time Browser Protection Service Worker (v3)
 * Authenticates & evaluates all website navigations against CyberThreat AI backend.
 * Provides instant real-time security verdicts to in-page overlays and browser action.
 */

const BACKEND_URL = "http://127.0.0.1:8000/api/browser/event";
const FETCH_TIMEOUT_MS = 6000;

// Cache to deduplicate rapid back-to-back checks on the exact same URL
const recentVerdicts = new Map();
const tabLastEvaluatedUrl = new Map();
const inFlightEvaluations = new Map();

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
    // Only skip CyberThreat AI's own backend and dev dashboard
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
 * Queries backend, assigns badges, records verdicts, returns unified result.
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

  // Deduplicate rapid repeat queries (< 3.5 seconds) for the identical URL
  const cached = recentVerdicts.get(url);
  if (cached && (Date.now() - cached.timestamp < 3500)) {
    updateBadge(cached.verdict.status, tabId);
    return cached.verdict;
  }

  // If already querying this URL, reuse in-flight promise to prevent duplicate requests
  if (inFlightEvaluations.has(url)) {
    return await inFlightEvaluations.get(url);
  }

  // Show evaluating indicator on badge
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

      const response = await fetchWithTimeout(
        BACKEND_URL,
        {
          method: "POST",
          headers,
          body: JSON.stringify({
            url,
            title: title || "",
            user_id: userId,
            device_id: deviceId
          })
        },
        FETCH_TIMEOUT_MS
      );

      if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
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
        reasons: reasons.length > 0 ? reasons : [`Standard analysis completed for ${reportedDomain}.`],
        url,
        timestamp: Date.now()
      };

      recentVerdicts.set(url, { timestamp: Date.now(), verdict });
      if (tabId) tabLastEvaluatedUrl.set(tabId, url);
      updateBadge(status, tabId);

      // Only trigger desktop notification for confirmed DANGEROUS threats (no spam for safe sites)
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
      console.warn(`[CyberThreat AI] Backend analysis unavailable for ${domain}:`, err.message);

      const failVerdict = {
        status: "UNKNOWN",
        domain,
        risk_score: null,
        reasons: [
          isTimeout
            ? "Analysis timed out — CyberThreat AI backend is busy."
            : "CyberThreat AI backend offline. Launch CyberThreat AI Desktop to enable real-time analysis."
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

// 1. Message listener for direct content script queries (on load and SPA route change)
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "ANALYZE_URL") {
    const tabId = sender.tab?.id || null;
    const title = request.title || sender.tab?.title || null;
    evaluateUrl(request.url, tabId, title).then((verdict) => {
      sendResponse(verdict);
    });
    return true; // Keep message channel open for async response
  }
});

// 2. Navigation listener: onCommitted fires as soon as browser commits to new document
chrome.webNavigation.onCommitted.addListener((details) => {
  if (details.frameId === 0 && !shouldSkipUrl(details.url)) {
    chrome.tabs.get(details.tabId, (tab) => {
      const title = tab?.title || null;
      evaluateUrl(details.url, details.tabId, title).then((verdict) => {
        // Proactively notify content script if already mounted
        chrome.tabs.sendMessage(details.tabId, {
          action: "SECURITY_VERDICT",
          url: details.url,
          verdict
        }).catch(() => {
          // Content script will fetch via ANALYZE_URL message upon mounting
        });
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

// 4. Tab switch listener: update badge when switching active tabs
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

// Clean up state on tab close
chrome.tabs.onRemoved.addListener((tabId) => {
  tabLastEvaluatedUrl.delete(tabId);
});

// Auto-load credentials from active-pairing API or pairing_credentials.json on startup
async function ensurePairedCredentials() {
  // 1. Try querying backend active pairing endpoint directly (dynamic on any machine)
  try {
    const activeRes = await fetch("http://127.0.0.1:8000/api/extension/active-pairing");
    if (activeRes.ok) {
      const activeData = await activeRes.json();
      if (activeData && activeData.email && activeData.email !== "unpaired@cyberthreat.local" && activeData.is_paired) {
        await chrome.storage.local.set({
          user_email: activeData.email,
          user_id: activeData.user_id || "current_user",
          device_id: activeData.device_id || "DEV-LOCAL"
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
      if (creds && creds.email && creds.email !== "unpaired@cyberthreat.local") {
        await chrome.storage.local.set({
          user_email: creds.email,
          user_id: creds.user_id || "current_user",
          device_id: creds.device_id || "DEV-HOST"
        });
        sendHeartbeat();
        return true;
      }
    }
  } catch (_) {}

  // 3. Fallback: query backend status directly
  try {
    const res = await fetch("http://127.0.0.1:8000/api/monitoring/status");
    if (res.ok) {
      const data = await res.json();
      if (data?.device_id) {
        await chrome.storage.local.set({
          device_id: data.device_id,
          user_id: data.user_id || "current_user"
        });
      }
    }
  } catch (_) {}
  return false;
}

async function sendHeartbeat() {
  try {
    const storage = await chrome.storage.local.get(["user_email", "user_id", "device_id"]);
    // If not paired yet, try auto-discovery now
    if (!storage.user_email || storage.user_email === "unpaired@cyberthreat.local") {
      await ensurePairedCredentials();
    }
    const updated = await chrome.storage.local.get(["user_email", "user_id", "device_id"]);
    await fetch("http://127.0.0.1:8000/api/extension/heartbeat", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        device_id: updated.device_id || "DEV-LOCAL",
        user_id: updated.user_id || "current_user",
        email: updated.user_email || "",
        version: "1.1.0"
      })
    });
  } catch (_) {}
}

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg && msg.action === "SYNC_PAIRING") {
    ensurePairedCredentials().then((paired) => sendResponse({ success: paired }));
    return true;
  }
});

chrome.runtime.onInstalled.addListener(() => {
  ensurePairedCredentials();
});

chrome.runtime.onStartup.addListener(() => {
  ensurePairedCredentials();
});

// Periodic automated pairing & heartbeat check
ensurePairedCredentials();
sendHeartbeat();
setInterval(ensurePairedCredentials, 10000);
setInterval(sendHeartbeat, 25000);
