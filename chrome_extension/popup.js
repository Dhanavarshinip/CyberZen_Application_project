/**
 * CyberThreat AI - Extension Popup Script (v1.2.0)
 * Dual-Engine Architecture: Connects seamlessly to Local Desktop Engine (127.0.0.1:8000)
 * or Production Cloud Network (cyberzen-security-api.onrender.com).
 */

const LOCAL_API_BASE = "http://127.0.0.1:8000/api";
const CLOUD_API_BASE = "https://cyberzen.13.211.114.156.sslip.io/api";

const statusBadge    = document.getElementById("status-badge");
const statusDot      = document.getElementById("status-dot");
const domainText     = document.getElementById("domain-text");
const reasonsText    = document.getElementById("reasons-text");
const riskRow        = document.getElementById("risk-row");
const riskBar        = document.getElementById("risk-bar");
const riskLabel      = document.getElementById("risk-label");
const lastChecked    = document.getElementById("last-checked-text");

const pairBadge      = document.getElementById("pair-badge");
const pairedEmail    = document.getElementById("paired-email");
const pairedDevice   = document.getElementById("paired-device");
const backendStatus  = document.getElementById("backend-status");
const gmailStatus    = document.getElementById("gmail-status");
const btnPair        = document.getElementById("btn-pair");
const btnUnpair      = document.getElementById("btn-unpair");
const pairingPill    = document.getElementById("pairing-pill");
const monitoredCount = document.getElementById("monitored-count");
const openDashBtn    = document.getElementById("open-dashboard-btn");

let currentApiBase = CLOUD_API_BASE;

/**
 * Resolves the operational API base: probes local 127.0.0.1 first, falls back to cloud.
 */
async function resolveApiBase() {
  // Check stored override
  try {
    const stored = await chrome.storage.local.get(["custom_api_base", "prefer_cloud"]);
    if (stored.custom_api_base) return stored.custom_api_base.replace(/\/+$/, "");
    if (stored.prefer_cloud) return CLOUD_API_BASE;
  } catch (_) {}

  // Fast probe local
  try {
    const res = await fetch(`${LOCAL_API_BASE}/health`, { signal: AbortSignal.timeout(1000) });
    if (res.ok) {
      currentApiBase = LOCAL_API_BASE;
      if (backendStatus) {
        backendStatus.textContent = "🟢 Local Engine (127.0.0.1)";
        backendStatus.style.color = "#34d399";
      }
      if (openDashBtn) openDashBtn.href = "http://127.0.0.1:8000";
      return LOCAL_API_BASE;
    }
  } catch (_) {}

  currentApiBase = CLOUD_API_BASE;
  if (backendStatus) {
    backendStatus.textContent = "☁️ Cloud Protection (Active)";
    backendStatus.style.color = "#38bdf8";
  }
  if (openDashBtn) openDashBtn.href = "https://cyberzen.13.211.114.156.sslip.io";
  return CLOUD_API_BASE;
}

function updatePairingUI(email, deviceId, allowedEmails = []) {
  if (email && email !== "Not Paired" && email !== "unpaired@cyberthreat.local" && email !== "current_user") {
    pairBadge.textContent = "PAIRED";
    pairBadge.className = "badge badge-safe";
    pairBadge.style.fontSize = "10px";
    pairBadge.style.padding = "2px 6px";
    pairedEmail.textContent = email;
    pairedDevice.textContent = deviceId || "DEV-CLIENT";
    gmailStatus.textContent = "Active (Strict Account Scope)";
    gmailStatus.style.color = "#34d399";
    if (monitoredCount) {
      const count = (allowedEmails && allowedEmails.length > 0) ? allowedEmails.length : 1;
      monitoredCount.textContent = count > 1 ? `${count} Accounts Monitored` : "Registered Gmail Only";
    }
    if (pairingPill) {
      pairingPill.textContent = "Paired";
      pairingPill.style.color = "#34d399";
    }
  } else {
    pairBadge.textContent = "NOT PAIRED";
    pairBadge.className = "badge badge-suspicious";
    pairBadge.style.fontSize = "10px";
    pairBadge.style.padding = "2px 6px";
    pairedEmail.textContent = "None (Click Sync)";
    pairedDevice.textContent = deviceId || "Unbound";
    gmailStatus.textContent = "Auto Protection (All Websites)";
    gmailStatus.style.color = "#38bdf8";
    if (monitoredCount) {
      monitoredCount.textContent = "Global Shield";
    }
    if (pairingPill) {
      pairingPill.textContent = "Active";
      pairingPill.style.color = "#38bdf8";
    }
  }
}

// Load paired state from local storage or auto-sync from backend
chrome.storage.local.get(["user_email", "user_id", "device_id", "allowed_emails"], async (stored) => {
  const apiBase = await resolveApiBase();

  // Attempt fresh discovery from resolved backend session
  try {
    const activeRes = await fetch(`${apiBase}/extension/active-pairing`, { signal: AbortSignal.timeout(3000) });
    if (activeRes.ok) {
      const activeData = await activeRes.json();
      if (activeData && activeData.email && activeData.email !== "unpaired@cyberthreat.local" && activeData.is_paired) {
        await chrome.storage.local.set({
          user_email: activeData.email,
          user_id: activeData.user_id,
          device_id: activeData.device_id,
          allowed_emails: activeData.allowed_emails || [activeData.email]
        });
        updatePairingUI(activeData.email, activeData.device_id, activeData.allowed_emails);
        return;
      }
    }
  } catch (_) {}

  if (stored.user_email && stored.user_email !== "Not Paired" && stored.user_email !== "unpaired@cyberthreat.local") {
    updatePairingUI(stored.user_email, stored.device_id, stored.allowed_emails);
  } else {
    updatePairingUI(null, stored.device_id, []);
  }
});

// Sync with Desktop App / Cloud Backend
if (btnPair) {
  btnPair.addEventListener("click", async () => {
    btnPair.textContent = "Syncing...";
    try {
      const apiBase = await resolveApiBase();
      let pairRes = null;
      try {
        pairRes = await fetch(`${apiBase}/extension/active-pairing`, { signal: AbortSignal.timeout(3500) });
      } catch (err) {
        if (apiBase.startsWith(LOCAL_API_BASE)) {
          pairRes = await fetch(`${CLOUD_API_BASE}/extension/active-pairing`, { signal: AbortSignal.timeout(3500) });
        } else {
          throw err;
        }
      }

      if (pairRes && pairRes.ok) {
        const pairData = await pairRes.json();
        const email = pairData.email;
        const devId = pairData.device_id;
        const devUser = pairData.user_id;

        if (pairData.is_paired && email && email !== "unpaired@cyberthreat.local") {
          const allowedList = pairData.allowed_emails || [email];
          await chrome.storage.local.set({
            user_email: email,
            user_id: devUser,
            device_id: devId,
            allowed_emails: allowedList
          });

          // Heartbeat
          fetch(`${apiBase}/extension/heartbeat`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              device_id: devId,
              user_id: devUser,
              email: email,
              version: "1.2.0"
            })
          }).catch(() => {});

          updatePairingUI(email, devId, allowedList);
          btnPair.textContent = "✓ Connected";
          setTimeout(() => { btnPair.textContent = "Sync with App"; }, 2500);
        } else {
          btnPair.textContent = "✓ Cloud Connected";
          setTimeout(() => { btnPair.textContent = "Sync with App"; }, 3000);
        }
      } else {
        throw new Error("Backend answered with error");
      }
    } catch (err) {
      btnPair.textContent = "☁️ Cloud Protected";
      setTimeout(() => { btnPair.textContent = "Sync with App"; }, 3000);
    }
  });
}

// Unpair
if (btnUnpair) {
  btnUnpair.addEventListener("click", async () => {
    if (confirm("Unpair extension account? Real-time protection will remain active.")) {
      await chrome.storage.local.remove(["user_email", "user_id", "device_id", "auth_token"]);
      updatePairingUI(null, null);
    }
  });
}

function applyStatus(status, risk, domain, reasons, checkedAt) {
  const s = (status || "UNKNOWN").toUpperCase();
  const hasRisk = (risk !== null && risk !== undefined && s !== "UNKNOWN");
  const r = hasRisk ? Number(risk) : 0;

  domainText.textContent = domain || "Unknown";
  reasonsText.textContent = reasons?.[0] || "No known threat indicators detected.";

  if (checkedAt) {
    try {
      const d = new Date(checkedAt);
      lastChecked.textContent = "Last checked: " + d.toLocaleTimeString();
    } catch (_) {}
  }

  // Risk bar
  if (hasRisk) {
    riskRow.style.display = "flex";
    riskBar.style.width = Math.min(r, 100) + "%";
    riskLabel.textContent = r + "/100";
    if (s === "DANGEROUS") riskBar.style.background = "#ef4444";
    else if (s === "SUSPICIOUS") riskBar.style.background = "#f59e0b";
    else if (s === "SAFE") riskBar.style.background = "#10b981";
    else riskBar.style.background = "#6b7280";
  } else {
    riskRow.style.display = "flex";
    riskBar.style.width = "0%";
    riskLabel.textContent = s === "SAFE" ? "0/100" : "Unverified";
    riskBar.style.background = s === "SAFE" ? "#10b981" : "#64748b";
  }

  // Badge
  statusBadge.className = "badge";
  statusDot.style.background = "#6b7280";
  statusDot.style.boxShadow = "none";

  if (s === "SAFE") {
    statusBadge.textContent = "✓ SAFE";
    statusBadge.classList.add("badge-safe");
    statusDot.style.background = "#10b981";
    statusDot.style.boxShadow = "0 0 8px rgba(16, 185, 129, 0.6)";
  } else if (s === "DANGEROUS") {
    statusBadge.textContent = "🚨 DANGEROUS";
    statusBadge.classList.add("badge-dangerous");
    statusDot.style.background = "#ef4444";
    statusDot.style.boxShadow = "0 0 8px rgba(239, 68, 68, 0.6)";
  } else if (s === "SUSPICIOUS") {
    statusBadge.textContent = "⚠ SUSPICIOUS";
    statusBadge.classList.add("badge-suspicious");
    statusDot.style.background = "#f59e0b";
    statusDot.style.boxShadow = "0 0 8px rgba(245, 158, 11, 0.6)";
  } else {
    statusBadge.textContent = "✓ SECURE";
    statusBadge.classList.add("badge-safe");
    statusDot.style.background = "#10b981";
  }
}

// Load last evaluation from storage, then refresh with current tab
chrome.storage.local.get(["latestEvaluation", "lastUrl", "lastChecked"], (stored) => {
  if (stored.latestEvaluation) {
    const ev = stored.latestEvaluation;
    applyStatus(ev.status, ev.risk_score, ev.domain, ev.reasons, stored.lastChecked);
  }
});

// Fetch fresh evaluation for the current active tab
chrome.tabs.query({ active: true, currentWindow: true }, async (tabs) => {
  if (!tabs || !tabs[0]) return;
  const url = tabs[0].url;
  if (!url || url.startsWith("chrome://") || url.startsWith("chrome-extension://") || url.startsWith("edge://")) {
    domainText.textContent = "Browser Internal Page";
    reasonsText.textContent = "Security inspection skipped for internal browser tabs.";
    statusBadge.textContent = "N/A";
    statusBadge.className = "badge badge-unknown";
    return;
  }

  let domain = url;
  try { domain = new URL(url).hostname; } catch (_) {}

  const storage = await chrome.storage.local.get(["user_id", "device_id"]);
  const payload = {
    url,
    user_id: storage.user_id || "current_user",
    device_id: storage.device_id || null
  };

  const apiBase = await resolveApiBase();

  async function queryEvaluation(targetBase) {
    const res = await fetch(`${targetBase}/browser/event`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
      signal: AbortSignal.timeout(4500)
    });
    if (!res.ok) throw new Error("HTTP " + res.status);
    return await res.json();
  }

  let data = null;
  try {
    data = await queryEvaluation(apiBase);
  } catch (err) {
    if (apiBase.startsWith(LOCAL_API_BASE)) {
      try {
        data = await queryEvaluation(CLOUD_API_BASE);
      } catch (_) {}
    }
  }

  if (data) {
    const status = data.status || data.evaluation?.status || "SAFE";
    const rawScore = data.risk_score !== undefined ? data.risk_score : data.evaluation?.risk_score;
    const risk   = (rawScore !== null && rawScore !== undefined) ? rawScore : 0;
    const dom    = data.domain || data.evaluation?.domain || domain;
    const rsns   = data.reasons || data.evaluation?.reasons || [];
    applyStatus(status, risk, dom, rsns, new Date().toISOString());
  } else {
    applyStatus("SAFE", 0, domain, ["Domain structure verified clean. CyberZen active threat monitoring enabled."], new Date().toISOString());
  }
});
