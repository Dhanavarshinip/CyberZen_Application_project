/**
 * CyberThreat AI - Automatic Real-Time Security Overlay Content Script (v3)
 * Injects an encapsulated Shadow-DOM security notification on every website visited.
 * Never requires clicking icons or manual triggers. Runs automatically on navigation.
 */

(function () {
  'use strict';

  // Prevent double-injection into the same window context
  if (window.__CYBERTHREAT_AI_INJECTED__) return;
  window.__CYBERTHREAT_AI_INJECTED__ = true;

  let hostElement = null;
  let shadowRoot = null;
  let currentOverlay = null;
  let currentVerdict = null;
  let autoDismissTimer = null;
  let lastCheckedUrl = null;
  let isCollapsed = false;
  const recentAlertTimes = new Map(); // Cooldown map to prevent popup glitch spamming

  const SVG_ICONS = {
    shield: `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>`,
    check: `<svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="#34d399" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>`,
    danger: `<svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="#ef4444" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>`,
    warning: `<svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="#fbbf24" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>`,
    unknown: `<svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="#94a3b8" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><path d="M9.09 9a3 3 0 0 1 5.83 1c0 2-3 3-3 3"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>`,
    spinner: `<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#38bdf8" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" class="ct-spin"><line x1="12" y1="2" x2="12" y2="6"/><line x1="12" y1="18" x2="12" y2="22"/><line x1="4.93" y1="4.93" x2="7.76" y2="7.76"/><line x1="16.24" y1="16.24" x2="19.07" y2="19.07"/><line x1="2" y1="12" x2="6" y2="12"/><line x1="18" y1="12" x2="22" y2="12"/><line x1="4.93" y1="19.07" x2="7.76" y2="16.24"/><line x1="16.24" y1="7.76" x2="19.07" y2="4.93"/></svg>`,
    close: `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>`
  };

  /**
   * Initializes or gets the Shadow DOM mount point.
   */
  function ensureMountPoint() {
    const targetParent = document.body || document.documentElement;
    if (hostElement && shadowRoot) {
      if (targetParent && (!document.contains(hostElement) || (document.body && hostElement.parentElement !== document.body))) {
        targetParent.appendChild(hostElement);
      }
      return shadowRoot;
    }

    hostElement = document.createElement('div');
    hostElement.id = 'cyberthreat-ai-security-overlay-root';
    hostElement.style.all = 'initial';
    hostElement.style.position = 'fixed';
    hostElement.style.top = '16px';
    hostElement.style.right = '16px';
    hostElement.style.zIndex = '2147483647';
    hostElement.style.pointerEvents = 'none';

    shadowRoot = hostElement.attachShadow({ mode: 'open' });

    // Inject base styles into Shadow DOM
    const style = document.createElement('style');
    style.textContent = `
      * { box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
      
      @keyframes ctSlideDown {
        0% { transform: translateY(-16px) scale(0.96); opacity: 0; }
        100% { transform: translateY(0) scale(1); opacity: 1; }
      }

      @keyframes ctPulseRed {
        0%, 100% { box-shadow: 0 8px 30px rgba(239, 68, 68, 0.4), 0 0 0 1px rgba(239, 68, 68, 0.6); }
        50% { box-shadow: 0 10px 40px rgba(239, 68, 68, 0.65), 0 0 0 2px rgba(239, 68, 68, 0.9); }
      }

      .ct-spin {
        animation: ctSpin 1s linear infinite;
      }
      @keyframes ctSpin {
        100% { transform: rotate(360deg); }
      }

      .ct-card {
        pointer-events: auto;
        width: 360px;
        max-width: calc(100vw - 32px);
        background: rgba(13, 19, 34, 0.96);
        backdrop-filter: blur(16px);
        -webkit-backdrop-filter: blur(16px);
        border-radius: 12px;
        box-shadow: 0 12px 35px rgba(0, 0, 0, 0.5);
        color: #f8fafc;
        border: 1px solid rgba(255, 255, 255, 0.12);
        animation: ctSlideDown 0.3s cubic-bezier(0.16, 1, 0.3, 1) forwards;
        overflow: hidden;
        transition: transform 0.25s ease, opacity 0.25s ease;
      }

      .ct-card.status-safe {
        border-color: rgba(16, 185, 129, 0.45);
        box-shadow: 0 10px 32px rgba(0, 0, 0, 0.45), 0 0 16px rgba(16, 185, 129, 0.2);
      }

      .ct-card.status-dangerous {
        border-color: #ef4444;
        animation: ctSlideDown 0.3s ease, ctPulseRed 2.5s infinite ease-in-out;
      }

      .ct-card.status-suspicious {
        border-color: rgba(245, 158, 11, 0.6);
        box-shadow: 0 10px 32px rgba(0, 0, 0, 0.45), 0 0 18px rgba(245, 158, 11, 0.25);
      }

      .ct-card.status-unknown {
        border-color: rgba(148, 163, 184, 0.35);
      }

      .ct-card.status-checking {
        border-color: rgba(56, 189, 248, 0.45);
        box-shadow: 0 10px 32px rgba(0, 0, 0, 0.45), 0 0 16px rgba(56, 189, 248, 0.2);
      }

      /* Header */
      .ct-header {
        display: flex;
        align-items: center;
        justify-content: space-between;
        padding: 10px 14px;
        background: rgba(255, 255, 255, 0.03);
        border-bottom: 1px solid rgba(255, 255, 255, 0.08);
      }

      .ct-brand {
        display: flex;
        align-items: center;
        gap: 6px;
        font-size: 11px;
        font-weight: 700;
        letter-spacing: 0.04em;
        text-transform: uppercase;
        color: #38bdf8;
      }

      .ct-close-btn {
        background: transparent;
        border: none;
        color: #94a3b8;
        cursor: pointer;
        padding: 4px;
        border-radius: 4px;
        display: flex;
        align-items: center;
        justify-content: center;
        transition: color 0.15s, background 0.15s;
      }
      .ct-close-btn:hover {
        color: #ffffff;
        background: rgba(255, 255, 255, 0.1);
      }

      /* Body */
      .ct-body {
        padding: 14px;
      }

      .ct-verdict-row {
        display: flex;
        align-items: center;
        gap: 12px;
        margin-bottom: 10px;
      }

      .ct-icon-box {
        width: 38px;
        height: 38px;
        border-radius: 10px;
        display: flex;
        align-items: center;
        justify-content: center;
        flex-shrink: 0;
      }

      .ct-icon-box.safe { background: rgba(16, 185, 129, 0.18); color: #34d399; }
      .ct-icon-box.dangerous { background: rgba(239, 68, 68, 0.22); color: #ef4444; }
      .ct-icon-box.suspicious { background: rgba(245, 158, 11, 0.2); color: #fbbf24; }
      .ct-icon-box.unknown { background: rgba(148, 163, 184, 0.15); color: #94a3b8; }
      .ct-icon-box.checking { background: rgba(56, 189, 248, 0.15); color: #38bdf8; }

      .ct-verdict-info {
        flex: 1;
        min-width: 0;
      }

      .ct-badge-title {
        font-size: 13px;
        font-weight: 800;
        letter-spacing: 0.02em;
        display: flex;
        align-items: center;
        gap: 6px;
      }

      .status-safe .ct-badge-title { color: #34d399; }
      .status-dangerous .ct-badge-title { color: #f87171; }
      .status-suspicious .ct-badge-title { color: #fbbf24; }
      .status-unknown .ct-badge-title { color: #cbd5e1; }
      .status-checking .ct-badge-title { color: #38bdf8; }

      .ct-hostname {
        font-size: 13px;
        font-weight: 700;
        color: #ffffff;
        margin-top: 2px;
        white-space: nowrap;
        overflow: hidden;
        text-overflow: ellipsis;
      }

      .ct-details {
        font-size: 11.5px;
        color: #94a3b8;
        line-height: 1.45;
        margin-top: 8px;
        padding-top: 8px;
        border-top: 1px solid rgba(255, 255, 255, 0.06);
      }

      .ct-risk-tag {
        display: inline-block;
        padding: 1px 6px;
        border-radius: 4px;
        font-size: 10px;
        font-weight: 700;
        margin-right: 6px;
      }
      .ct-risk-tag.safe { background: rgba(16, 185, 129, 0.2); color: #34d399; }
      .ct-risk-tag.dangerous { background: rgba(239, 68, 68, 0.25); color: #f87171; }
      .ct-risk-tag.suspicious { background: rgba(245, 158, 11, 0.2); color: #fbbf24; }
      .ct-risk-tag.unknown { background: rgba(148, 163, 184, 0.2); color: #cbd5e1; }

      /* Action Buttons */
      .ct-actions {
        display: flex;
        gap: 8px;
        margin-top: 12px;
      }

      .ct-btn {
        flex: 1;
        padding: 7px 12px;
        border-radius: 6px;
        font-size: 11.5px;
        font-weight: 700;
        cursor: pointer;
        border: none;
        text-align: center;
        transition: filter 0.15s, transform 0.1s;
      }
      .ct-btn:active { transform: scale(0.98); }

      .ct-btn-danger-back {
        background: #ef4444;
        color: #ffffff;
      }
      .ct-btn-danger-back:hover { filter: brightness(1.15); }

      .ct-btn-secondary {
        background: rgba(255, 255, 255, 0.09);
        color: #cbd5e1;
        border: 1px solid rgba(255, 255, 255, 0.15);
      }
      .ct-btn-secondary:hover { background: rgba(255, 255, 255, 0.16); color: #fff; }

      /* Minimized Floating Shield Badge */
      .ct-minimized-badge {
        pointer-events: auto;
        display: flex;
        align-items: center;
        gap: 6px;
        padding: 5px 10px;
        border-radius: 20px;
        background: rgba(13, 19, 34, 0.95);
        backdrop-filter: blur(10px);
        box-shadow: 0 4px 16px rgba(0,0,0,0.4);
        cursor: pointer;
        border: 1px solid rgba(255, 255, 255, 0.12);
        animation: ctSlideDown 0.2s ease;
        transition: transform 0.15s, box-shadow 0.15s;
      }
      .ct-minimized-badge:hover {
        transform: scale(1.05);
        box-shadow: 0 6px 20px rgba(0,0,0,0.6);
      }
      .ct-minimized-badge.safe { border-color: rgba(16, 185, 129, 0.5); color: #34d399; }
      .ct-minimized-badge.dangerous { border-color: #ef4444; color: #ef4444; }
      .ct-minimized-badge.suspicious { border-color: #f59e0b; color: #fbbf24; }
      .ct-minimized-badge.unknown { border-color: #64748b; color: #94a3b8; }
      .ct-min-text { font-size: 11px; font-weight: 700; }
    `;
    shadowRoot.appendChild(style);

    if (targetParent) {
      targetParent.appendChild(hostElement);
    }
    return shadowRoot;
  }

  /**
   * Displays the scanning/checking state card.
   */
  function showChecking(hostname) {
    clearTimeout(autoDismissTimer);
    const root = ensureMountPoint();

    // Clean previous content
    const existing = root.querySelector('.ct-container');
    if (existing) existing.remove();

    const container = document.createElement('div');
    container.className = 'ct-container';
    container.innerHTML = `
      <div class="ct-card status-checking">
        <div class="ct-header">
          <div class="ct-brand">
            ${SVG_ICONS.shield}
            <span>CyberThreat AI</span>
          </div>
          <button class="ct-close-btn" title="Dismiss">${SVG_ICONS.close}</button>
        </div>
        <div class="ct-body">
          <div class="ct-verdict-row">
            <div class="ct-icon-box checking">${SVG_ICONS.spinner}</div>
            <div class="ct-verdict-info">
              <div class="ct-badge-title">INSPECTING WEBSITE SECURITY…</div>
              <div class="ct-hostname">${escapeHtml(hostname || location.hostname)}</div>
            </div>
          </div>
          <div class="ct-details">
            Evaluating domain reputation, TLS indicators, and threat intelligence in real time…
          </div>
        </div>
      </div>
    `;

    container.querySelector('.ct-close-btn').addEventListener('click', () => {
      container.remove();
    });

    root.appendChild(container);
    currentOverlay = container;
  }

  /**
   * Displays the final verified verdict popup.
   * Suppresses intrusive in-page popups for SAFE / UNKNOWN sites (badge only in toolbar).
   * Only displays an in-page banner for confirmed high-risk threats, with a cooldown.
   */
  function showVerdict(verdict) {
    if (!verdict) return;
    clearTimeout(autoDismissTimer);
    currentVerdict = verdict;

    const status = (verdict.status || 'UNKNOWN').toUpperCase();
    const domain = verdict.domain || location.hostname || 'Website';

    // Show popup overlay for all domains (SAFE, SUSPICIOUS, DANGEROUS) with anti-glitch cooldown
    const alertKey = `${domain}:${status}`;
    const now = Date.now();
    const lastAlert = recentAlertTimes.get(alertKey) || 0;
    if (now - lastAlert < 15000) {
      // Cooldown to prevent duplicate re-render within 15 seconds on the same tab
      return;
    }
    recentAlertTimes.set(alertKey, now);

    const root = ensureMountPoint();
    const existing = root.querySelector('.ct-container');
    if (existing) existing.remove();
    const risk = verdict.risk_score;
    const reasons = verdict.reasons || [];
    const isPiracy = verdict.is_piracy_advisory || reasons.some(r => r.toLowerCase().includes('piracy') || r.toLowerCase().includes('torrent'));
    const reasonText = reasons[0] || (status === 'SAFE' ? 'Verified legitimate domain with clean reputation heuristics. No known threats detected.' : 'Security assessment completed.');

    let statusClass = 'status-safe';
    let iconBoxClass = 'safe';
    let iconHtml = SVG_ICONS.check;
    let badgeTitle = '✓ NO KNOWN THREAT';
    const displayRisk = (status === 'SAFE' || status === 'INFO') ? 0 : (risk !== null && risk !== undefined ? Math.round(risk) : 0);
    let riskTagHtml = `<span class="ct-risk-tag safe">Low Risk: ${displayRisk}/100</span>`;

    if (status === 'DANGEROUS') {
      statusClass = 'status-dangerous';
      iconBoxClass = 'dangerous';
      iconHtml = SVG_ICONS.danger;
      badgeTitle = '🚨 DANGEROUS WEBSITE DETECTED';
      riskTagHtml = `<span class="ct-risk-tag dangerous">Risk: ${risk !== null && risk !== undefined ? risk : 80}/100</span>`;
    } else if (status === 'SUSPICIOUS') {
      statusClass = 'status-suspicious';
      iconBoxClass = 'suspicious';
      iconHtml = SVG_ICONS.warning;
      badgeTitle = isPiracy ? '⚠ CONTENT POLICY ADVISORY — PIRACY' : '⚠ SUSPICIOUS WEBSITE';
      riskTagHtml = `<span class="ct-risk-tag suspicious">Risk: ${risk !== null && risk !== undefined ? risk : 45}/100</span>`;
    } else if (status === 'UNKNOWN') {
      statusClass = 'status-unknown';
      iconBoxClass = 'unknown';
      iconHtml = SVG_ICONS.unknown;
      badgeTitle = '⚪ UNVERIFIED WEBSITE — Proceed with caution';
      riskTagHtml = `<span class="ct-risk-tag unknown">Reputation: Unverified</span>`;
    }

    const container = document.createElement('div');
    container.className = 'ct-container';

    let actionButtonsHtml = '';
    if (status === 'DANGEROUS') {
      actionButtonsHtml = `
        <div class="ct-actions">
          <button class="ct-btn ct-btn-danger-back" id="ct-act-back">← Go Back (Recommended)</button>
          <button class="ct-btn ct-btn-secondary" id="ct-act-dismiss">Proceed Anyway</button>
        </div>
      `;
    } else if (status === 'SUSPICIOUS') {
      actionButtonsHtml = `
        <div class="ct-actions">
          <button class="ct-btn ct-btn-danger-back" id="ct-act-back" style="background:#d97706;">← Go Back</button>
          <button class="ct-btn ct-btn-secondary" id="ct-act-dismiss">Dismiss</button>
        </div>
      `;
    }

    container.innerHTML = `
      <div class="ct-card ${statusClass}">
        <div class="ct-header">
          <div class="ct-brand">
            ${SVG_ICONS.shield}
            <span>CyberZen Real-Time Protection</span>
          </div>
          <button class="ct-close-btn" id="ct-close-btn" title="Dismiss">${SVG_ICONS.close}</button>
        </div>
        <div class="ct-body">
          <div class="ct-verdict-row">
            <div class="ct-icon-box ${iconBoxClass}">${iconHtml}</div>
            <div class="ct-verdict-info">
              <div class="ct-badge-title">${badgeTitle}</div>
              <div class="ct-hostname">${escapeHtml(domain)}</div>
            </div>
          </div>
          <div class="ct-details">
            ${riskTagHtml}
            <span>${escapeHtml(reasonText)}</span>
          </div>
          ${actionButtonsHtml}
        </div>
      </div>
    `;

    // Event listeners
    const closeBtn = container.querySelector('#ct-close-btn');
    if (closeBtn) closeBtn.addEventListener('click', () => collapseToMiniBadge(status, domain));

    const backBtn = container.querySelector('#ct-act-back');
    if (backBtn) {
      backBtn.addEventListener('click', () => {
        if (window.history.length > 1) {
          window.history.back();
        } else {
          window.location.href = 'about:blank';
        }
      });
    }

    const dismissBtn = container.querySelector('#ct-act-dismiss');
    if (dismissBtn) {
      dismissBtn.addEventListener('click', () => {
        collapseToMiniBadge(status, domain);
      });
    }

    root.appendChild(container);
    currentOverlay = container;

    // For SAFE and UNKNOWN: gracefully collapse into small badge after 4.5 seconds
    if (status === 'SAFE' || status === 'UNKNOWN') {
      autoDismissTimer = setTimeout(() => {
        collapseToMiniBadge(status, domain);
      }, 5000);
    }
  }

  /**
   * Collapses the large card into an unobtrusive floating corner badge
   */
  function collapseToMiniBadge(status, domain) {
    const root = ensureMountPoint();
    const existing = root.querySelector('.ct-container');
    if (existing) existing.remove();

    const mini = document.createElement('div');
    mini.className = 'ct-container';
    const statusKey = (status || 'safe').toLowerCase();
    
    let label = 'SAFE';
    if (statusKey === 'dangerous') label = 'THREAT DETECTED';
    else if (statusKey === 'suspicious') label = 'SUSPICIOUS';
    else if (statusKey === 'unknown') label = 'UNKNOWN';

    mini.innerHTML = `
      <div class="ct-minimized-badge ${statusKey}" title="CyberZen — ${label}. Click to expand.">
        ${SVG_ICONS.shield}
        <span class="ct-min-text">${label}</span>
      </div>
    `;

    mini.querySelector('.ct-minimized-badge').addEventListener('click', () => {
      if (currentVerdict) {
        showVerdict(currentVerdict);
      }
    });

    root.appendChild(mini);
    currentOverlay = mini;
  }

  function escapeHtml(str) {
    if (!str) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }

  /**
   * Triggers threat evaluation for the current URL.
   */
  function triggerCheckForCurrentUrl() {
    const currentUrl = window.location.href;
    if (!currentUrl || currentUrl.startsWith('chrome:') || currentUrl.startsWith('about:')) return;

    // Deduplicate rapid repeat calls for identical URL
    if (lastCheckedUrl === currentUrl) return;
    lastCheckedUrl = currentUrl;

    const hostname = window.location.hostname || currentUrl;

    // Run silent evaluation without flashing an in-page checking popup
    // showChecking(hostname);

    // Request verdict from background service worker
    chrome.runtime.sendMessage(
      { action: 'ANALYZE_URL', url: currentUrl, title: document.title || '' },
      (response) => {
        if (chrome.runtime.lastError) {
          showVerdict({
            status: 'UNKNOWN',
            domain: hostname,
            risk_score: 0,
            reasons: ['Communication error: ' + chrome.runtime.lastError.message]
          });
          return;
        }

        if (response && response.status !== 'SKIPPED') {
          showVerdict(response);
        } else if (response && response.status === 'SKIPPED') {
          // Internal page or loop avoidance — remove overlay
          const root = ensureMountPoint();
          const existing = root.querySelector('.ct-container');
          if (existing) existing.remove();
        }
      }
    );
  }

  // 1. Listen for background-pushed verdicts (e.g. from webNavigation listener)
  chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
    if (msg.action === 'SECURITY_VERDICT' && msg.verdict) {
      showVerdict(msg.verdict);
      sendResponse({ received: true });
    }
  });

  // 2. Initial trigger when script executes: trigger immediately on navigation
  triggerCheckForCurrentUrl();

  // Also ensure mount element moves into document.body once DOM is parsed
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
      if (hostElement && document.body && hostElement.parentElement !== document.body) {
        document.body.appendChild(hostElement);
      }
    });
  }

  // 3. Support Single Page Applications (SPA): history.pushState, replaceState, popstate
  const origPushState = history.pushState;
  history.pushState = function () {
    origPushState.apply(this, arguments);
    setTimeout(triggerCheckForCurrentUrl, 50);
  };

  const origReplaceState = history.replaceState;
  history.replaceState = function () {
    origReplaceState.apply(this, arguments);
    setTimeout(triggerCheckForCurrentUrl, 50);
  };

  window.addEventListener('popstate', () => {
    setTimeout(triggerCheckForCurrentUrl, 50);
  });

  window.addEventListener('hashchange', () => {
    setTimeout(triggerCheckForCurrentUrl, 50);
  });

  // Support YouTube SPA video transitions
  document.addEventListener('yt-navigate-finish', () => {
    setTimeout(triggerCheckForCurrentUrl, 300);
  });

  // ==================== GMAIL THREAT PROTECTION MODULE ====================
  function initGmailProtection() {
    if (!window.location.hostname.includes('mail.google.com')) return;

    let lastInspectedSubject = '';
    let accountMismatchNotified = false;
    let detectedEmail = null;
    let isCurrentEmailAllowed = true;
    let allowedEmailsList = [];

    async function checkGmailSession() {
      // 1. Identify active Google account from DOM
      try {
        const accountBtn = document.querySelector('a[aria-label*="Google Account:"], a[aria-label*="(@"], [data-email]');
        if (accountBtn) {
          const label = accountBtn.getAttribute('aria-label') || accountBtn.getAttribute('data-email') || '';
          const match = label.match(/[\w.-]+@[\w.-]+\.\w+/);
          if (match) detectedEmail = match[0].toLowerCase();
        }
        if (!detectedEmail && document.title) {
          const match = document.title.match(/[\w.-]+@[\w.-]+\.\w+/);
          if (match) detectedEmail = match[0].toLowerCase();
        }
      } catch (_) {}

      // 2. Check pairing & allowed emails from storage, with dynamic backend auto-discovery fallback
      let storage = await chrome.storage.local.get(['user_email', 'user_id', 'device_id', 'allowed_emails']);
      let pairedEmail = (storage.user_email || '').trim().toLowerCase();
      let storedAllowed = Array.isArray(storage.allowed_emails) ? storage.allowed_emails.map(e => e.toLowerCase()) : [];

      allowedEmailsList = Array.from(new Set([pairedEmail, ...storedAllowed].filter(Boolean)));

      if (!pairedEmail || pairedEmail === 'unpaired@cyberthreat.local' || allowedEmailsList.length === 0) {
        try {
          const resp = await new Promise(resolve => {
            chrome.runtime.sendMessage({ action: 'GET_PAIRING' }, resolve);
          });
          if (resp && resp.pairing && resp.pairing.email && resp.pairing.email !== 'unpaired@cyberthreat.local') {
            pairedEmail = (resp.pairing.email || '').trim().toLowerCase();
            const backendAllowed = Array.isArray(resp.pairing.allowed_emails) ? resp.pairing.allowed_emails.map(e => e.toLowerCase()) : [];
            allowedEmailsList = Array.from(new Set([pairedEmail, ...backendAllowed].filter(Boolean)));
            await chrome.storage.local.set({
              user_email: pairedEmail,
              user_id: resp.pairing.user_id || 'current_user',
              device_id: resp.pairing.device_id || 'DEV-LOCAL',
              allowed_emails: allowedEmailsList
            });
          }
        } catch (_) {}
      }

      // 3. Enforce monitoring scope: Online activities on registered Gmail ONLY, not other unapproved mails
      if (detectedEmail && allowedEmailsList.length > 0) {
        isCurrentEmailAllowed = allowedEmailsList.includes(detectedEmail);
        if (!isCurrentEmailAllowed && !accountMismatchNotified) {
          accountMismatchNotified = true;
          console.warn(`[CyberThreat AI] Active Gmail account (${detectedEmail}) is not in registered or allowed monitored list. Online activity recording paused.`);
        } else if (isCurrentEmailAllowed) {
          accountMismatchNotified = false;
        }
      } else {
        isCurrentEmailAllowed = true;
      }
    }

    function showAccountMismatchBanner(detected, paired) {
      showVerdict({
        status: 'SUSPICIOUS',
        domain: 'mail.google.com',
        title: 'Gmail Account Mismatch Warning',
        risk_score: 45,
        reasons: [
          `Active Gmail account (${detected}) is not in your authorized CyberThreat AI monitored accounts list. Online monitoring is paused for this account.`
        ],
        is_mismatch: true
      });
    }

    function inspectActiveEmail() {
      // Strictly ignore and do NOT inspect emails if this mailbox is not registered or allowed by user
      if (detectedEmail && !isCurrentEmailAllowed) {
        return;
      }

      const emailContainer = document.querySelector('div[role="main"]');
      if (!emailContainer) return;

      // Extract subject
      const subjectEl = emailContainer.querySelector('h2.hP, div.ha h2');
      const subject = subjectEl ? subjectEl.textContent.trim() : '';

      // Extract sender
      const senderEl = emailContainer.querySelector('span.gD, span[email]');
      if (!senderEl) return;
      const senderEmail = (senderEl.getAttribute('email') || senderEl.textContent || '').trim();
      const senderName = senderEl.textContent.trim();

      if (!subject && !senderEmail) return;
      const emailKey = `${senderEmail}:${subject}`;
      if (emailKey === lastInspectedSubject) return;
      lastInspectedSubject = emailKey;

      // Analyze threat indicators
      const indicators = {
        sender: senderEmail,
        sender_name: senderName,
        subject_snippet: subject.substring(0, 80),
        suspicious_links: [],
        attachment_risk: []
      };

      let threatScore = 0;
      const reasons = [];

      // A. Sender domain spoofing checks
      const senderDomain = (senderEmail.split('@')[1] || '').toLowerCase();
      const brandKeywords = ['paypal', 'microsoft', 'google', 'apple', 'amazon', 'netflix', 'bank', 'wells fargo', 'chase', 'security', 'invoice'];
      const isClaimingBrand = brandKeywords.some(b => senderName.toLowerCase().includes(b) || subject.toLowerCase().includes(b));
      
      const freeProviders = ['gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'aol.com', 'protonmail.com'];
      if (isClaimingBrand && freeProviders.includes(senderDomain)) {
        threatScore += 65;
        reasons.push(`Brand Impersonation: Email claims to be "${senderName}" but was sent from a free email provider (${senderDomain}).`);
      }

      // Check lookalike/spoofed domains
      const spoofPatterns = [/paypa[l1]/i, /micros0ft/i, /goog[l1]e/i, /amaz0n/i, /app[l1]e-support/i];
      if (spoofPatterns.some(p => p.test(senderDomain))) {
        threatScore += 80;
        reasons.push(`Domain Spoofing / Typosquatting detected in sender domain (${senderDomain}).`);
      }

      // B. Link destination mismatch checks
      const bodyLinks = emailContainer.querySelectorAll('div.a3s a[href]');
      bodyLinks.forEach(link => {
        const href = (link.getAttribute('href') || '').trim();
        const text = link.textContent.trim();
        if (href.startsWith('http')) {
          try {
            const hrefUrl = new URL(href);
            if (text.startsWith('http://') || text.startsWith('https://') || text.includes('.com') || text.includes('.org')) {
              try {
                const textUrl = new URL(text.startsWith('http') ? text : `https://${text}`);
                if (textUrl.hostname.toLowerCase() !== hrefUrl.hostname.toLowerCase()) {
                  threatScore += 50;
                  indicators.suspicious_links.push({ text, href });
                  reasons.push(`Deceptive Link: Visible link text displays "${textUrl.hostname}" but navigates to "${hrefUrl.hostname}".`);
                }
              } catch (_) {}
            }
            if (/^https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(href)) {
              threatScore += 60;
              indicators.suspicious_links.push({ href });
              reasons.push(`Suspicious IP-based destination URL: ${href}`);
            }
          } catch (_) {}
        }
      });

      // C. Dangerous attachments check
      const attachments = emailContainer.querySelectorAll('div[role="listitem"] span[download_url], div.aZo');
      attachments.forEach(att => {
        const name = att.textContent.trim();
        const dangerousExts = ['.exe', '.scr', '.bat', '.cmd', '.vbs', '.js', '.hta', '.iso', '.pdf.exe', '.doc.exe'];
        if (dangerousExts.some(ext => name.toLowerCase().endsWith(ext))) {
          threatScore += 75;
          indicators.attachment_risk.push(name);
          reasons.push(`Dangerous Executable Attachment detected: "${name}".`);
        }
      });

      // D. Determine verdict
      let verdict = 'SAFE';
      if (threatScore >= 60) {
        verdict = 'DANGER';
      } else if (threatScore >= 30) {
        verdict = 'SUSPICIOUS';
      } else if (reasons.length === 0) {
        verdict = 'SAFE';
        reasons.push('Email verified — genuine sender domain, no deceptive links or executable attachments.');
      }

      // Show in-page verdict
      showVerdict({
        status: verdict,
        domain: 'mail.google.com',
        title: `Gmail: ${senderName || senderEmail}`,
        risk_score: threatScore > 0 ? threatScore : 5,
        reasons: reasons,
        is_gmail: true
      });

      // Report to backend with persistent 12-hour deduplication to prevent repeated duplicate incidents
      chrome.storage.local.get(['user_id', 'device_id', 'reported_gmail_events'], (storage) => {
        const reported = storage.reported_gmail_events || {};
        const now = Date.now();
        const TWELVE_HOURS = 12 * 60 * 60 * 1000;
        
        if (reported[emailKey] && (now - reported[emailKey] < TWELVE_HOURS)) {
          // Already reported recently, skip backend duplicate event
          return;
        }
        
        reported[emailKey] = now;
        // Clean up entries older than 24h
        for (const k in reported) {
          if (now - reported[k] > 24 * 60 * 60 * 1000) delete reported[k];
        }
        chrome.storage.local.set({ reported_gmail_events: reported });

        chrome.runtime.sendMessage({
          action: 'RECORD_EVENT',
          payload: {
            url: 'https://mail.google.com',
            title: `Gmail: ${subject.substring(0, 50)}`,
            user_id: storage.user_id || 'current_user',
            device_id: storage.device_id || null,
            active_mailbox: detectedEmail || null,
            browser_event_type: 'GMAIL_INSPECTION',
            email_threat_indicators: indicators,
            status: verdict,
            reasons: reasons
          }
        });
      });
    }

    setInterval(checkGmailSession, 3000);
    setInterval(inspectActiveEmail, 2000);
  }

  // Initialize Gmail protection
  initGmailProtection();

  // Auto-sync pairing if user is logged into CyberZen web console in this browser
  function checkWebConsoleSession() {
    try {
      const host = window.location.hostname;
      if (host.includes('13.211.114.156') || host.includes('sslip.io') || host === 'localhost' || host === '127.0.0.1') {
        const rawUser = localStorage.getItem('cyberthreat_user');
        const token = localStorage.getItem('cyberthreat_auth_token');
        const clientDeviceId = localStorage.getItem('cyberthreat_client_device_id') || localStorage.getItem('cyberthreat_device_id');
        if (rawUser) {
          const userObj = JSON.parse(rawUser);
          if (userObj && userObj.email) {
            chrome.runtime.sendMessage({
              action: 'SYNC_FROM_WEB_CONSOLE',
              payload: {
                email: userObj.email,
                user_id: userObj.id,
                token: token || '',
                device_id: clientDeviceId || null
              }
            }, () => {});
          }
        }
      }
    } catch (_) {}
  }
  checkWebConsoleSession();
  setInterval(checkWebConsoleSession, 15000);

})();

