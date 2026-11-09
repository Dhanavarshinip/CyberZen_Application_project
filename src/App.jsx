import React, { useState, useEffect, useRef } from 'react';
import { AuthProvider, useAuth } from './context/AuthContext';
import { ThemeProvider, useTheme } from './context/ThemeContext';
import AuthLayout from './components/auth/AuthLayout';
import PublicWebsiteLayout from './components/public/PublicWebsiteLayout';
import FirstLaunchOnboardingModal from './components/onboarding/FirstLaunchOnboardingModal';
import StartupAnimation from './components/StartupAnimation';
import Navbar from './components/Navbar';
import HomeView from './components/HomeView';
import ActivityView from './components/ActivityView';
import IncidentsView from './components/IncidentsView';
import DevicesView from './components/DevicesView';
import SettingsView from './components/SettingsView';
import DownloadView from './components/public/DownloadView';
import { ErrorBoundary } from './components/ErrorBoundary';
import { apiClient } from './services/apiClient';

const PUBLIC_CLOUD_BACKEND = 'https://cyberzen.13.211.114.156.sslip.io/api';

const getDynamicApiBase = () => {
  if (import.meta.env.VITE_API_URL) return import.meta.env.VITE_API_URL;
  if (typeof window !== 'undefined') {
    const stored = localStorage.getItem('cyberthreat_api_base');
    if (stored && !stored.includes('127.0.0.1:8000') && !stored.includes('localhost:8000')) {
      return stored;
    }
    if (window.location.hostname === '13.211.114.156' || window.location.hostname.endsWith('sslip.io')) {
      return `${window.location.origin}/api`;
    }
  }
  return PUBLIC_CLOUD_BACKEND;
};

const API_BASE = {
  toString() {
    return (typeof apiClient !== 'undefined' && apiClient.getApiBase) ? apiClient.getApiBase() : getDynamicApiBase();
  },
  valueOf() {
    return (typeof apiClient !== 'undefined' && apiClient.getApiBase) ? apiClient.getApiBase() : getDynamicApiBase();
  }
};

function MainApp() {
  const { user } = useAuth();
  const { isDark } = useTheme();
  const [activeTab, setActiveTab] = useState(() => {
    try {
      const params = new URLSearchParams(window.location.search);
      const tabParam = params.get('tab');
      if (tabParam && ['home', 'activity', 'incidents', 'devices', 'settings', 'download'].includes(tabParam)) {
        return tabParam;
      }
    } catch (_) {}
    return 'home';
  });
  const [navHistory, setNavHistory] = useState(() => [activeTab || 'home']);

  // Synchronize when browser URL parameters change (e.g. from notification clicks)
  useEffect(() => {
    const handleLocationChange = () => {
      try {
        const params = new URLSearchParams(window.location.search);
        const tab = params.get('tab');
        if (tab && ['home', 'activity', 'incidents', 'devices', 'settings', 'download'].includes(tab)) {
          setActiveTab(tab);
          setNavHistory(prev => (prev[prev.length - 1] === tab ? prev : [...prev, tab]));
        }
      } catch (_) {}
    };
    handleLocationChange();
    window.addEventListener('popstate', handleLocationChange);
    return () => window.removeEventListener('popstate', handleLocationChange);
  }, []);
  const [events, setEvents] = useState([]);
  const [incidents, setIncidents] = useState([]);
  const [isOnline, setIsOnline] = useState(true);
  const [connectionStatus, setConnectionStatus] = useState('ONLINE');
  const [lastHeartbeat, setLastHeartbeat] = useState(null);
  const [pendingSyncCount, setPendingSyncCount] = useState(0);
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [activeWarning, setActiveWarning] = useState(null);
  const [selectedDeviceId, setSelectedDeviceId] = useState(null);
  const [devicesList, setDevicesList] = useState([]);
  const [monitorDeviceId, setMonitorDeviceId] = useState(null);
  const [pendingSynced, setPendingSynced] = useState(null);
  const [showPublicWebsite, setShowPublicWebsite] = useState(false);
  const [showOnboarding, setShowOnboarding] = useState(() => {
    // Only ask permissions when user newly registers; NEVER ask on normal sign-in
    return sessionStorage.getItem('cyberthreat_just_registered') === 'true';
  });
  const [isMonitoringActive, setIsMonitoringActive] = useState(true);
  const lastSeenEventIdRef = useRef(null);
  const dismissedEventIdsRef = useRef(new Set());
  const seenThreatEventIdsRef = useRef(new Set());
  const wasOfflineRef = useRef(false);
  const monitorDeviceIdRef = useRef(null);
  const selectedDeviceIdRef = useRef(null);
  const deviceIdFetchedRef = useRef(false);
  const [targetIncidentId, setTargetIncidentId] = useState(null);

  const [historyIndex, setHistoryIndex] = useState(0);

  // Smooth Tab Navigation tracking history (browser-like back / forward stack)
  const navigateToTab = (newTab, extraData = null) => {
    if (newTab === 'incidents' && extraData?.incidentId) {
      setTargetIncidentId(extraData.incidentId);
    }
    if (newTab === activeTab) return;
    setNavHistory(prev => {
      const sliced = prev.slice(0, historyIndex + 1);
      return [...sliced, newTab];
    });
    setHistoryIndex(prev => prev + 1);
    setActiveTab(newTab);
  };

  // Back Navigation handler
  const navigateBack = () => {
    if (showPublicWebsite) {
      setShowPublicWebsite(false);
      return;
    }
    if (showOnboarding) {
      setShowOnboarding(false);
      return;
    }
    if (targetIncidentId) {
      setTargetIncidentId(null);
      return;
    }
    if (historyIndex > 0) {
      const prevIdx = historyIndex - 1;
      setHistoryIndex(prevIdx);
      setActiveTab(navHistory[prevIdx] || 'home');
    } else if (activeTab !== 'home') {
      setActiveTab('home');
      setNavHistory(['home']);
      setHistoryIndex(0);
    }
  };

  // Forward Navigation handler
  const navigateForward = () => {
    if (historyIndex < navHistory.length - 1) {
      const nextIdx = historyIndex + 1;
      setHistoryIndex(nextIdx);
      setActiveTab(navHistory[nextIdx]);
    }
  };

  const canGoBack = historyIndex > 0 || activeTab !== 'home' || Boolean(targetIncidentId) || showPublicWebsite || showOnboarding;
  const canGoForward = historyIndex < navHistory.length - 1;

  // Keep refs in sync with state for use inside async callbacks
  useEffect(() => {
    monitorDeviceIdRef.current = monitorDeviceId;
  }, [monitorDeviceId]);

  useEffect(() => {
    selectedDeviceIdRef.current = selectedDeviceId;
  }, [selectedDeviceId]);

  // Send OS-level notification via the Web Notification API
  // In Electron this becomes a real Windows toast notification
  const sendNativeNotification = (title, body, isDanger) => {
    try {
      if (typeof Notification !== 'undefined' && Notification.permission === 'granted') {
        const n = new Notification(
          `${isDanger ? '🔴' : '🟠'} CyberThreat AI — ${title}`,
          {
            body,
            icon: '/favicon.ico',
            tag: 'cyberthreat-alert',
            requireInteraction: isDanger // Danger alerts persist until dismissed
          }
        );
        n.onclick = () => { try { window.focus(); } catch (e) {} };
      }
    } catch (e) {
      // Notification API unavailable in this context — in-app toast still shows
    }
  };

  // Request notification permission on mount
  useEffect(() => {
    if (typeof Notification !== 'undefined' && Notification.permission === 'default') {
      Notification.requestPermission();
    }
  }, []);

  // Fetch this client endpoint's persistent unique device_id
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
  };

  // Poll real backend data — strictly scoped to selected device_id
  const fetchData = async () => {
    setIsRefreshing(true);
    try {
      // Ensure we have a local device_id
      await fetchDeviceId();

      // Load registered user devices for dropdown switcher and validate ownership
      let currentTargetDeviceId = selectedDeviceIdRef.current;
      if (user?.id) {
        try {
          const devRes = await apiClient.getDevices(user.id);
          const userDevices = Array.isArray(devRes?.devices) ? devRes.devices : [];
          // Auto-enroll and pair current workstation if not already bound
          const myLocalDeviceId = monitorDeviceIdRef.current;
          const alreadyEnrolled = myLocalDeviceId && userDevices.some(d => d.device_id === myLocalDeviceId);
          if (myLocalDeviceId && !alreadyEnrolled) {
            try {
              await apiClient.registerDevice(myLocalDeviceId, user.id, 'My Workstation', navigator.userAgent || 'Windows Device');
              if (user.email) {
                await apiClient.pairExtension(user.email, myLocalDeviceId, user.id);
              }
              const refreshedDevRes = await apiClient.getDevices(user.id);
              userDevices = Array.isArray(refreshedDevRes?.devices) ? refreshedDevRes.devices : userDevices;
            } catch (_) {}
          }
          setDevicesList(userDevices);

          // Prioritize user's own enrolled devices, selecting the active hardware monitor device first
          const activeHwDev = myLocalDeviceId ? userDevices.find(d => d.device_id === myLocalDeviceId) : null;
          const userOwnsTarget = currentTargetDeviceId && userDevices.some(d => d.device_id === currentTargetDeviceId);
          if (!userOwnsTarget || (activeHwDev && currentTargetDeviceId !== myLocalDeviceId && (!selectedDeviceIdRef.current || selectedDeviceIdRef.current === 'DEV_619334F6B1FB'))) {
            currentTargetDeviceId = activeHwDev ? activeHwDev.device_id : (myLocalDeviceId || (userDevices.length > 0 ? userDevices[0].device_id : null));
            setSelectedDeviceId(currentTargetDeviceId);
            selectedDeviceIdRef.current = currentTargetDeviceId;
          }
        } catch { /* ignore */ }
      }

      // Check backend health and agent status
      const [health, monStatus] = await Promise.all([
        apiClient.getHealth(),
        apiClient.getMonitoringStatus()
      ]);

      if (!health) {
        setConnectionStatus('SERVER_UNAVAILABLE');
        setIsOnline(false);
        wasOfflineRef.current = true;
      } else {
        const nowTime = new Date().toLocaleTimeString();
        setLastHeartbeat(nowTime);

        const isAgentRunning = health.real_monitor === true || monStatus?.active === true;
        const isOnlineNet = health.online_mode !== false;

        if (!isAgentRunning) {
          setConnectionStatus('AGENT_DISCONNECTED');
          setIsOnline(false);
        } else if (!isOnlineNet) {
          setConnectionStatus('OFFLINE_MONITORING');
          setIsOnline(false);
          wasOfflineRef.current = true;
        } else {
          setConnectionStatus('ONLINE');
          setIsOnline(true);

          // Auto-sync: detect if we just came back online
          if (wasOfflineRef.current) {
            wasOfflineRef.current = false;
            try {
              const syncRes = await fetch(`${API_BASE}/connectivity/check`, { signal: AbortSignal.timeout(3000) });
              if (syncRes.ok) {
                const syncData = await syncRes.json();
                if (syncData.auto_synced && syncData.pending_synced > 0) {
                  setPendingSynced(syncData.pending_synced);
                  setTimeout(() => setPendingSynced(null), 8000);
                }
              }
            } catch { /* ignore */ }
          }
        }
      }

      // === STRICT DEVICE ISOLATION ===
      // Fetch events STRICTLY for the selected device only or the authenticated user.
      // Device A never sees Device B events, and Friend's Laptop never sees My Laptop events.
      let evUrl = `${API_BASE}/telemetry/events?limit=100&exclude_test=true`;
      if (currentTargetDeviceId) {
        evUrl += `&device_id=${encodeURIComponent(currentTargetDeviceId)}`;
      } else if (user?.id) {
        evUrl += `&user_id=${encodeURIComponent(user.id)}`;
      }

      let evData = null;
      try {
        const evRes = await fetch(evUrl, {
          headers: apiClient.getAuthHeaders(),
          signal: AbortSignal.timeout(4000)
        });
        if (evRes.ok) evData = await evRes.json();
      } catch { /* ignore — may be offline */ }

      // Fetch incidents for the authenticated user and/or selected device
      let incUrl = `${API_BASE}/incidents`;
      const incParams = new URLSearchParams();
      if (user?.id) {
        incParams.set('user_id', user.id);
      }
      if (currentTargetDeviceId) {
        incParams.set('device_id', currentTargetDeviceId);
      }
      const incQs = incParams.toString();
      if (incQs) incUrl += `?${incQs}`;
      let incData = null;
      try {
        const incRes = await fetch(incUrl, {
          headers: apiClient.getAuthHeaders(),
          signal: AbortSignal.timeout(4000)
        });
        if (incRes.ok) incData = await incRes.json();
      } catch { /* ignore */ }

      if (evData && Array.isArray(evData.events)) {
        setEvents(evData.events);
        const pending = evData.events.filter(e => e.sync_status === 'PENDING').length;
        setPendingSyncCount(pending);

        // Trigger real-time notifications for both online and offline activities on this host machine
        if (evData.events.length > 0) {
          const hostDevId = monitorDeviceIdRef.current;
          // Inspect the latest events (up to top 15) to ensure offline threats and background activities are reliably caught
          for (const ev of evData.events.slice(0, 15)) {
            // Only trigger notifications for this physical machine or if device is not strictly separated
            if (currentTargetDeviceId && hostDevId && ev.device_id && ev.device_id !== hostDevId && ev.device_id !== currentTargetDeviceId) {
              continue;
            }

            const isTestEvent = ev.features?.is_test_event;
            if (isTestEvent) continue;

            const isThreat =
              (ev.risk_score || 0) >= 40 ||
              ev.features?.status === 'DANGEROUS' ||
              ev.features?.status === 'SUSPICIOUS' ||
              ev.features?.is_eicar;

            const isDismissed = dismissedEventIdsRef.current.has(ev.event_id);
            const isAlreadySeen = seenThreatEventIdsRef.current.has(ev.event_id);

            if (isThreat && !isDismissed && !isAlreadySeen) {
              seenThreatEventIdsRef.current.add(ev.event_id);
              lastSeenEventIdRef.current = ev.event_id;

              const isOffline = ev.features?.activity_domain === 'OFFLINE' || ev.features?.connectivity_state === 'OFFLINE';
              const isDanger =
                (ev.risk_score || 0) >= 70 ||
                ev.features?.status === 'DANGEROUS' ||
                ev.features?.is_eicar;

              let warningTitle = isDanger ? 'Dangerous Threat Detected' : 'Suspicious Activity Detected';
              if (isOffline) {
                warningTitle = isDanger ? '🔴 Offline Security Threat Detected' : '🟠 Suspicious Offline Activity Detected';
              }

              const warningMsg =
                ev.features?.description ||
                `Security risk flagged on: ${ev.features?.display_name || ev.features?.domain || ev.features?.file_name || ev.features?.process_name || 'Host Process'}.`;

              // Show in-app toast
              setActiveWarning({ isDanger, isOffline, title: warningTitle, message: warningMsg, event: ev });

              // Also fire a real Windows/OS notification
              sendNativeNotification(warningTitle, warningMsg, isDanger);
              break; // Present the top active warning in the banner
            }
          }
        }
      } else {
        setEvents([]);
      }

      if (incData && Array.isArray(incData.incidents)) {
        setIncidents(incData.incidents);
      }
    } catch (err) {
      setIsOnline(false);
      wasOfflineRef.current = true;
    } finally {
      setIsRefreshing(false);
    }
  };

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 2500); // 2.5s responsive polling
    return () => clearInterval(interval);
  }, [user]);

  return (
    <div style={{
      minHeight: '100vh',
      background: isDark ? '#000000' : '#ffffff',
      color: isDark ? '#ffffff' : '#0f172a',
      display: 'flex',
      flexDirection: 'column',
      position: 'relative',
      fontFamily: 'Inter, system-ui, -apple-system, sans-serif',
      transition: 'background-color 0.25s ease, color 0.25s ease'
    }}>
      {/* Animatory Cyber Background */}
      <div className="cyber-bg" />
      {/* Navigation */}
      <Navbar
        activeTab={activeTab}
        setActiveTab={navigateToTab}
        canGoBack={canGoBack}
        canGoForward={canGoForward}
        onNavigateBack={navigateBack}
        onNavigateForward={navigateForward}
        isOnline={isOnline}
        connectionStatus={connectionStatus}
        lastHeartbeat={lastHeartbeat}
        pendingSyncCount={pendingSyncCount}
        devices={devicesList}
        selectedDeviceId={selectedDeviceId || monitorDeviceId}
        onSelectDevice={(id) => {
          setSelectedDeviceId(id);
          selectedDeviceIdRef.current = id;
          fetchData();
        }}
        currentHostDeviceId={monitorDeviceId}
        onOpenWebsite={() => setShowPublicWebsite(true)}
        onOpenOnboarding={() => setShowOnboarding(true)}
      />

      {/* Public Website Overlay if requested */}
      {showPublicWebsite && (
        <div style={{ position: 'fixed', inset: 0, zIndex: 150, overflowY: 'auto', background: '#090d16' }}>
          <div style={{
            background: 'rgba(0, 240, 255, 0.1)',
            borderBottom: '1px solid rgba(0, 240, 255, 0.3)',
            padding: '0.6rem 2rem',
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            fontSize: '0.85rem'
          }}>
            <span style={{ color: '#00f0ff', fontWeight: 600 }}>Viewing Public Website & Download Portal</span>
            <button
              onClick={() => setShowPublicWebsite(false)}
              style={{
                background: '#00f0ff',
                color: '#090d16',
                border: 'none',
                borderRadius: '6px',
                padding: '0.35rem 0.85rem',
                fontWeight: 700,
                fontSize: '0.8rem',
                cursor: 'pointer'
              }}
            >
              Return to Operations Center &rarr;
            </button>
          </div>
          <PublicWebsiteLayout initialPage="home" />
        </div>
      )}

      {/* First Launch Consent & Permissions Modal */}
      <FirstLaunchOnboardingModal
        isOpen={showOnboarding}
        onClose={() => {
          sessionStorage.removeItem('cyberthreat_just_registered');
          localStorage.setItem('cyberthreat_onboarding_completed', 'true');
          setShowOnboarding(false);
        }}
        isMonitoringActive={isMonitoringActive}
        user={user}
        monitorDeviceId={monitorDeviceId}
        onDeviceEnrolled={(dev) => {
          if (dev?.device_id) {
            setSelectedDeviceId(dev.device_id);
            selectedDeviceIdRef.current = dev.device_id;
            fetchData();
          }
        }}
        onToggleMonitoring={async (val) => {
          setIsMonitoringActive(val);
          try {
            await fetch(`${API_BASE}/monitoring/toggle`, {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ enabled: val })
            });
            fetchData();
          } catch (e) {}
        }}
      />

      {/* Real-Time Security Warning Toast */}
      {activeWarning && (
        <div style={{
          position: 'fixed',
          bottom: '24px',
          right: '24px',
          background: activeWarning.isDanger ? '#ef4444' : '#f59e0b',
          color: '#ffffff',
          borderRadius: '12px',
          padding: '1.25rem',
          boxShadow: activeWarning.isDanger
            ? '0 10px 30px rgba(239, 68, 68, 0.45)'
            : '0 10px 30px rgba(245, 158, 11, 0.45)',
          zIndex: 1000,
          maxWidth: '380px',
          display: 'flex',
          flexDirection: 'column',
          gap: '0.75rem',
          animation: 'slideUp 0.3s ease-out'
        }}>
          <div>
            <div style={{ fontSize: '1rem', fontWeight: 800, display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <span>{activeWarning.isDanger ? '🔴' : '🟠'}</span> {activeWarning.title}
              {activeWarning.isOffline && (
                <span style={{ fontSize: '0.68rem', background: 'rgba(0, 0, 0, 0.3)', padding: '2px 7px', borderRadius: '4px', marginLeft: 'auto', fontWeight: 700 }}>
                  OFFLINE
                </span>
              )}
            </div>
            <div style={{ fontSize: '0.85rem', marginTop: '0.35rem', lineHeight: 1.4, opacity: 0.95 }}>
              {activeWarning.message}
            </div>
          </div>
          <div style={{ display: 'flex', gap: '0.5rem' }}>
            <button
              onClick={() => { navigateToTab('incidents'); setActiveWarning(null); }}
              style={{
                flex: 1, padding: '0.55rem', borderRadius: '6px', border: 'none',
                background: '#ffffff', color: activeWarning.isDanger ? '#ef4444' : '#b45309',
                fontWeight: 700, fontSize: '0.82rem', cursor: 'pointer'
              }}
            >
              View Details
            </button>
            <button
              onClick={() => {
                if (activeWarning?.event?.event_id) {
                  dismissedEventIdsRef.current.add(activeWarning.event.event_id);
                }
                setActiveWarning(null);
              }}
              style={{
                padding: '0.55rem 0.85rem', borderRadius: '6px',
                border: '1px solid rgba(255, 255, 255, 0.4)', background: 'transparent',
                color: '#ffffff', fontWeight: 600, fontSize: '0.82rem', cursor: 'pointer'
              }}
            >
              Dismiss
            </button>
          </div>
        </div>
      )}

      {/* Active View */}
      <main style={{ flex: 1, overflowY: 'auto', position: 'relative', zIndex: 1 }}>
        <ErrorBoundary key={activeTab}>
          {activeTab === 'home' && (
            <HomeView
              events={events}
              incidents={incidents}
              isOnline={isOnline}
              connectionStatus={connectionStatus}
              lastHeartbeat={lastHeartbeat}
              onNavigateTab={navigateToTab}
              onRefresh={fetchData}
              deviceId={selectedDeviceId}
              devicesList={devicesList}
              user={user}
            />
          )}
          {activeTab === 'activity' && (
            <ActivityView
              events={events}
              onRefresh={fetchData}
              isRefreshing={isRefreshing}
              deviceId={selectedDeviceId}
              user={user}
              onNavigateTab={navigateToTab}
            />
          )}
          {activeTab === 'incidents' && (
            <IncidentsView
              incidents={incidents}
              events={events}
              onRefresh={fetchData}
              deviceId={selectedDeviceId}
              user={user}
              targetIncidentId={targetIncidentId}
              onNavigateTab={navigateToTab}
            />
          )}
          {activeTab === 'devices' && <DevicesView onDeviceRegistered={fetchData} />}
          {activeTab === 'settings' && <SettingsView />}
          {activeTab === 'download' && <DownloadView />}
        </ErrorBoundary>
      </main>

      <style>{`
        @keyframes slideUp {
          from { transform: translateY(20px); opacity: 0; }
          to { transform: translateY(0); opacity: 1; }
        }
      `}</style>
    </div>
  );
}

function isDesktopEnvironment() {
  if (typeof window === 'undefined') return false;
  if (window.cyberthreatDesktop?.isDesktop) return true;
  if (window.location.search.includes('app_mode=desktop')) return true;
  if (window.navigator?.userAgent?.toLowerCase().includes('electron')) return true;
  if (localStorage.getItem('cyberthreat_is_desktop') === 'true') return true;
  return false;
}

export default function App() {
  const [showStartup, setShowStartup] = useState(true);
  if (showStartup) {
    return <StartupAnimation onComplete={() => setShowStartup(false)} />;
  }
  return (
    <ThemeProvider>
      <AuthProvider>
        <AuthConsumer />
      </AuthProvider>
    </ThemeProvider>
  );
}

function AuthConsumer() {
  const { isAuthenticated } = useAuth();
  const isDesktop = isDesktopEnvironment();
  const [showWebsiteFallback, setShowWebsiteFallback] = useState(false);

  useEffect(() => {
    if (isDesktop) {
      localStorage.setItem('cyberthreat_is_desktop', 'true');
    }
  }, [isDesktop]);

  // Read URL parameters cleanly
  const params = typeof window !== 'undefined' ? new URLSearchParams(window.location.search) : null;
  const tabParam = params ? params.get('tab') : null;
  const pageParam = params ? params.get('page') : null;
  const pathname = typeof window !== 'undefined' ? window.location.pathname : '';

  // Dedicated public installation route detection only when explicitly requested
  const isExplicitDownload = pathname === '/download' || pathname.startsWith('/install') || tabParam === 'download' || pageParam === 'download';

  if (isExplicitDownload) {
    return (
      <PublicWebsiteLayout
        initialPage="download"
        onNavigateToApp={() => {
          window.location.href = '/';
        }}
      />
    );
  }

  // If user is authenticated, render the full MainApp (Dashboard, Activity, Incidents, etc.)
  if (isAuthenticated) {
    return <MainApp />;
  }

  // Inside Desktop Electron Shell: Guide directly to Create Account / Sign In
  if (isDesktop && !showWebsiteFallback) {
    return (
      <AuthLayout
        onOpenWebsite={() => setShowWebsiteFallback(true)}
        defaultMode="signup"
      />
    );
  }

  // In Web Browser: Render Public Website with initial page determined by user query or default to 'home'
  let initialWebPage = 'home';
  if (tabParam === 'login' || pageParam === 'login') {
    initialWebPage = 'login';
  } else if (tabParam === 'register' || tabParam === 'signup' || pageParam === 'register' || pageParam === 'signup') {
    initialWebPage = 'register';
  } else if (tabParam === 'features' || pageParam === 'features') {
    initialWebPage = 'features';
  }

  return (
    <PublicWebsiteLayout
      initialPage={initialWebPage}
      onNavigateToApp={() => setShowWebsiteFallback(false)}
    />
  );
}
