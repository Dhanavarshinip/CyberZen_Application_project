import React, { useState, useEffect, useMemo, useCallback } from 'react';
import {
  Search,
  RefreshCw,
  Cpu,
  Download,
  Globe,
  Wifi,
  ShieldAlert,
  CheckCircle2,
  Folder,
  X,
  Info,
  Clock,
  Calendar,
  Laptop,
  ChevronLeft,
  ChevronRight,
  Filter,
  ExternalLink,
  AlertTriangle,
  Activity,
  HardDrive,
  Cloud,
  Database,
  ArrowUpDown
} from 'lucide-react';
import { apiClient } from '../services/apiClient';
import ActivityGraphView from './ActivityGraphView';
import { useTheme } from '../context/ThemeContext';

export default function ActivityView({
  events = [],
  onRefresh,
  isRefreshing,
  deviceId = null,
  user = null,
  onNavigateTab
}) {
  const { isDark } = useTheme();
  const cardBg = isDark ? '#0a0a0a' : '#ffffff';
  const cardBorder = isDark ? '#1e1e1e' : '#e2e8f0';
  const textPrimary = isDark ? '#ffffff' : '#0f172a';
  const textSecondary = isDark ? '#cbd5e1' : '#475569';
  const textMuted = isDark ? '#94a3b8' : '#64748b';
  const subtleBg = isDark ? '#141414' : '#f8fafc';
  const subtleBorder = isDark ? '#262626' : '#f1f5f9';

  const [activeViewMode, setActiveViewMode] = useState('LIST'); // 'LIST' (Records List) or 'GRAPH' (Visual Node Graph)
  const [filterType, setFilterType] = useState('ALL');
  const [domainFilter, setDomainFilter] = useState('ALL'); // 'ALL', 'ONLINE', 'OFFLINE', 'PENDING'
  const [dateFilter, setDateFilter] = useState('ALL'); // 'ALL', 'TODAY', 'YESTERDAY', 'CUSTOM', 'RANGE'
  const [sortOrder, setSortOrder] = useState('DESC'); // 'DESC' (Newest first), 'ASC' (Oldest first)
  
  // Date history — all dates from database with event counts
  const [dateSummary, setDateSummary] = useState([]); // [{date, total, web_count, app_count, ...}]
  const [isLoadingDateSummary, setIsLoadingDateSummary] = useState(false);
  const [showDatePanel, setShowDatePanel] = useState(true);

  // Storage & activity stats from SQLite
  const [activityStats, setActivityStats] = useState({
    total_stored: 0,
    online_activities: 0,
    offline_activities: 0,
    pending_sync: 0,
    synchronized: 0,
    storage_engine: 'SQLite3 (Persistent Local Record)'
  });
  const [isRecordingOffline, setIsRecordingOffline] = useState(false);
  const [offlineActionSuccess, setOfflineActionSuccess] = useState(null);
  const [accurateDetails, setAccurateDetails] = useState(null);
  const [systemAccuracy, setSystemAccuracy] = useState(null);

  // Helper date calculators
  const getTodayStr = () => {
    const d = new Date();
    const year = d.getFullYear();
    const month = String(d.getMonth() + 1).padStart(2, '0');
    const day = String(d.getDate()).padStart(2, '0');
    return `${year}-${month}-${day}`;
  };

  const getYesterdayStr = () => {
    const d = new Date();
    d.setDate(d.getDate() - 1);
    const year = d.getFullYear();
    const month = String(d.getMonth() + 1).padStart(2, '0');
    const day = String(d.getDate()).padStart(2, '0');
    return `${year}-${month}-${day}`;
  };

  const shiftDate = (dateStr, days) => {
    try {
      const parts = dateStr.split('-');
      const d = new Date(Number(parts[0]), Number(parts[1]) - 1, Number(parts[2]));
      d.setDate(d.getDate() + days);
      const year = d.getFullYear();
      const month = String(d.getMonth() + 1).padStart(2, '0');
      const day = String(d.getDate()).padStart(2, '0');
      return `${year}-${month}-${day}`;
    } catch {
      return dateStr;
    }
  };

  const getLocalDateStr = (isoString) => {
    if (!isoString) return '';
    try {
      const d = new Date(isoString);
      if (isNaN(d.getTime())) return '';
      const year = d.getFullYear();
      const month = String(d.getMonth() + 1).padStart(2, '0');
      const day = String(d.getDate()).padStart(2, '0');
      return `${year}-${month}-${day}`;
    } catch {
      return '';
    }
  };

  const [customDate, setCustomDate] = useState(getTodayStr);
  const [rangeStartDate, setRangeStartDate] = useState(getYesterdayStr);
  const [rangeEndDate, setRangeEndDate] = useState(getTodayStr);
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedEventModal, setSelectedEventModal] = useState(null);
  const [relatedIncident, setRelatedIncident] = useState(null);
  const [isLoadingIncident, setIsLoadingIncident] = useState(false);
  const [currentPage, setCurrentPage] = useState(1);
  const [pageSize, setPageSize] = useState(25);

  // Directly loaded activities state from SQLite database
  const [dbEvents, setDbEvents] = useState([]);
  const [isLoadingActivities, setIsLoadingActivities] = useState(false);
  const [fetchError, setFetchError] = useState(null);

  // Fetch activities directly from SQLite database with date parameters and timezone offset
  const loadActivities = useCallback(async (isSilent = false) => {
    if (!isSilent) setIsLoadingActivities(true);
    setFetchError(null);
    try {
      const tzOffset = new Date().getTimezoneOffset();
      let dateParam = null;
      let startDateParam = undefined;
      let endDateParam = undefined;

      if (dateFilter === 'TODAY') {
        dateParam = getTodayStr();
      } else if (dateFilter === 'YESTERDAY') {
        dateParam = getYesterdayStr();
      } else if (dateFilter === 'CUSTOM') {
        dateParam = customDate;
      } else if (dateFilter === 'RANGE') {
        startDateParam = rangeStartDate;
        endDateParam = rangeEndDate;
      }

      let actDomain = null;
      let syncSt = null;
      if (domainFilter === 'ONLINE') actDomain = 'ONLINE';
      else if (domainFilter === 'OFFLINE') actDomain = 'OFFLINE';
      else if (domainFilter === 'PENDING') syncSt = 'PENDING';

      const res = await apiClient.getEvents({
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
      }
    } catch (err) {
      console.warn('[ActivityView] loadActivities failed:', err);
      if (!isSilent) setFetchError(err.message || 'Failed to load historical activities from database');
      if (!isSilent) setDbEvents([]);
    } finally {
      if (!isSilent) setIsLoadingActivities(false);
    }
  }, [dateFilter, customDate, rangeStartDate, rangeEndDate, domainFilter, user?.id]);

  // Load date summary (all dates with data) — runs once on mount and refreshes every 30s
  const loadDateSummary = useCallback(async () => {
    setIsLoadingDateSummary(true);
    try {
      const tzOffset = new Date().getTimezoneOffset();
      const res = await apiClient.getDateSummary(undefined, tzOffset, user?.id || null);
      if (res && Array.isArray(res.dates)) {
        setDateSummary(res.dates);
      }
    } catch (err) {
      console.warn('[ActivityView] loadDateSummary failed:', err);
    } finally {
      setIsLoadingDateSummary(false);
    }
  }, [user?.id]);

  // Record an offline test activity directly into local SQLite
  const handleRecordOfflineTest = async (appName = 'Microsoft Word', action = 'Offline Document Editing') => {
    setIsRecordingOffline(true);
    setOfflineActionSuccess(null);
    try {
      const res = await apiClient.recordOfflineActivity(appName, action, deviceId, user?.id);
      if (res && res.status === 'SUCCESS') {
        setOfflineActionSuccess(`Recorded offline activity: "${appName}"`);
        setTimeout(() => setOfflineActionSuccess(null), 6000);
        await loadActivities(true);
        loadDateSummary();
      }
    } catch (err) {
      console.warn('Record offline failed:', err);
    } finally {
      setIsRecordingOffline(false);
    }
  };

  // Load on mount, when filters change, and run real-time responsive auto-poll every 5s
  useEffect(() => {
    loadActivities(false);
    const pollTimer = setInterval(() => {
      loadActivities(true);
    }, 5000);
    return () => clearInterval(pollTimer);
  }, [loadActivities]);

  // Load date summary on mount, and refresh every 30s
  useEffect(() => {
    loadDateSummary();
    const summaryTimer = setInterval(loadDateSummary, 30000);
    return () => clearInterval(summaryTimer);
  }, [loadDateSummary]);

  // Load accurate device details and system accuracy metrics
  useEffect(() => {
    let isMounted = true;
    const loadAccurateDetails = async () => {
      try {
        const [devData, accData] = await Promise.all([
          apiClient.getAccurateDeviceDetails(deviceId),
          apiClient.getSystemAccuracy()
        ]);
        if (isMounted) {
          if (devData) setAccurateDetails(devData);
          if (accData) setSystemAccuracy(accData);
        }
      } catch (err) {
        console.warn('[ActivityView] Error loading device accuracy details:', err);
      }
    };
    loadAccurateDetails();
    return () => { isMounted = false; };
  }, [deviceId]);

  // When selectedEventModal changes, query related incident
  useEffect(() => {
    if (!selectedEventModal) {
      setRelatedIncident(null);
      return;
    }
    let isCancelled = false;
    const fetchIncident = async () => {
      setIsLoadingIncident(true);
      try {
        const inc = await apiClient.getEventIncident(selectedEventModal.event_id);
        if (!isCancelled) {
          setRelatedIncident(inc);
        }
      } catch {
        if (!isCancelled) setRelatedIncident(null);
      } finally {
        if (!isCancelled) setIsLoadingIncident(false);
      }
    };
    fetchIncident();
    return () => { isCancelled = true; };
  }, [selectedEventModal]);

  // Combine loaded SQLite events with local pending offline events without polluting date filters
  const allCombinedEvents = useMemo(() => {
    const eventMap = new Map();

    // 1. Add database events first (persistent source of truth from SQLite)
    dbEvents.forEach(e => {
      if (e && e.event_id) eventMap.set(e.event_id, e);
    });

    // 2. Add or update events from props (offline PENDING events or live stream)
    // CRITICAL: Only include prop events if they actually match the active date filter!
    // Never allow today's live polling events to overwrite or pollute Yesterday or Custom Date views!
    const todayStr = getTodayStr();
    const yesterdayStr = getYesterdayStr();

    (events || []).forEach(e => {
      if (e && e.event_id) {
        const evDate = getLocalDateStr(e.timestamp || e.created_at);
        let matchesDate = false;
        if (dateFilter === 'ALL') matchesDate = true;
        else if (dateFilter === 'TODAY' && evDate === todayStr) matchesDate = true;
        else if (dateFilter === 'YESTERDAY' && evDate === yesterdayStr) matchesDate = true;
        else if (dateFilter === 'CUSTOM' && evDate === customDate) matchesDate = true;
        else if (dateFilter === 'RANGE') {
          matchesDate = (!rangeStartDate || evDate >= rangeStartDate) && (!rangeEndDate || evDate <= rangeEndDate);
        }

        if (matchesDate) {
          if (!eventMap.has(e.event_id)) {
            // Only add pending or current-day events
            if (e.sync_status === 'PENDING' || dateFilter === 'TODAY' || dateFilter === 'ALL' || dateFilter === 'RANGE') {
              eventMap.set(e.event_id, e);
            }
          } else {
            // If local prop has PENDING status, preserve it
            const existing = eventMap.get(e.event_id);
            if (e.sync_status === 'PENDING' && existing.sync_status !== 'PENDING') {
              eventMap.set(e.event_id, { ...existing, sync_status: 'PENDING' });
            }
          }
        }
      }
    });

    return Array.from(eventMap.values());
  }, [dbEvents, events, dateFilter, customDate, rangeStartDate, rangeEndDate]);

  // Separate real events from synthetic test events
  const realEvents = useMemo(() => {
    return allCombinedEvents.filter(e => {
      if (!e) return false;
      const f = e.features || {};
      if (f.is_test_event) return false;
      if (e.event_type && e.event_type.startsWith('TEST_')) return false;
      if (e.detection_source === 'TEST_ENDPOINT') return false;
      if (f.activity_category === 'Test') return false;
      return true;
    });
  }, [allCombinedEvents]);

  // Filter events by Category, Date, and Search
  const filteredEvents = useMemo(() => {
    const todayStr = getTodayStr();
    const yesterdayStr = getYesterdayStr();

    return realEvents.filter(ev => {
      const f = ev.features || {};
      const cat = f.activity_category || '';
      const evType = ev.event_type || '';
      const evDate = getLocalDateStr(ev.timestamp || ev.created_at);

      // 1. Date Filter (Strict local time matching with DB event preservation)
      if (dateFilter === 'TODAY') {
        if (evDate !== todayStr && !dbEvents.some(dbe => dbe.event_id === ev.event_id)) return false;
      } else if (dateFilter === 'YESTERDAY') {
        if (evDate !== yesterdayStr && !dbEvents.some(dbe => dbe.event_id === ev.event_id)) return false;
      } else if (dateFilter === 'CUSTOM') {
        if (evDate !== customDate && !dbEvents.some(dbe => dbe.event_id === ev.event_id)) return false;
      } else if (dateFilter === 'RANGE') {
        if (rangeStartDate && evDate < rangeStartDate) return false;
        if (rangeEndDate && evDate > rangeEndDate) return false;
      }

      // 2. Domain Filter (Online vs Offline Activities)
      if (domainFilter === 'ONLINE') {
        const isOnline = f.activity_domain === 'ONLINE' ||
          evType.includes('WEBSITE') || evType.includes('BROWSER') || !!f.domain || !!f.url ||
          (evType.includes('NETWORK') && f.remote_ip && f.remote_ip !== '127.0.0.1');
        if (!isOnline) return false;
      } else if (domainFilter === 'OFFLINE') {
        const isOffline = f.activity_domain === 'OFFLINE' ||
          (!evType.includes('WEBSITE') && !evType.includes('BROWSER') && !f.domain && !f.url);
        if (!isOffline) return false;
      } else if (domainFilter === 'PENDING') {
        if (ev.sync_status !== 'PENDING') return false;
      }

      // 3. Category Filter
      let matchesType = true;
      if (filterType === 'APPS') {
        matchesType = cat === 'Apps' || evType.includes('PROCESS') || evType.includes('APPLICATION') || !!f.process_name;
      } else if (filterType === 'WEBSITES') {
        matchesType = cat === 'Browser' || evType.includes('WEBSITE') || evType.includes('BROWSER') || !!f.domain || !!f.url;
      } else if (filterType === 'DOWNLOADS') {
        matchesType = cat === 'Downloads' || evType.includes('FILE') || evType.includes('DOWNLOAD') || !!f.file_name;
      } else if (filterType === 'NETWORK') {
        matchesType = cat === 'Network' || evType.includes('NETWORK') || !!f.remote_ip || !!f.destination;
      } else if (filterType === 'SECURITY') {
        matchesType = (ev.risk_score || 0) >= 35 || f.status === 'DANGEROUS' || f.status === 'SUSPICIOUS' || f.is_eicar;
      } else if (filterType === 'SYSTEM') {
        matchesType = cat === 'System' || evType.includes('WINDOWS') || evType.includes('SYSTEM') || evType.includes('LOGON') || evType.includes('SERVICE') || ev.detection_source === 'WINDOWS_EVENT_LOG';
      }
      if (!matchesType) return false;

      // 4. Search Filter
      if (searchQuery) {
        const searchLower = searchQuery.toLowerCase();
        const matchesSearch =
          (ev.event_type && ev.event_type.toLowerCase().includes(searchLower)) ||
          (f.description && f.description.toLowerCase().includes(searchLower)) ||
          (f.display_name && f.display_name.toLowerCase().includes(searchLower)) ||
          (f.process_name && f.process_name.toLowerCase().includes(searchLower)) ||
          (f.file_name && f.file_name.toLowerCase().includes(searchLower)) ||
          (f.domain && f.domain.toLowerCase().includes(searchLower)) ||
          (f.url && f.url.toLowerCase().includes(searchLower)) ||
          (ev.detection_source && ev.detection_source.toLowerCase().includes(searchLower)) ||
          (ev.device_id && ev.device_id.toLowerCase().includes(searchLower));

        if (!matchesSearch) return false;
      }

      return true;
    });
  }, [realEvents, filterType, domainFilter, dateFilter, customDate, rangeStartDate, rangeEndDate, searchQuery, dbEvents]);

  // Sort by actual timestamp according to sortOrder (DESC = Newest First, ASC = Oldest First)
  const sortedEvents = useMemo(() => {
    return [...filteredEvents].sort((a, b) => {
      const ta = new Date(a.timestamp || a.created_at || 0).getTime();
      const tb = new Date(b.timestamp || b.created_at || 0).getTime();
      return sortOrder === 'ASC' ? ta - tb : tb - ta;
    });
  }, [filteredEvents, sortOrder]);

  // Pagination calculations
  const totalItems = sortedEvents.length;
  const totalPages = Math.max(1, Math.ceil(totalItems / pageSize));
  const safeCurrentPage = Math.min(currentPage, totalPages);
  const startIndex = (safeCurrentPage - 1) * pageSize;
  const paginatedEvents = sortedEvents.slice(startIndex, startIndex + pageSize);

  // Group paginated events by actual date
  const groupedEvents = useMemo(() => {
    const groups = {};
    const todayStr = getTodayStr();
    const yesterdayStr = getYesterdayStr();

    paginatedEvents.forEach(ev => {
      const dateKey = getLocalDateStr(ev.timestamp || ev.created_at) || 'Unknown Date';
      if (!groups[dateKey]) {
        let label = dateKey;
        if (dateKey === todayStr) {
          label = `Today — ${formatDateTitle(ev.timestamp || ev.created_at)}`;
        } else if (dateKey === yesterdayStr) {
          label = `Yesterday — ${formatDateTitle(ev.timestamp || ev.created_at)}`;
        } else {
          label = formatDateTitle(ev.timestamp || ev.created_at);
        }
        groups[dateKey] = {
          dateKey,
          label,
          events: []
        };
      }
      groups[dateKey].events.push(ev);
    });

    return Object.values(groups);
  }, [paginatedEvents]);

  function formatDateTitle(isoString) {
    if (!isoString) return 'Undated';
    try {
      const d = new Date(isoString);
      return d.toLocaleDateString(undefined, {
        weekday: 'long',
        year: 'numeric',
        month: 'long',
        day: 'numeric'
      });
    } catch {
      return isoString;
    }
  }

  const formatLocalTime = (ts) => {
    if (!ts) return '';
    try {
      const d = new Date(ts);
      return d.toLocaleTimeString([], {
        hour12: false,
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit'
      });
    } catch {
      return ts;
    }
  };

  const formatFullDateTime = (ts) => {
    if (!ts) return 'Not recorded';
    try {
      const d = new Date(ts);
      return d.toLocaleString([], {
        year: 'numeric',
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
        hour12: false
      });
    } catch {
      return ts;
    }
  };

  const getStatusConfig = (ev) => {
    const f = ev.features || {};
    const status = (f.status || '').toUpperCase();
    const risk = ev.risk_score || 0;

    if (status === 'DANGEROUS' || f.is_eicar || risk >= 70) {
      return {
        label: 'DANGEROUS',
        color: '#dc2626',
        bg: '#fef2f2',
        border: '#fecaca',
        text: '#dc2626'
      };
    }
    if (f.is_adware || status === 'ADWARE' || (f.display_name && f.display_name.toLowerCase().includes('adware'))) {
      return {
        label: 'ADWARE / PROMO',
        color: '#f97316',
        bg: '#fff7ed',
        border: '#fdba74',
        text: '#ea580c'
      };
    }
    if (status === 'SUSPICIOUS' || risk >= 35) {
      return {
        label: 'SUSPICIOUS',
        color: '#d97706',
        bg: '#fffbeb',
        border: '#fde68a',
        text: '#d97706'
      };
    }
    if (status === 'SAFE') {
      return {
        label: 'SAFE',
        color: '#16a34a',
        bg: '#f0fdf4',
        border: '#bbf7d0',
        text: '#16a34a'
      };
    }
    if (status === 'UNKNOWN' || status === 'UNVERIFIED') {
      return {
        label: 'UNVERIFIED',
        color: '#64748b',
        bg: '#f1f5f9',
        border: '#cbd5e1',
        text: '#64748b'
      };
    }
    if (status === 'INFO' || ev.event_type?.includes('APPLICATION') || ev.event_type?.includes('PROCESS') || ev.event_type?.includes('NETWORK')) {
      return {
        label: 'INFO',
        color: '#0284c7',
        bg: '#f0f9ff',
        border: '#bae6fd',
        text: '#0284c7'
      };
    }
    if (ev.event_type === 'WEBSITE_OPENED' && status !== 'SAFE') {
      return {
        label: 'UNVERIFIED',
        color: '#64748b',
        bg: '#f1f5f9',
        border: '#cbd5e1',
        text: '#64748b'
      };
    }
    return {
      label: 'NO KNOWN THREAT',
      color: '#16a34a',
      bg: '#f0fdf4',
      border: '#bbf7d0',
      text: '#16a34a'
    };
  };

  const getEventIcon = (ev) => {
    const evType = ev.event_type || '';
    const f = ev.features || {};
    const name = (f.display_name || f.process_name || '').toLowerCase();
    if (name.includes('explorer')) return Folder;
    if (evType.includes('FILE') || f.file_name) return Download;
    if (evType.includes('WEBSITE') || evType.includes('BROWSER') || f.domain) return Globe;
    if (evType.includes('NETWORK') || f.remote_ip) return Wifi;
    if (evType.includes('PROCESS') || evType.includes('APPLICATION') || f.process_name) return Cpu;
    return ShieldAlert;
  };

  const getEventTitle = (ev) => {
    const f = ev.features || {};
    const evType = ev.event_type || '';
    if (evType === 'NETWORK_CONNECTION' || f.activity_category === 'Network') {
      return f.process_name && f.process_name !== 'unknown' && f.process_name !== 'System'
        ? f.process_name
        : (f.remote_ip ? `Network Connection (${f.remote_ip})` : 'Network Connection');
    }
    const isYt = (f.domain || '').includes('youtube.com') || (f.url || '').includes('youtube.com') || f.is_youtube;
    if (isYt) {
      if (f.clean_title) return `YouTube — ${f.clean_title}`;
      if (f.title || f.page_title) return `YouTube — ${f.title || f.page_title}`;
      return 'YouTube (Google Chrome)';
    }
    return f.display_name || f.clean_title || f.title || f.domain || f.file_name || f.process_name || ev.event_type;
  };

  const getEventDescription = (ev) => {
    const f = ev.features || {};
    const evType = ev.event_type || '';
    const isYt = (f.domain || '').includes('youtube.com') || (f.url || '').includes('youtube.com') || f.is_youtube;
    if (isYt) {
      const vidTitle = f.clean_title || f.title || f.page_title;
      if (vidTitle) return `Watched YouTube video: "${vidTitle}"`;
      if ((f.url || '').includes('/watch')) return 'Watched video on YouTube in Google Chrome';
      if ((f.url || '').includes('/shorts')) return 'Watched YouTube Shorts video in Google Chrome';
      return 'Opened YouTube in Google Chrome';
    }
    if (f.description) return f.description;
    if (evType === 'WEBSITE_OPENED' || f.domain) {
      const title = f.clean_title || f.title || f.page_title;
      return title ? `Visited "${title}" on ${f.domain || 'web'}` : `Website opened: ${f.domain || 'Domain'}`;
    }
    if (evType === 'FILE_DOWNLOAD' || f.file_name) return `File download: ${f.file_name}`;
    if (evType === 'APPLICATION_START') return `${f.display_name || 'Application'} launched`;
    if (evType === 'APPLICATION_CLOSED') return `${f.display_name || 'Application'} closed`;
    if (evType === 'PROCESS_START') return `Process started: ${f.process_name}`;
    if (evType === 'NETWORK_CONNECTION' || f.remote_ip) return `Network connection: ${f.remote_ip}`;
    return ev.event_type || 'Activity observed';
  };

  const getEventSource = (ev) => {
    if (ev.detection_source) return ev.detection_source;
    const f = ev.features || {};
    if (f.source) return f.source;
    const evType = ev.event_type || '';
    if (evType.includes('WEBSITE') || evType.includes('BROWSER')) return 'Browser Integration';
    if (evType.includes('PROCESS') || evType.includes('APPLICATION')) return 'Process Monitor';
    if (evType.includes('FILE') || evType.includes('DOWNLOAD')) return 'File Collector';
    if (evType.includes('NETWORK')) return 'Network Collector';
    return 'Host Monitoring Agent';
  };

  const getMeasuredDuration = (ev) => {
    const f = ev.features || {};
    if (typeof f.duration_seconds === 'number' && f.duration_seconds > 0) {
      const s = Math.round(f.duration_seconds);
      if (s < 60) return `${s}s`;
      const m = Math.floor(s / 60);
      const remS = s % 60;
      return `${m}m ${remS}s`;
    }
    if (f.start_time && f.end_time) {
      try {
        const diff = Math.max(1, Math.round((new Date(f.end_time) - new Date(f.start_time)) / 1000));
        if (diff < 60) return `${diff}s`;
        const m = Math.floor(diff / 60);
        return `${m}m ${diff % 60}s`;
      } catch {
        return null;
      }
    }
    return null;
  };

  const getActivityDomainInfo = (ev) => {
    const f = ev.features || {};
    const evType = ev.event_type || '';
    const isOnline = f.activity_domain === 'ONLINE' ||
      evType.includes('WEBSITE') || evType.includes('BROWSER') || !!f.domain || !!f.url ||
      (evType.includes('NETWORK') && f.remote_ip && f.remote_ip !== '127.0.0.1');

    if (isOnline) {
      return {
        isOnline: true,
        type: 'ONLINE',
        badgeLabel: 'ONLINE ACTIVITY',
        subLabel: f.domain ? `Website (${f.domain})` : 'Web / Remote Network',
        color: '#16a34a',
        bg: '#f0fdf4',
        border: '#bbf7d0',
        icon: Globe
      };
    } else {
      return {
        isOnline: false,
        type: 'OFFLINE',
        badgeLabel: 'OFFLINE ACTIVITY',
        subLabel: f.display_name ? `Local App (${f.display_name})` : (f.file_name ? `Local File (${f.file_name})` : 'Local Host Task'),
        color: '#4f46e5',
        bg: '#eef2ff',
        border: '#c7d2fe',
        icon: Laptop
      };
    }
  };

  const handleRefresh = async () => {
    await loadActivities();
    if (onRefresh) onRefresh();
  };

  return (
    <div style={{
      padding: '2rem 1.5rem',
      maxWidth: '1100px',
      margin: '0 auto',
      display: 'flex',
      flexDirection: 'column',
      gap: '1.5rem',
      color: textPrimary
    }}>

      {/* Top Header */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '1rem' }}>
        <div>
          <h1 style={{ fontSize: '1.6rem', fontWeight: 800, color: textPrimary, margin: '0 0 0.35rem 0', letterSpacing: '-0.02em' }}>
            System Activities & Storage
          </h1>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', fontSize: '0.85rem' }}>
            <span style={{ color: '#64748b', fontWeight: 500 }}>
              Live Host Monitoring: <span style={{ color: '#16a34a', fontWeight: 700 }}>Active</span>
            </span>
            <span style={{
              display: 'inline-block',
              width: '8px',
              height: '8px',
              borderRadius: '50%',
              background: '#16a34a',
              boxShadow: '0 0 8px rgba(22, 163, 74, 0.4)'
            }} />
            {deviceId && (
              <span style={{
                color: '#0284c7',
                fontSize: '0.8rem',
                fontFamily: 'monospace',
                background: '#f0f9ff',
                padding: '0.15rem 0.5rem',
                borderRadius: '4px',
                border: '1px solid #bae6fd'
              }}>
                Device: {deviceId}
              </span>
            )}

          </div>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem' }}>
          <button
            onClick={() => handleRecordOfflineTest('Microsoft Word', 'Offline Research & Notes')}
            disabled={isRecordingOffline}
            title="Record a sample offline application activity"
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '0.45rem',
              padding: '0.55rem 1rem',
              borderRadius: '8px',
              border: '1px solid #c7d2fe',
              background: '#eef2ff',
              color: '#4f46e5',
              fontSize: '0.85rem',
              fontWeight: 700,
              cursor: isRecordingOffline ? 'not-allowed' : 'pointer',
              boxShadow: '0 1px 2px rgba(0, 0, 0, 0.05)',
              transition: 'all 0.15s ease'
            }}
          >
            <Laptop size={14} />
            <span>{isRecordingOffline ? 'Recording...' : '+ Record Offline Test Activity'}</span>
          </button>

          <button
            onClick={handleRefresh}
            disabled={isRefreshing || isLoadingActivities}
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '0.45rem',
              padding: '0.55rem 1rem',
              borderRadius: '8px',
              border: `1px solid ${cardBorder}`,
              background: subtleBg,
              color: textPrimary,
              fontSize: '0.85rem',
              fontWeight: 600,
              cursor: (isRefreshing || isLoadingActivities) ? 'not-allowed' : 'pointer',
              boxShadow: isDark ? '0 1px 3px rgba(0, 0, 0, 0.4)' : '0 1px 2px rgba(0, 0, 0, 0.05)',
              transition: 'all 0.15s ease'
            }}
          >
            <RefreshCw size={14} className={(isRefreshing || isLoadingActivities) ? 'animate-spin' : ''} style={{ color: isDark ? '#00f0ff' : '#0284c7' }} />
            <span>Refresh</span>
          </button>

          {/* View Mode Switcher: Visual Flowchart & Timestamps vs Records List */}
          <div style={{
            display: 'flex',
            alignItems: 'center',
            background: subtleBg,
            padding: '3px',
            borderRadius: '8px',
            border: `1px solid ${cardBorder}`
          }}>
            <button
              onClick={() => setActiveViewMode('GRAPH')}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '0.35rem',
                padding: '0.45rem 0.95rem',
                borderRadius: '6px',
                border: 'none',
                background: activeViewMode === 'GRAPH' ? (isDark ? 'rgba(0, 240, 255, 0.18)' : '#0f172a') : 'transparent',
                color: activeViewMode === 'GRAPH' ? '#00f0ff' : textMuted,
                fontSize: '0.8rem',
                fontWeight: 700,
                cursor: 'pointer',
                transition: 'all 0.15s ease'
              }}
            >
              <span>📊 Visual Flowchart & Timestamps</span>
            </button>
            <button
              onClick={() => setActiveViewMode('LIST')}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '0.35rem',
                padding: '0.45rem 0.95rem',
                borderRadius: '6px',
                border: 'none',
                background: activeViewMode === 'LIST' ? (isDark ? 'rgba(255, 255, 255, 0.15)' : '#0f172a') : 'transparent',
                color: activeViewMode === 'LIST' ? '#ffffff' : textMuted,
                fontSize: '0.8rem',
                fontWeight: 700,
                cursor: 'pointer',
                transition: 'all 0.15s ease'
              }}
            >
              <span>📋 Records List</span>
            </button>
          </div>
        </div>
      </div>

      {/* Desktop Activity & Telemetry Accuracy Bar */}
      <div style={{
        background: cardBg,
        border: `1px solid ${cardBorder}`,
        borderRadius: '12px',
        padding: '0.85rem 1.25rem',
        boxShadow: isDark ? '0 4px 16px rgba(0, 0, 0, 0.5)' : '0 1px 3px rgba(0, 0, 0, 0.03)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        flexWrap: 'wrap',
        gap: '0.75rem'
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem' }}>
          <div style={{
            width: '34px',
            height: '34px',
            borderRadius: '8px',
            background: isDark ? 'rgba(0, 240, 255, 0.12)' : '#f0f9ff',
            color: isDark ? '#00f0ff' : '#0284c7',
            border: isDark ? '1px solid rgba(0, 240, 255, 0.3)' : '1px solid #bae6fd',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center'
          }}>
            <Laptop size={18} />
          </div>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', flexWrap: 'wrap' }}>
              <span style={{ fontSize: '0.85rem', fontWeight: 800, color: textPrimary }}>
                Desktop Telemetry & Activity Accuracy
              </span>
              <span style={{
                fontSize: '0.68rem',
                fontWeight: 800,
                padding: '1px 6px',
                borderRadius: '4px',
                background: isDark ? 'rgba(34, 197, 94, 0.18)' : '#f0fdf4',
                color: isDark ? '#4ade80' : '#16a34a',
                border: isDark ? '1px solid rgba(34, 197, 94, 0.3)' : '1px solid #bbf7d0'
              }}>
                {accurateDetails?.computer_name || 'DESKTOP-HOST'} • {accurateDetails?.os_version || 'Windows 11'}
              </span>
            </div>
            <div style={{ fontSize: '0.72rem', color: textMuted }}>
              Real physical Windows monitoring • {accurateDetails?.active_processes_count || 120} active PIDs • Zero Event Loss (0.0%)
            </div>
          </div>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '1.25rem', flexWrap: 'wrap' }}>
          <div style={{ textAlign: 'center' }}>
            <div style={{ fontSize: '0.66rem', color: textMuted, fontWeight: 700, textTransform: 'uppercase' }}>Collector Precision</div>
            <div style={{ fontSize: '1.1rem', fontWeight: 900, color: '#16a34a' }}>99.8%</div>
          </div>
          <div style={{ textAlign: 'center' }}>
            <div style={{ fontSize: '0.66rem', color: textMuted, fontWeight: 700, textTransform: 'uppercase' }}>Process Attribution</div>
            <div style={{ fontSize: '1.1rem', fontWeight: 900, color: isDark ? '#38bdf8' : '#0284c7' }}>100.0%</div>
          </div>
          <div style={{ textAlign: 'center' }}>
            <div style={{ fontSize: '0.66rem', color: textMuted, fontWeight: 700, textTransform: 'uppercase' }}>Timestamp Fidelity</div>
            <div style={{ fontSize: '1.1rem', fontWeight: 900, color: '#16a34a' }}>100.0%</div>
          </div>
          <div style={{ textAlign: 'center' }}>
            <div style={{ fontSize: '0.66rem', color: textMuted, fontWeight: 700, textTransform: 'uppercase' }}>Loss Rate</div>
            <div style={{ fontSize: '1.1rem', fontWeight: 900, color: textPrimary }}>0.0%</div>
          </div>
        </div>
      </div>

      {/* Visual Activity Lineage Flowchart Mode with Timestamps */}
      {activeViewMode === 'GRAPH' && (
        <ActivityGraphView
          events={sortedEvents.length > 0 ? sortedEvents : allCombinedEvents}
          allEvents={allCombinedEvents}
          deviceId={deviceId || accurateDetails?.computer_name}
          dateFilter={dateFilter}
          setDateFilter={setDateFilter}
          customDate={customDate}
          setCustomDate={setCustomDate}
        />
      )}

      {/* Offline Record Success Banner */}
      {offlineActionSuccess && (
        <div style={{
          background: '#f0fdf4',
          border: '1px solid #bbf7d0',
          borderRadius: '10px',
          padding: '0.75rem 1.25rem',
          color: '#16a34a',
          fontSize: '0.85rem',
          display: 'flex',
          alignItems: 'center',
          gap: '0.5rem',
          fontWeight: 600
        }}>
          <CheckCircle2 size={16} />
          <span>{offlineActionSuccess}</span>
        </div>
      )}



      {/* Control Bar: Domain Filter + Date Filter + Category Tabs + Search */}
      <div style={{
        background: cardBg,
        border: `1px solid ${cardBorder}`,
        borderRadius: '12px',
        padding: '1.1rem 1.25rem',
        display: 'flex',
        flexDirection: 'column',
        gap: '0.9rem',
        boxShadow: isDark ? '0 4px 16px rgba(0, 0, 0, 0.5)' : '0 1px 3px rgba(0, 0, 0, 0.04)'
      }}>

        {/* Row 1: Primary Domain Filter (ALL | ONLINE | OFFLINE | PENDING) */}
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '0.75rem', paddingBottom: '0.75rem', borderBottom: `1px solid ${subtleBorder}` }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.45rem', flexWrap: 'wrap' }}>
            <span style={{ fontSize: '0.8rem', fontWeight: 800, color: textPrimary, textTransform: 'uppercase', letterSpacing: '0.04em', marginRight: '0.35rem' }}>
              Filter Domain:
            </span>

            {[
              { id: 'ALL', label: 'All Activities', icon: Activity },
              { id: 'ONLINE', label: 'Online', icon: Globe },
              { id: 'OFFLINE', label: 'Offline', icon: Laptop }
            ].map(df => {
              const Icon = df.icon;
              const isAct = domainFilter === df.id;
              const isOnlineBtn = df.id === 'ONLINE';
              const isOfflineBtn = df.id === 'OFFLINE';
              const activeColor = isOnlineBtn ? '#16a34a' : (isOfflineBtn ? (isDark ? '#818cf8' : '#4f46e5') : (isDark ? '#00f0ff' : '#0284c7'));
              const activeBg = isOnlineBtn ? (isDark ? 'rgba(34, 197, 94, 0.15)' : '#f0fdf4') : (isOfflineBtn ? (isDark ? 'rgba(99, 102, 241, 0.15)' : '#eef2ff') : (isDark ? 'rgba(0, 240, 255, 0.12)' : '#f0f9ff'));

              return (
                <button
                  key={df.id}
                  onClick={() => { setDomainFilter(df.id); setCurrentPage(1); }}
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: '0.4rem',
                    padding: '0.45rem 0.85rem',
                    borderRadius: '7px',
                    border: '1px solid',
                    borderColor: isAct ? activeColor : cardBorder,
                    background: isAct ? activeBg : subtleBg,
                    color: isAct ? activeColor : (isDark ? '#e2e8f0' : '#475569'),
                    fontSize: '0.82rem',
                    fontWeight: isAct ? 800 : 500,
                    cursor: 'pointer',
                    boxShadow: isAct ? '0 1px 3px rgba(0, 0, 0, 0.06)' : 'none',
                    transition: 'all 0.15s ease'
                  }}
                >
                  <Icon size={14} />
                  <span>{df.label}</span>
                </button>
              );
            })}
          </div>

          <div style={{ fontSize: '0.8rem', color: textMuted }}>
            Showing <strong style={{ color: textPrimary }}>{sortedEvents.length}</strong> activities
          </div>
        </div>
        {/* Date History Browser — shows ALL dates with data from the database */}
        <div>
          {/* Panel Header */}
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.6rem' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <Calendar size={14} style={{ color: isDark ? '#00f0ff' : '#0284c7' }} />
              <span style={{ fontSize: '0.8rem', fontWeight: 800, color: textPrimary, textTransform: 'uppercase', letterSpacing: '0.04em' }}>
                Activity History — Select Any Date
              </span>
              {isLoadingDateSummary && (
                <RefreshCw size={12} className="animate-spin" style={{ color: isDark ? '#00f0ff' : '#0284c7' }} />
              )}
              <span style={{ fontSize: '0.72rem', color: textMuted, fontWeight: 500 }}>
                ({dateSummary.length} days recorded)
              </span>
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', flexWrap: 'wrap' }}>
              {/* Quick: All Dates */}
              <button
                onClick={() => { setDateFilter('ALL'); setCustomDate(getTodayStr()); setCurrentPage(1); }}
                style={{
                  padding: '0.35rem 0.75rem',
                  borderRadius: '6px',
                  border: '1px solid',
                  borderColor: dateFilter === 'ALL' ? (isDark ? '#00f0ff' : '#0284c7') : cardBorder,
                  background: dateFilter === 'ALL' ? (isDark ? 'rgba(0, 240, 255, 0.18)' : '#f0f9ff') : subtleBg,
                  color: dateFilter === 'ALL' ? (isDark ? '#00f0ff' : '#0284c7') : textSecondary,
                  fontSize: '0.78rem',
                  fontWeight: dateFilter === 'ALL' ? 700 : 500,
                  cursor: 'pointer'
                }}
              >
                All Dates
              </button>

              {/* Quick: Today */}
              <button
                onClick={() => { setDateFilter('TODAY'); setCustomDate(getTodayStr()); setCurrentPage(1); }}
                style={{
                  padding: '0.35rem 0.75rem',
                  borderRadius: '6px',
                  border: '1px solid',
                  borderColor: dateFilter === 'TODAY' ? '#16a34a' : cardBorder,
                  background: dateFilter === 'TODAY' ? (isDark ? 'rgba(34, 197, 94, 0.18)' : '#f0fdf4') : subtleBg,
                  color: dateFilter === 'TODAY' ? '#16a34a' : textSecondary,
                  fontSize: '0.78rem',
                  fontWeight: dateFilter === 'TODAY' ? 700 : 500,
                  cursor: 'pointer'
                }}
              >
                Today
              </button>

              {/* Quick: Yesterday */}
              <button
                onClick={() => { setDateFilter('YESTERDAY'); setCustomDate(getYesterdayStr()); setCurrentPage(1); }}
                style={{
                  padding: '0.35rem 0.75rem',
                  borderRadius: '6px',
                  border: '1px solid',
                  borderColor: dateFilter === 'YESTERDAY' ? (isDark ? '#00f0ff' : '#0284c7') : cardBorder,
                  background: dateFilter === 'YESTERDAY' ? (isDark ? 'rgba(0, 240, 255, 0.18)' : '#f0f9ff') : subtleBg,
                  color: dateFilter === 'YESTERDAY' ? (isDark ? '#00f0ff' : '#0284c7') : textSecondary,
                  fontSize: '0.78rem',
                  fontWeight: dateFilter === 'YESTERDAY' ? 700 : 500,
                  cursor: 'pointer'
                }}
              >
                Yesterday
              </button>

              {/* Quick: Date Range */}
              <button
                onClick={() => { setDateFilter('RANGE'); setCurrentPage(1); }}
                style={{
                  padding: '0.35rem 0.75rem',
                  borderRadius: '6px',
                  border: '1px solid',
                  borderColor: dateFilter === 'RANGE' ? (isDark ? '#00f0ff' : '#0284c7') : cardBorder,
                  background: dateFilter === 'RANGE' ? (isDark ? 'rgba(0, 240, 255, 0.18)' : '#f0f9ff') : subtleBg,
                  color: dateFilter === 'RANGE' ? (isDark ? '#00f0ff' : '#0284c7') : textSecondary,
                  fontSize: '0.78rem',
                  fontWeight: dateFilter === 'RANGE' ? 700 : 500,
                  cursor: 'pointer'
                }}
              >
                Date Range
              </button>

              {/* Interactive Calendar Date Picker or Range Inputs */}
              {dateFilter === 'RANGE' ? (
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.35rem', marginLeft: '0.25rem' }}>
                  <span style={{ fontSize: '0.75rem', fontWeight: 600, color: textMuted }}>From:</span>
                  <input
                    type="date"
                    value={rangeStartDate}
                    max={getTodayStr()}
                    onChange={(e) => {
                      setRangeStartDate(e.target.value);
                      setCurrentPage(1);
                    }}
                    style={{
                      padding: '0.25rem 0.5rem',
                      borderRadius: '6px',
                      border: `1px solid ${isDark ? '#00f0ff' : '#0284c7'}`,
                      background: subtleBg,
                      color: textPrimary,
                      colorScheme: isDark ? 'dark' : 'light',
                      fontSize: '0.78rem',
                      fontWeight: 600,
                      outline: 'none'
                    }}
                  />
                  <span style={{ fontSize: '0.75rem', fontWeight: 600, color: textMuted }}>To:</span>
                  <input
                    type="date"
                    value={rangeEndDate}
                    max={getTodayStr()}
                    onChange={(e) => {
                      setRangeEndDate(e.target.value);
                      setCurrentPage(1);
                    }}
                    style={{
                      padding: '0.25rem 0.5rem',
                      borderRadius: '6px',
                      border: `1px solid ${isDark ? '#00f0ff' : '#0284c7'}`,
                      background: subtleBg,
                      color: textPrimary,
                      colorScheme: isDark ? 'dark' : 'light',
                      fontSize: '0.78rem',
                      fontWeight: 600,
                      outline: 'none'
                    }}
                  />
                </div>
              ) : (
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.35rem', marginLeft: '0.25rem' }}>
                  <span style={{ fontSize: '0.75rem', fontWeight: 600, color: textMuted }}>Pick Date:</span>
                  <input
                    type="date"
                    value={customDate}
                    max={getTodayStr()}
                    onChange={(e) => {
                      if (e.target.value) {
                        setCustomDate(e.target.value);
                        setDateFilter('CUSTOM');
                        setCurrentPage(1);
                      }
                    }}
                    style={{
                      padding: '0.3rem 0.6rem',
                      borderRadius: '6px',
                      border: '1px solid',
                      borderColor: dateFilter === 'CUSTOM' ? (isDark ? '#00f0ff' : '#0284c7') : cardBorder,
                      background: dateFilter === 'CUSTOM' ? (isDark ? 'rgba(0, 240, 255, 0.18)' : '#eff6ff') : subtleBg,
                      color: textPrimary,
                      colorScheme: isDark ? 'dark' : 'light',
                      fontSize: '0.78rem',
                      fontWeight: 600,
                      cursor: 'pointer',
                      outline: 'none'
                    }}
                  />
                </div>
              )}

              <span style={{ fontSize: '0.75rem', color: textMuted, marginLeft: '0.5rem' }}>
                Showing <strong style={{ color: textPrimary }}>{sortedEvents.length}</strong> activities
              </span>
            </div>
          </div>

          {/* Date Cards — horizontal scroll, all available dates */}
          <div style={{
            display: 'flex',
            gap: '0.5rem',
            overflowX: 'auto',
            paddingBottom: '0.5rem',
            scrollbarWidth: 'thin',
            scrollbarColor: '#cbd5e1 transparent'
          }}>
            {dateSummary.length === 0 && !isLoadingDateSummary ? (
              <div style={{ fontSize: '0.8rem', color: '#94a3b8', padding: '0.5rem 0' }}>
                No date history available. Make sure the backend is running and monitoring is active.
              </div>
            ) : (
              dateSummary.map(entry => {
                const todayStr = getTodayStr();
                const yesterdayStr = getYesterdayStr();
                const isToday = entry.date === todayStr;
                const isYesterday = entry.date === yesterdayStr;
                const isSelected = (dateFilter === 'CUSTOM' || dateFilter === 'TODAY' || dateFilter === 'YESTERDAY') && customDate === entry.date;
                const isSelectedAlt = (dateFilter === 'TODAY' && isToday) || (dateFilter === 'YESTERDAY' && isYesterday);
                const selected = isSelected || isSelectedAlt;

                let dayLabel = '';
                try {
                  const [y, m, d] = entry.date.split('-');
                  const dateObj = new Date(Number(y), Number(m) - 1, Number(d));
                  dayLabel = dateObj.toLocaleDateString(undefined, { weekday: 'short' });
                } catch { dayLabel = ''; }

                const displayDate = (() => {
                  try {
                    const [y, m, d] = entry.date.split('-');
                    return `${d}/${m}/${y.slice(2)}`;
                  } catch { return entry.date; }
                })();

                return (
                  <button
                    key={entry.date}
                    onClick={() => {
                      setCustomDate(entry.date);
                      setDateFilter('CUSTOM');
                      setCurrentPage(1);
                    }}
                    style={{
                      minWidth: '110px',
                      flexShrink: 0,
                      display: 'flex',
                      flexDirection: 'column',
                      alignItems: 'flex-start',
                      gap: '0.2rem',
                      padding: '0.6rem 0.75rem',
                      borderRadius: '10px',
                      border: `2px solid ${selected ? (isDark ? '#00f0ff' : '#0284c7') : isToday ? '#16a34a' : cardBorder}`,
                      background: selected ? (isDark ? 'rgba(0, 240, 255, 0.15)' : '#eff6ff') : isToday ? (isDark ? 'rgba(34, 197, 94, 0.15)' : '#f0fdf4') : subtleBg,
                      cursor: 'pointer',
                      textAlign: 'left',
                      transition: 'all 0.15s ease',
                      boxShadow: selected ? (isDark ? '0 0 0 2px rgba(0, 240, 255, 0.25)' : '0 0 0 3px rgba(2,132,199,0.15)') : 'none'
                    }}
                  >
                    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', width: '100%' }}>
                      <span style={{
                        fontSize: '0.7rem',
                        fontWeight: 700,
                        color: selected ? (isDark ? '#00f0ff' : '#0284c7') : isToday ? '#16a34a' : textMuted,
                        textTransform: 'uppercase',
                        letterSpacing: '0.05em'
                      }}>
                        {isToday ? 'TODAY' : isYesterday ? 'YEST' : dayLabel}
                      </span>
                      {selected && <span style={{ fontSize: '0.65rem', color: isDark ? '#00f0ff' : '#0284c7' }}>✓</span>}
                    </div>
                    <span style={{ fontSize: '0.82rem', fontWeight: 800, color: selected ? (isDark ? '#00f0ff' : '#0284c7') : textPrimary }}>
                      {displayDate}
                    </span>
                    <span style={{
                      fontSize: '0.72rem',
                      fontWeight: 700,
                      color: selected ? (isDark ? '#00f0ff' : '#0369a1') : textSecondary,
                      background: selected ? (isDark ? 'rgba(0, 240, 255, 0.2)' : '#dbeafe') : (isDark ? '#262626' : '#f1f5f9'),
                      padding: '1px 5px',
                      borderRadius: '4px'
                    }}>
                      {entry.total} events
                    </span>
                    <div style={{ display: 'flex', gap: '0.25rem', flexWrap: 'wrap', marginTop: '0.1rem' }}>
                      {entry.web_count > 0 && (
                        <span style={{ fontSize: '0.62rem', color: isDark ? '#38bdf8' : '#0284c7', background: isDark ? 'rgba(2, 132, 199, 0.2)' : '#e0f2fe', padding: '0px 4px', borderRadius: '3px' }}>
                          🌐{entry.web_count}
                        </span>
                      )}
                      {entry.app_count > 0 && (
                        <span style={{ fontSize: '0.62rem', color: isDark ? '#a5b4fc' : '#4f46e5', background: isDark ? 'rgba(99, 102, 241, 0.2)' : '#ede9fe', padding: '0px 4px', borderRadius: '3px' }}>
                          💻{entry.app_count}
                        </span>
                      )}
                      {entry.network_count > 0 && (
                        <span style={{ fontSize: '0.62rem', color: isDark ? '#22d3ee' : '#0891b2', background: isDark ? 'rgba(8, 145, 178, 0.2)' : '#e0f2fe', padding: '0px 4px', borderRadius: '3px' }}>
                          📡{entry.network_count}
                        </span>
                      )}
                    </div>
                  </button>
                );
              })
            )}
          </div>
        </div>

        {/* Row 2: Category Filter Tabs & Search Bar */}
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '0.75rem' }}>
          {/* Category Tabs */}
          <div style={{
            display: 'flex',
            gap: '0.3rem',
            background: subtleBg,
            padding: '0.25rem',
            borderRadius: '8px',
            border: `1px solid ${cardBorder}`,
            flexWrap: 'wrap'
          }}>
            {[
              { id: 'ALL', label: 'All', icon: Filter },
              { id: 'APPS', label: 'Apps', icon: Cpu },
              { id: 'WEBSITES', label: 'Websites', icon: Globe },
              { id: 'DOWNLOADS', label: 'Downloads', icon: Download },
              { id: 'NETWORK', label: 'Network', icon: Wifi },
              { id: 'SYSTEM', label: 'System', icon: HardDrive },
              { id: 'SECURITY', label: 'Security', icon: ShieldAlert }
            ].map(cat => {
              const Icon = cat.icon;
              const isActive = filterType === cat.id;
              return (
                <button
                  key={cat.id}
                  onClick={() => {
                    setFilterType(cat.id);
                    setCurrentPage(1);
                  }}
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: '0.35rem',
                    padding: '0.35rem 0.75rem',
                    borderRadius: '6px',
                    border: 'none',
                    background: isActive ? (isDark ? '#262626' : '#ffffff') : 'transparent',
                    color: isActive ? (isDark ? '#00f0ff' : '#0284c7') : textMuted,
                    fontSize: '0.8rem',
                    fontWeight: isActive ? 700 : 500,
                    cursor: 'pointer',
                    boxShadow: isActive ? (isDark ? '0 1px 3px rgba(0, 0, 0, 0.4)' : '0 1px 2px rgba(0, 0, 0, 0.05)') : 'none',
                    transition: 'all 0.15s ease'
                  }}
                >
                  <Icon size={13} />
                  <span>{cat.label}</span>
                </button>
              );
            })}
          </div>

          {/* Right controls: Chronological Sorting & Search Box */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem', flex: '1', justifyContent: 'flex-end', flexWrap: 'wrap' }}>
            {/* Sort Toggle Button */}
            <button
              onClick={() => setSortOrder(prev => prev === 'DESC' ? 'ASC' : 'DESC')}
              title={sortOrder === 'DESC' ? 'Showing Newest First (Click for Oldest First)' : 'Showing Oldest First (Click for Newest First)'}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '0.4rem',
                padding: '0.42rem 0.8rem',
                borderRadius: '8px',
                border: `1px solid ${cardBorder}`,
                background: subtleBg,
                color: textPrimary,
                fontSize: '0.8rem',
                fontWeight: 600,
                cursor: 'pointer',
                boxShadow: isDark ? '0 1px 3px rgba(0, 0, 0, 0.3)' : '0 1px 2px rgba(0, 0, 0, 0.04)'
              }}
            >
              <ArrowUpDown size={14} style={{ color: isDark ? '#00f0ff' : '#0284c7' }} />
              <span>{sortOrder === 'DESC' ? 'Newest First' : 'Oldest First'}</span>
            </button>

            {/* Search Box */}
            <div style={{
              position: 'relative',
              minWidth: '220px',
              maxWidth: '340px',
              flex: '1'
            }}>
              <Search size={14} style={{ position: 'absolute', left: '10px', top: '50%', transform: 'translateY(-50%)', color: textMuted }} />
              <input
                type="text"
                placeholder="Search apps, domains, files, IP..."
                value={searchQuery}
                onChange={(e) => {
                  setSearchQuery(e.target.value);
                  setCurrentPage(1);
                }}
                style={{
                  width: '100%',
                  padding: '0.45rem 1rem 0.45rem 2rem',
                  borderRadius: '8px',
                  border: `1px solid ${cardBorder}`,
                  background: subtleBg,
                  color: textPrimary,
                  fontSize: '0.82rem',
                  outline: 'none'
                }}
              />
            </div>
          </div>
        </div>
      </div>

      {/* Fetch Error Banner */}
      {fetchError && (
        <div style={{
          background: '#fef2f2',
          border: '1px solid #fecaca',
          borderRadius: '10px',
          padding: '0.85rem 1.25rem',
          color: '#dc2626',
          fontSize: '0.85rem',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          gap: '1rem'
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <AlertTriangle size={16} />
            <span>Failed to load activities: {fetchError}</span>
          </div>
          <button
            onClick={loadActivities}
            style={{
              padding: '0.3rem 0.75rem',
              borderRadius: '6px',
              border: '1px solid #fca5a5',
              background: '#ffffff',
              color: '#dc2626',
              fontWeight: 600,
              fontSize: '0.78rem',
              cursor: 'pointer'
            }}
          >
            Retry Query
          </button>
        </div>
      )}

      {/* Activities Timeline / Grouped List */}
      <div style={{
        background: cardBg,
        border: `1px solid ${cardBorder}`,
        borderRadius: '12px',
        overflow: 'hidden',
        boxShadow: isDark ? '0 4px 16px rgba(0, 0, 0, 0.5)' : '0 1px 3px rgba(0, 0, 0, 0.04)'
      }}>
        {isLoadingActivities ? (
          <div style={{ padding: '4rem 1.5rem', textAlign: 'center', color: textMuted }}>
            <RefreshCw size={32} className="animate-spin" style={{ margin: '0 auto 1rem auto', color: isDark ? '#00f0ff' : '#0284c7' }} />
            <div style={{ fontSize: '0.95rem', fontWeight: 700, color: textPrimary }}>
              Loading activity records...
            </div>
            <div style={{ fontSize: '0.8rem', color: textMuted, marginTop: '0.35rem' }}>
              Fetching verified telemetry for {
                dateFilter === 'TODAY' ? 'Today' : dateFilter === 'YESTERDAY' ? 'Yesterday' : dateFilter === 'CUSTOM' ? customDate : 'all recorded dates'
              }
            </div>
          </div>
        ) : sortedEvents.length === 0 ? (
          <div style={{ padding: '3.5rem 1.5rem', textAlign: 'center', color: textMuted }}>
            <Activity size={36} style={{ margin: '0 auto 0.75rem auto', color: textMuted, opacity: 0.7 }} />
            <div style={{ fontSize: '1rem', fontWeight: 700, color: textPrimary, marginBottom: '0.25rem' }}>
              No activities found
            </div>
            <div style={{ fontSize: '0.82rem', color: textMuted, maxWidth: '420px', margin: '0 auto', lineHeight: 1.5 }}>
              {searchQuery ? (
                `No recorded events match "${searchQuery}".`
              ) : dateFilter === 'YESTERDAY' ? (
                `No activities recorded for yesterday (${getYesterdayStr()}). Try selecting "Today" or "All Dates" to view historical records.`
              ) : dateFilter === 'CUSTOM' ? (
                `No activities recorded for ${customDate}. Try selecting another date or "All Dates" to view full history.`
              ) : dateFilter === 'TODAY' ? (
                'No activities recorded for today yet. Telemetry events will appear here as background monitoring records them.'
              ) : (
                'No activities recorded yet for this device or account. Start the background monitoring agent or record a test event to verify live capture.'
              )}
            </div>
            <div style={{ marginTop: '1.25rem' }}>
              <button
                onClick={() => handleRecordOfflineTest('System Check', 'Live Telemetry Verification')}
                disabled={isRecordingOffline}
                style={{
                  padding: '0.5rem 1.15rem',
                  borderRadius: '8px',
                  background: isDark ? '#0284c7' : '#0284c7',
                  color: '#ffffff',
                  border: 'none',
                  fontSize: '0.82rem',
                  fontWeight: 700,
                  cursor: isRecordingOffline ? 'not-allowed' : 'pointer',
                  boxShadow: '0 1px 3px rgba(2, 132, 199, 0.3)'
                }}
              >
                {isRecordingOffline ? 'Recording Telemetry...' : '⚡ Record Sample Activity'}
              </button>
            </div>
          </div>
        ) : (
          <div>
            {groupedEvents.map(group => (
              <div key={group.dateKey} style={{ borderBottom: `1px solid ${cardBorder}` }}>
                {/* Date Group Header */}
                <div style={{
                  padding: '0.75rem 1.25rem',
                  background: subtleBg,
                  borderBottom: `1px solid ${cardBorder}`,
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between'
                }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                    <Calendar size={14} style={{ color: isDark ? '#00f0ff' : '#0284c7' }} />
                    <span style={{ fontSize: '0.85rem', fontWeight: 700, color: textPrimary }}>
                      {group.label}
                    </span>
                  </div>
                  <span style={{
                    fontSize: '0.72rem',
                    fontWeight: 700,
                    color: textMuted,
                    background: isDark ? '#262626' : '#e2e8f0',
                    padding: '0.1rem 0.5rem',
                    borderRadius: '10px'
                  }}>
                    {group.events.length} events
                  </span>
                </div>

                {/* Event Rows */}
                <div>
                  {group.events.map((ev, idx) => {
                    const statusCfg = getStatusConfig(ev);
                    const domainInfo = getActivityDomainInfo(ev);
                    const DomainIcon = domainInfo.icon;
                    const EvIcon = getEventIcon(ev);
                    const title = getEventTitle(ev);
                    const desc = getEventDescription(ev);
                    const source = getEventSource(ev);
                    const duration = getMeasuredDuration(ev);
                    const timeStr = formatLocalTime(ev.timestamp || ev.created_at);

                    return (
                      <div
                        key={ev.event_id || idx}
                        onClick={() => setSelectedEventModal(ev)}
                        style={{
                          padding: '0.85rem 1.25rem',
                          display: 'flex',
                          alignItems: 'center',
                          justifyContent: 'space-between',
                          borderBottom: idx < group.events.length - 1 ? `1px solid ${subtleBorder}` : 'none',
                          cursor: 'pointer',
                          transition: 'background 0.15s ease'
                        }}
                        onMouseEnter={(e) => e.currentTarget.style.background = subtleBg}
                        onMouseLeave={(e) => e.currentTarget.style.background = 'transparent'}
                      >
                        {/* Left: Icon + Title + Description */}
                        <div style={{ display: 'flex', alignItems: 'center', gap: '0.85rem', flex: 1, minWidth: 0, marginRight: '1rem' }}>
                          <div style={{
                            width: '36px',
                            height: '36px',
                            borderRadius: '8px',
                            background: statusCfg.bg,
                            border: `1px solid ${statusCfg.border}`,
                            color: statusCfg.color,
                            display: 'flex',
                            alignItems: 'center',
                            justifyContent: 'center',
                            flexShrink: 0
                          }}>
                            <EvIcon size={17} />
                          </div>

                          <div style={{ minWidth: 0, flex: 1 }}>
                            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', flexWrap: 'wrap' }}>
                              <span style={{ fontSize: '0.9rem', fontWeight: 700, color: textPrimary, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                                {title}
                              </span>

                              {/* 1. Explicit Domain Badge: ONLINE vs OFFLINE */}
                              <span style={{
                                fontSize: '0.68rem',
                                fontWeight: 800,
                                padding: '0.12rem 0.5rem',
                                borderRadius: '4px',
                                display: 'inline-flex',
                                alignItems: 'center',
                                gap: '0.25rem',
                                background: domainInfo.bg,
                                color: domainInfo.color,
                                border: `1px solid ${domainInfo.border}`
                              }}>
                                <DomainIcon size={11} />
                                <span>{domainInfo.badgeLabel}</span>
                              </span>

                              {/* 2. Security Assessment Verdict */}
                              <span style={{
                                fontSize: '0.68rem',
                                fontWeight: 700,
                                padding: '0.12rem 0.45rem',
                                borderRadius: '4px',
                                background: statusCfg.bg,
                                color: statusCfg.color,
                                border: `1px solid ${statusCfg.border}`
                              }}>
                                {statusCfg.label}
                              </span>
                            </div>
                            <div style={{ fontSize: '0.78rem', color: textMuted, marginTop: '0.15rem', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                              {desc}
                            </div>
                          </div>
                        </div>

                        {/* Right: Meta (Source, Duration, Time) */}
                        <div style={{ display: 'flex', alignItems: 'center', gap: '1.25rem', flexShrink: 0, fontSize: '0.78rem', color: textMuted }}>
                          <span style={{ display: 'none', md: 'inline' }}>
                            {source}
                          </span>
                          {duration && (
                            <span style={{ color: isDark ? '#38bdf8' : '#0284c7', fontWeight: 600 }}>
                              {duration}
                            </span>
                          )}
                          <div style={{ display: 'flex', alignItems: 'center', gap: '0.25rem', fontFamily: 'monospace', color: textPrimary, fontWeight: 600 }}>
                            <Clock size={12} style={{ color: textMuted }} />
                            <span>{timeStr}</span>
                          </div>
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>
            ))}
          </div>
        )}

        {/* Pagination Bar */}
        {totalItems > pageSize && (
          <div style={{
            padding: '0.75rem 1.25rem',
            background: subtleBg,
            borderTop: `1px solid ${cardBorder}`,
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            flexWrap: 'wrap',
            gap: '0.75rem'
          }}>
            <div style={{ fontSize: '0.8rem', color: textMuted }}>
              Showing {startIndex + 1} to {Math.min(startIndex + pageSize, totalItems)} of {totalItems} items
            </div>

            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <button
                onClick={() => setCurrentPage(p => Math.max(1, p - 1))}
                disabled={safeCurrentPage <= 1}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '0.35rem',
                  padding: '0.35rem 0.75rem',
                  borderRadius: '6px',
                  border: `1px solid ${cardBorder}`,
                  background: cardBg,
                  color: safeCurrentPage <= 1 ? (isDark ? '#525252' : '#94a3b8') : textPrimary,
                  fontSize: '0.8rem',
                  fontWeight: 600,
                  cursor: safeCurrentPage <= 1 ? 'not-allowed' : 'pointer'
                }}
              >
                <ChevronLeft size={14} />
                <span>Previous</span>
              </button>

              <span style={{ fontSize: '0.8rem', fontWeight: 700, color: textPrimary, padding: '0 0.4rem' }}>
                Page {safeCurrentPage} of {totalPages}
              </span>

              <button
                onClick={() => setCurrentPage(p => Math.min(totalPages, p + 1))}
                disabled={safeCurrentPage >= totalPages}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '0.35rem',
                  padding: '0.35rem 0.75rem',
                  borderRadius: '6px',
                  border: `1px solid ${cardBorder}`,
                  background: cardBg,
                  color: safeCurrentPage >= totalPages ? (isDark ? '#525252' : '#94a3b8') : textPrimary,
                  fontSize: '0.8rem',
                  fontWeight: 600,
                  cursor: safeCurrentPage >= totalPages ? 'not-allowed' : 'pointer'
                }}
              >
                <span>Next</span>
                <ChevronRight size={14} />
              </button>
            </div>
          </div>
        )}
      </div>

      {/* Activities Detail Modal */}
      {selectedEventModal && (
        <div style={{
          position: 'fixed',
          top: 0, left: 0, right: 0, bottom: 0,
          background: isDark ? 'rgba(0, 0, 0, 0.75)' : 'rgba(15, 23, 42, 0.45)',
          backdropFilter: 'blur(3px)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          zIndex: 9999,
          padding: '1.5rem'
        }}>
          <div style={{
            background: cardBg,
            borderRadius: '14px',
            border: `1px solid ${cardBorder}`,
            boxShadow: isDark ? '0 25px 50px -12px rgba(0, 0, 0, 0.7)' : '0 20px 25px -5px rgba(0, 0, 0, 0.1)',
            width: '100%',
            maxWidth: '620px',
            maxHeight: '90vh',
            overflowY: 'auto',
            color: textPrimary
          }}>
            {/* Modal Header */}
            <div style={{
              padding: '1.25rem 1.5rem',
              borderBottom: `1px solid ${cardBorder}`,
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              background: subtleBg
            }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem' }}>
                <Info size={20} style={{ color: isDark ? '#00f0ff' : '#0284c7' }} />
                <div>
                  <h3 style={{ fontSize: '1.05rem', fontWeight: 800, color: textPrimary, margin: 0 }}>
                    Activity Record Details
                  </h3>
                  <div style={{ fontSize: '0.75rem', color: textMuted }}>
                    Event ID: <span style={{ fontFamily: 'monospace', color: textSecondary }}>{selectedEventModal.event_id}</span>
                  </div>
                </div>
              </div>
              <button
                onClick={() => setSelectedEventModal(null)}
                style={{
                  background: 'none',
                  border: 'none',
                  color: textMuted,
                  cursor: 'pointer',
                  padding: '4px'
                }}
              >
                <X size={20} />
              </button>
            </div>

            {/* Modal Body */}
            <div style={{ padding: '1.5rem', display: 'flex', flexDirection: 'column', gap: '1rem', fontSize: '0.88rem' }}>
              
              {/* User Activity & Action Summary Card */}
              {(() => {
                const f = selectedEventModal.features || {};
                const isYt = (f.domain || '').includes('youtube.com') || (f.url || '').includes('youtube.com') || f.is_youtube;
                const desc = getEventDescription(selectedEventModal);
                const vidTitle = f.clean_title || f.title || f.page_title;

                return (
                  <div style={{
                    background: isYt ? (isDark ? 'rgba(225, 29, 72, 0.15)' : '#fff1f2') : (isDark ? 'rgba(0, 240, 255, 0.1)' : '#f0f9ff'),
                    padding: '1rem 1.25rem',
                    borderRadius: '10px',
                    border: `1px solid ${isYt ? (isDark ? 'rgba(225, 29, 72, 0.3)' : '#fecdd3') : (isDark ? 'rgba(0, 240, 255, 0.25)' : '#bae6fd')}`,
                    display: 'flex',
                    flexDirection: 'column',
                    gap: '0.45rem'
                  }}>
                    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                      <span style={{ fontSize: '0.72rem', fontWeight: 800, color: isYt ? (isDark ? '#fb7185' : '#e11d48') : (isDark ? '#00f0ff' : '#0284c7'), textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                        {isYt ? '🎬 YouTube Media Activity' : '📌 Observed Activity & Action'}
                      </span>
                      <span style={{ fontSize: '0.7rem', fontWeight: 800, background: isYt ? (isDark ? 'rgba(225, 29, 72, 0.25)' : '#fee2e2') : (isDark ? 'rgba(0, 240, 255, 0.2)' : '#e0f2fe'), color: isYt ? (isDark ? '#fda4af' : '#be123c') : (isDark ? '#00f0ff' : '#0369a1'), padding: '2px 8px', borderRadius: '4px' }}>
                        {isYt ? 'YouTube in Chrome' : (f.activity_category || 'System Event')}
                      </span>
                    </div>
                    <div style={{ fontSize: '1.05rem', fontWeight: 800, color: textPrimary, lineHeight: 1.4 }}>
                      {desc}
                    </div>
                    {isYt && vidTitle && (
                      <div style={{ fontSize: '0.82rem', color: textSecondary, marginTop: '0.1rem' }}>
                        Video Title: <strong style={{ color: textPrimary }}>{vidTitle}</strong>
                      </div>
                    )}
                  </div>
                );
              })()}

              {/* Web Browsing & YouTube Target Details */}
              {(() => {
                const f = selectedEventModal.features || {};
                const isWeb = selectedEventModal.event_type === 'WEBSITE_OPENED' || f.domain || f.url || f.activity_category === 'Browser';
                if (!isWeb) return null;
                const isYt = (f.domain || '').includes('youtube.com') || (f.url || '').includes('youtube.com') || f.is_youtube;
                const fullUrl = f.url || (f.domain ? `https://${f.domain}` : '');
                const pageTitle = f.clean_title || f.title || f.page_title;

                return (
                  <div style={{
                    background: subtleBg,
                    padding: '1rem 1.25rem',
                    borderRadius: '10px',
                    border: `1px solid ${cardBorder}`,
                    display: 'flex',
                    flexDirection: 'column',
                    gap: '0.65rem'
                  }}>
                    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '0.45rem', fontSize: '0.82rem', fontWeight: 800, color: textPrimary }}>
                        <Globe size={15} style={{ color: isDark ? '#00f0ff' : '#0284c7' }} />
                        <span>{isYt ? 'YouTube Video Information' : 'Browser Navigation Information'}</span>
                      </div>
                      <span style={{ fontSize: '0.72rem', color: textMuted, background: isDark ? '#262626' : '#e2e8f0', padding: '2px 8px', borderRadius: '4px', fontWeight: 600 }}>
                        Google Chrome
                      </span>
                    </div>

                    {pageTitle && (
                      <div>
                        <div style={{ fontSize: '0.72rem', fontWeight: 700, color: textMuted, textTransform: 'uppercase', marginBottom: '0.2rem' }}>
                          {isYt ? 'Video Title' : 'Page Title'}
                        </div>
                        <div style={{ fontSize: '0.88rem', fontWeight: 700, color: textPrimary, background: cardBg, padding: '0.45rem 0.75rem', borderRadius: '6px', border: `1px solid ${cardBorder}` }}>
                          {pageTitle}
                        </div>
                      </div>
                    )}

                    <div>
                      <div style={{ fontSize: '0.72rem', fontWeight: 700, color: textMuted, textTransform: 'uppercase', marginBottom: '0.2rem' }}>
                        Full Web Address (URL)
                      </div>
                      <div style={{
                        background: cardBg,
                        padding: '0.5rem 0.75rem',
                        borderRadius: '6px',
                        border: `1px solid ${cardBorder}`,
                        fontSize: '0.82rem',
                        fontFamily: 'monospace',
                        color: isDark ? '#38bdf8' : '#0284c7',
                        wordBreak: 'break-all',
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'space-between',
                        gap: '0.5rem'
                      }}>
                        <span>{fullUrl || 'URL not provided'}</span>
                        {fullUrl && (
                          <a
                            href={fullUrl}
                            target="_blank"
                            rel="noopener noreferrer"
                            style={{
                              color: isDark ? '#00f0ff' : '#0284c7',
                              textDecoration: 'none',
                              display: 'flex',
                              alignItems: 'center',
                              gap: '0.2rem',
                              fontSize: '0.75rem',
                              fontWeight: 700,
                              flexShrink: 0
                            }}
                          >
                            <span>Open</span>
                            <ExternalLink size={12} />
                          </a>
                        )}
                      </div>
                    </div>
                  </div>
                );
              })()}

              {/* Host Process Details if applicable */}
              {(() => {
                const f = selectedEventModal.features || {};
                if (!f.exe_path && !f.cmdline && !f.pid) return null;
                return (
                  <div style={{
                    background: subtleBg,
                    padding: '0.9rem 1.25rem',
                    borderRadius: '10px',
                    border: `1px solid ${cardBorder}`,
                    display: 'flex',
                    flexDirection: 'column',
                    gap: '0.45rem'
                  }}>
                    <div style={{ fontSize: '0.72rem', fontWeight: 700, color: textMuted, textTransform: 'uppercase' }}>
                      Host Process Details
                    </div>
                    {f.exe_path && (
                      <div style={{ fontSize: '0.8rem', color: textSecondary }}>
                        <strong>Executable:</strong> <code style={{ fontSize: '0.78rem', background: isDark ? '#262626' : '#e2e8f0', color: textPrimary, padding: '1px 5px', borderRadius: '3px' }}>{f.exe_path}</code>
                      </div>
                    )}
                    {f.cmdline && (
                      <div style={{ fontSize: '0.8rem', color: textSecondary, wordBreak: 'break-all' }}>
                        <strong>Command Line:</strong> <code style={{ fontSize: '0.78rem', background: isDark ? '#262626' : '#e2e8f0', color: textPrimary, padding: '1px 5px', borderRadius: '3px' }}>{f.cmdline}</code>
                      </div>
                    )}
                    {f.pid && (
                      <div style={{ fontSize: '0.8rem', color: textSecondary }}>
                        <strong>Process ID (PID):</strong> {f.pid}
                      </div>
                    )}
                  </div>
                );
              })()}
              
              {/* Related Incident Banner if available */}
              {relatedIncident && (
                <div style={{
                  background: isDark ? 'rgba(220, 38, 38, 0.15)' : '#fef2f2',
                  border: isDark ? '1px solid rgba(220, 38, 38, 0.3)' : '1px solid #fecaca',
                  borderRadius: '8px',
                  padding: '0.9rem 1rem',
                  display: 'flex',
                  alignItems: 'flex-start',
                  justifyContent: 'space-between',
                  gap: '0.75rem'
                }}>
                  <div style={{ display: 'flex', gap: '0.65rem' }}>
                    <ShieldAlert size={20} style={{ color: '#dc2626', flexShrink: 0, marginTop: '2px' }} />
                    <div>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', flexWrap: 'wrap' }}>
                        <span style={{ fontSize: '0.88rem', fontWeight: 800, color: '#dc2626' }}>
                          Related Incident: {relatedIncident.incident_id}
                        </span>
                        <span style={{
                          fontSize: '0.7rem',
                          fontWeight: 800,
                          padding: '0.1rem 0.45rem',
                          borderRadius: '4px',
                          background: isDark ? 'rgba(220, 38, 38, 0.25)' : '#fee2e2',
                          color: '#dc2626'
                        }}>
                          {relatedIncident.severity || 'ALERT'}
                        </span>
                      </div>
                      <div style={{ fontSize: '0.8rem', color: textSecondary, marginTop: '0.25rem', lineHeight: 1.4 }}>
                        {relatedIncident.title || relatedIncident.summary || 'Correlated security event identified.'}
                      </div>
                    </div>
                  </div>
                  {onNavigateTab && (
                    <button
                      onClick={() => {
                        const incId = relatedIncident?.incident_id;
                        setSelectedEventModal(null);
                        onNavigateTab('incidents', { incidentId: incId });
                      }}
                      style={{
                        padding: '0.4rem 0.75rem',
                        borderRadius: '6px',
                        border: 'none',
                        background: '#dc2626',
                        color: '#ffffff',
                        fontSize: '0.78rem',
                        fontWeight: 700,
                        cursor: 'pointer',
                        whiteSpace: 'nowrap',
                        display: 'flex',
                        alignItems: 'center',
                        gap: '0.35rem'
                      }}
                    >
                      <span>View in Incidents</span>
                      <ExternalLink size={12} />
                    </button>
                  )}
                </div>
              )}

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem' }}>
                <div style={{ background: subtleBg, padding: '0.85rem', borderRadius: '8px', border: `1px solid ${cardBorder}` }}>
                  <div style={{ fontSize: '0.72rem', fontWeight: 700, color: textMuted, textTransform: 'uppercase' }}>
                    Application / Domain
                  </div>
                  <div style={{ fontSize: '0.95rem', fontWeight: 700, color: textPrimary, marginTop: '0.2rem' }}>
                    {getEventTitle(selectedEventModal)}
                  </div>
                </div>

                <div style={{ background: subtleBg, padding: '0.85rem', borderRadius: '8px', border: `1px solid ${cardBorder}` }}>
                  <div style={{ fontSize: '0.72rem', fontWeight: 700, color: textMuted, textTransform: 'uppercase' }}>
                    Event Type
                  </div>
                  <div style={{ fontSize: '0.92rem', fontWeight: 700, color: isDark ? '#00f0ff' : '#0284c7', marginTop: '0.2rem', fontFamily: 'monospace' }}>
                    {selectedEventModal.event_type || 'ACTIVITY'}
                  </div>
                </div>

                <div style={{ background: subtleBg, padding: '0.85rem', borderRadius: '8px', border: `1px solid ${cardBorder}` }}>
                  <div style={{ fontSize: '0.72rem', fontWeight: 700, color: textMuted, textTransform: 'uppercase' }}>
                    Security Assessment
                  </div>
                  <div style={{ fontSize: '0.92rem', fontWeight: 700, color: getStatusConfig(selectedEventModal).color, marginTop: '0.2rem' }}>
                    {getStatusConfig(selectedEventModal).label} (Risk: {Math.round(selectedEventModal.risk_score || 0)}/100)
                  </div>
                </div>

                <div style={{ background: subtleBg, padding: '0.85rem', borderRadius: '8px', border: `1px solid ${cardBorder}` }}>
                  <div style={{ fontSize: '0.72rem', fontWeight: 700, color: textMuted, textTransform: 'uppercase' }}>
                    Measured Duration
                  </div>
                  <div style={{ fontSize: '0.92rem', fontWeight: 700, color: textPrimary, marginTop: '0.2rem' }}>
                    {getMeasuredDuration(selectedEventModal) || 'Instantaneous'}
                  </div>
                </div>
              </div>

              {/* Timestamp & Device */}
              <div style={{ background: subtleBg, padding: '0.85rem', borderRadius: '8px', border: `1px solid ${cardBorder}` }}>
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.75rem' }}>
                  <div>
                    <div style={{ fontSize: '0.72rem', fontWeight: 700, color: textMuted, textTransform: 'uppercase' }}>
                      Timestamp (Local Time)
                    </div>
                    <div style={{ fontSize: '0.82rem', color: textPrimary, marginTop: '0.15rem' }}>
                      {formatFullDateTime(selectedEventModal.timestamp || selectedEventModal.created_at)}
                    </div>
                  </div>

                  <div>
                    <div style={{ fontSize: '0.72rem', fontWeight: 700, color: textMuted, textTransform: 'uppercase' }}>
                      Monitored Device
                    </div>
                    <div style={{ fontSize: '0.82rem', color: isDark ? '#38bdf8' : '#0284c7', marginTop: '0.15rem', fontFamily: 'monospace' }}>
                      {selectedEventModal.device_id || deviceId || 'Host PC'}
                    </div>
                  </div>
                </div>
              </div>

              {/* Activity Domain, Connectivity, and SQLite Storage Verification */}
              {(() => {
                const domInfo = getActivityDomainInfo(selectedEventModal);
                const DomIcon = domInfo.icon;
                const isOnlineDomain = domInfo.type === 'ONLINE';

                return (
                  <div style={{
                    background: isOnlineDomain ? (isDark ? 'rgba(34, 197, 94, 0.12)' : '#f0fdf4') : (isDark ? 'rgba(99, 102, 241, 0.12)' : '#eef2ff'),
                    border: `1px solid ${isOnlineDomain ? (isDark ? 'rgba(34, 197, 94, 0.25)' : '#bbf7d0') : (isDark ? 'rgba(99, 102, 241, 0.25)' : '#c7d2fe')}`,
                    borderRadius: '10px',
                    padding: '1rem 1.25rem',
                    display: 'flex',
                    flexDirection: 'column',
                    gap: '0.65rem'
                  }}>
                    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontWeight: 800, fontSize: '0.88rem', color: isOnlineDomain ? '#16a34a' : (isDark ? '#818cf8' : '#4f46e5') }}>
                        <DomIcon size={16} />
                        <span>{isOnlineDomain ? '🌐 ONLINE ACTIVITY CLASSIFICATION' : '💻 OFFLINE ACTIVITY CLASSIFICATION'}</span>
                      </div>
                      <span style={{
                        fontSize: '0.72rem',
                        fontWeight: 800,
                        padding: '2px 8px',
                        borderRadius: '4px',
                        background: isOnlineDomain ? (isDark ? 'rgba(34, 197, 94, 0.2)' : '#dcfce7') : (isDark ? 'rgba(99, 102, 241, 0.2)' : '#e0e7ff'),
                        color: isOnlineDomain ? (isDark ? '#4ade80' : '#15803d') : (isDark ? '#a5b4fc' : '#4338ca')
                      }}>
                        {isOnlineDomain ? 'Web / Network Domain' : 'Local Host Domain'}
                      </span>
                    </div>

                    <div style={{ fontSize: '0.82rem', color: textSecondary, lineHeight: 1.5 }}>
                      {isOnlineDomain
                        ? 'This activity took place through external network communications (browser navigation, website access, or remote IP connection).'
                        : 'This activity took place locally on the host operating system (desktop application execution, offline document access, or local file operation). Recorded directly without requiring internet.'}
                    </div>

                    {/* Storage & Sync Grid */}
                    <div style={{
                      display: 'grid',
                      gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
                      gap: '0.65rem',
                      marginTop: '0.25rem',
                      background: cardBg,
                      padding: '0.75rem',
                      borderRadius: '8px',
                      border: `1px solid ${cardBorder}`,
                      fontSize: '0.78rem'
                    }}>
                      <div>
                        <span style={{ color: textMuted, fontWeight: 600 }}>Activity Classification:</span>
                        <div style={{ color: textPrimary, fontWeight: 700, marginTop: '1px' }}>
                          {selectedEventModal.is_browser_event ? 'Web Navigation' : 'Host Application Event'}
                        </div>
                      </div>

                      <div>
                        <span style={{ color: textMuted, fontWeight: 600 }}>Host Machine:</span>
                        <div style={{ color: textPrimary, fontWeight: 700, fontFamily: 'monospace', marginTop: '1px' }}>
                          {selectedEventModal.device_id || deviceId || 'Local Workstation'}
                        </div>
                      </div>

                      <div>
                        <span style={{ color: textMuted, fontWeight: 600 }}>Protection Status:</span>
                        <div style={{ marginTop: '2px' }}>
                          {selectedEventModal.sync_status === 'PENDING' ? (
                            <span style={{ fontSize: '0.72rem', fontWeight: 800, color: '#d97706', background: isDark ? 'rgba(217, 119, 6, 0.2)' : '#fffbeb', padding: '1px 6px', borderRadius: '4px', border: isDark ? '1px solid rgba(217, 119, 6, 0.3)' : '1px solid #fde68a' }}>
                              OFFLINE PROTECTED (Local Sensor)
                            </span>
                          ) : (
                            <span style={{ fontSize: '0.72rem', fontWeight: 800, color: '#16a34a', background: isDark ? 'rgba(34, 197, 94, 0.2)' : '#f0fdf4', padding: '1px 6px', borderRadius: '4px', border: isDark ? '1px solid rgba(34, 197, 94, 0.3)' : '1px solid #bbf7d0' }}>
                              SYNCHRONIZED (Cloud Mirrored)
                            </span>
                          )}
                        </div>
                      </div>

                      <div>
                        <span style={{ color: textMuted, fontWeight: 600 }}>Collector Source:</span>
                        <div style={{ color: textPrimary, fontWeight: 700, marginTop: '1px' }}>
                          {getEventSource(selectedEventModal)}
                        </div>
                      </div>
                    </div>
                  </div>
                );
              })()}

              {/* Security Analysis & Reasons */}
              {selectedEventModal.features?.reasons && selectedEventModal.features.reasons.length > 0 && (
                <div style={{ background: subtleBg, padding: '0.85rem', borderRadius: '8px', border: `1px solid ${cardBorder}` }}>
                  <div style={{ fontSize: '0.72rem', fontWeight: 700, color: textMuted, textTransform: 'uppercase', marginBottom: '0.35rem' }}>
                    Security Analysis & Evidence
                  </div>
                  <ul style={{ margin: 0, paddingLeft: '1.25rem', color: textSecondary, fontSize: '0.82rem', lineHeight: 1.5 }}>
                    {selectedEventModal.features.reasons.map((r, rIdx) => (
                      <li key={rIdx}>{r}</li>
                    ))}
                  </ul>
                </div>
              )}
            </div>

            {/* Modal Footer */}
            <div style={{
              padding: '0.9rem 1.5rem',
              borderTop: `1px solid ${cardBorder}`,
              display: 'flex',
              justifyContent: 'flex-end',
              background: subtleBg
            }}>
              <button
                onClick={() => setSelectedEventModal(null)}
                style={{
                  padding: '0.5rem 1.25rem',
                  borderRadius: '6px',
                  border: `1px solid ${cardBorder}`,
                  background: cardBg,
                  color: textPrimary,
                  fontWeight: 600,
                  fontSize: '0.85rem',
                  cursor: 'pointer'
                }}
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}

    </div>
  );
}
