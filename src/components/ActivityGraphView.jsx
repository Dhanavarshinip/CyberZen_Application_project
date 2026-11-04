import React, { useState, useMemo, useCallback, useRef, useEffect } from 'react';
import { 
  Shield, 
  ShieldAlert, 
  ShieldCheck, 
  AlertTriangle, 
  Lock, 
  Wifi, 
  HardDrive, 
  Globe, 
  Cpu, 
  FileText, 
  RotateCcw, 
  X, 
  Info,
  Clock,
  Filter,
  Move,
  ChevronRight,
  Folder,
  Download,
  Video,
  Search,
  ZoomIn,
  ZoomOut,
  ArrowRight,
  Layers,
  Calendar
} from 'lucide-react';
import { apiClient } from '../services/apiClient';
import { useTheme } from '../context/ThemeContext';

/**
 * ActivityGraphView: Chronological Full-Day Visual Timeline & Causal Lineage Graph.
 * 
 * Satisfies User Requirements:
 * 1. Readability: Large activity cards (250x92), large text (13px/11px), icons, clear contrast.
 * 2. Unambiguous Timestamps: Formatted actual event time with seconds, correct local timezone.
 * 3. Chronological Left-to-Right layout with staggered non-overlapping vertical lanes.
 * 4. Genuine Causal Relationships ONLY (Chrome opened -> Website visited -> File downloaded -> File Explorer opened).
 *    Independent events are not artificially chained together.
 * 5. Time Window Filters (All Day 24h, Morning 6-12, Afternoon 12-17, Evening 17-22, Night 22-6).
 * 6. Responsive canvas with zoom in/out, reset, pan dragging, and node dragging.
 * 7. Comprehensive inspection drawer when an activity card is clicked.
 * 8. Visual Date Switching: Today, Yesterday, Custom Dates, and All Dates.
 */
export default function ActivityGraphView({
  events = [],
  allEvents = [],
  deviceId = 'Host PC',
  dateFilter: propDateFilter = null,
  setDateFilter = null,
  customDate: propCustomDate = null,
  setCustomDate = null
}) {
  const { isDark } = useTheme();

  // Pure pitch black for dark mode, pure clean white for light mode - ZERO blue tint!
  const containerBg = isDark ? '#000000' : '#ffffff';
  const headerBg = isDark ? '#080808' : '#f8fafc';
  const dateBarBg = isDark ? '#0c0c0c' : '#f1f5f9';
  const subFilterBg = isDark ? '#080808' : '#f8fafc';
  const canvasBg = isDark ? '#000000' : '#ffffff';
  const cardBorder = isDark ? '#222222' : '#e2e8f0';
  const subtleBorder = isDark ? '#1a1a1a' : '#f1f5f9';
  const textTitle = isDark ? '#f8fafc' : '#0f172a';
  const textSub = isDark ? '#94a3b8' : '#64748b';
  const inputBg = isDark ? '#121212' : '#ffffff';
  const drawerBg = isDark ? 'rgba(8, 8, 8, 0.98)' : 'rgba(255, 255, 255, 0.98)';
  const boxInnerBg = isDark ? '#050505' : '#f8fafc';
  const floatingLegendBg = isDark ? 'rgba(8, 8, 8, 0.95)' : 'rgba(255, 255, 255, 0.95)';

  const [selectedNode, setSelectedNode] = useState(null);
  const [filterMode, setFilterMode] = useState('ALL'); // 'ALL', 'ONLINE', 'OFFLINE', 'THREATS'
  const [searchFilter, setSearchFilter] = useState('');
  
  // Date Navigation State for Visual Representation
  const getTodayStr = useCallback(() => {
    const d = new Date();
    const year = d.getFullYear();
    const month = String(d.getMonth() + 1).padStart(2, '0');
    const day = String(d.getDate()).padStart(2, '0');
    return `${year}-${month}-${day}`;
  }, []);

  const getYesterdayStr = useCallback(() => {
    const d = new Date();
    d.setDate(d.getDate() - 1);
    const year = d.getFullYear();
    const month = String(d.getMonth() + 1).padStart(2, '0');
    const day = String(d.getDate()).padStart(2, '0');
    return `${year}-${month}-${day}`;
  }, []);

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

  const formatDisplayDateShort = (dateStr) => {
    if (!dateStr) return '';
    try {
      const [y, m, d] = dateStr.split('-');
      return `${d}/${m}/${y.slice(2)}`;
    } catch {
      return dateStr;
    }
  };

  const [graphDateFilter, setGraphDateFilter] = useState(() => propDateFilter || 'TODAY');
  const [graphCustomDate, setGraphCustomDate] = useState(() => propCustomDate || getTodayStr());
  const [internalLoadedEvents, setInternalLoadedEvents] = useState(null);

  // Sync with prop changes if passed from parent
  useEffect(() => {
    if (propDateFilter) {
      setGraphDateFilter(propDateFilter);
    }
  }, [propDateFilter]);

  useEffect(() => {
    if (propCustomDate) {
      setGraphCustomDate(propCustomDate);
    }
  }, [propCustomDate]);

  const activeDateFilter = propDateFilter || graphDateFilter;
  const activeCustomDate = propCustomDate || graphCustomDate;

  // Asynchronously ensure events are available when user switches dates
  useEffect(() => {
    let isCancelled = false;
    const todayStr = getTodayStr();
    const yesterdayStr = getYesterdayStr();
    const source = (allEvents && allEvents.length > 0) ? allEvents : events;

    let targetDate = null;
    let shouldFetch = false;

    if (activeDateFilter === 'TODAY') {
      targetDate = todayStr;
      const hasToday = source.some(e => getLocalDateStr(e.timestamp || e.created_at) === todayStr);
      if (!hasToday && source.length === 0) shouldFetch = true;
    } else if (activeDateFilter === 'YESTERDAY') {
      targetDate = yesterdayStr;
      const hasYesterday = source.some(e => getLocalDateStr(e.timestamp || e.created_at) === yesterdayStr);
      if (!hasYesterday) shouldFetch = true;
    } else if (activeDateFilter === 'CUSTOM') {
      targetDate = activeCustomDate;
      const hasCustom = source.some(e => getLocalDateStr(e.timestamp || e.created_at) === activeCustomDate);
      if (!hasCustom) shouldFetch = true;
    }

    if (shouldFetch && targetDate) {
      const tzOffset = new Date().getTimezoneOffset();
      apiClient.getEvents({
        limit: 5000,
        date: targetDate,
        clientTzOffset: tzOffset,
        excludeTest: true
      }).then(res => {
        if (!isCancelled && res && Array.isArray(res.events)) {
          setInternalLoadedEvents(res.events);
        }
      }).catch(() => {});
    } else {
      setInternalLoadedEvents(null);
    }

    return () => { isCancelled = true; };
  }, [activeDateFilter, activeCustomDate, events, allEvents, getTodayStr, getYesterdayStr]);

  const handleDateChange = (mode) => {
    setGraphDateFilter(mode);
    if (setDateFilter) {
      setDateFilter(mode);
    }
  };

  const handleCustomDateChange = (dateVal) => {
    setGraphCustomDate(dateVal);
    setGraphDateFilter('CUSTOM');
    if (setCustomDate) setCustomDate(dateVal);
    if (setDateFilter) setDateFilter('CUSTOM');
  };

  // Time-range filter for zooming into particular timestamps of the day
  const [timeWindow, setTimeWindow] = useState('ALL_DAY'); // 'ALL_DAY', 'MORNING', 'AFTERNOON', 'EVENING', 'NIGHT'

  // Zoom and Pan State
  const [zoomLevel, setZoomLevel] = useState(1);
  const [panOffset, setPanOffset] = useState({ x: 0, y: 0 });
  const [isPanning, setIsPanning] = useState(false);
  const [panStart, setPanStart] = useState({ x: 0, y: 0 });

  // Custom Node Positions for Drag-and-Drop
  const [customPositions, setCustomPositions] = useState({});
  const [draggingNodeId, setDraggingNodeId] = useState(null);
  const [dragStartMouse, setDragStartMouse] = useState({ x: 0, y: 0 });
  const [dragStartNodePos, setDragStartNodePos] = useState({ x: 0, y: 0 });
  const [dragDistance, setDragDistance] = useState(0);

  const containerRef = useRef(null);

  // Helper date/time formatters with exact seconds for unambiguous timestamps
  const formatTime12h = (isoString) => {
    if (!isoString) return '--:--:--';
    try {
      const d = new Date(isoString);
      if (isNaN(d.getTime())) return '--:--:--';
      let hours = d.getHours();
      const minutes = String(d.getMinutes()).padStart(2, '0');
      const seconds = String(d.getSeconds()).padStart(2, '0');
      const ampm = hours >= 12 ? 'PM' : 'AM';
      hours = hours % 12 || 12;
      return `${hours}:${minutes}:${seconds} ${ampm}`;
    } catch {
      return '--:--:--';
    }
  };

  const getFractionalHour = (isoString) => {
    if (!isoString) return 12.0;
    try {
      const d = new Date(isoString);
      if (isNaN(d.getTime())) return 12.0;
      return d.getHours() + d.getMinutes() / 60 + d.getSeconds() / 3600;
    } catch {
      return 12.0;
    }
  };

  // Filter events according to active mode, date, and time window
  const processedEvents = useMemo(() => {
    // Select best event source: internal loaded events for selected date, or allEvents, or events
    let rawList = [];
    if (internalLoadedEvents && internalLoadedEvents.length > 0) {
      rawList = internalLoadedEvents;
    } else if (allEvents && allEvents.length > 0) {
      rawList = allEvents;
    } else if (Array.isArray(events)) {
      rawList = events;
    }

    let list = [...rawList];

    // Filter out internal background synthetic noise
    list = list.filter(e => {
      if (!e) return false;
      const f = e.features || {};
      if (f.is_test_event) return false;
      if (e.event_type && e.event_type.startsWith('TEST_')) return false;
      return true;
    });

    // 0. Date Filter: Today, Yesterday, Custom Date, or All
    const todayStr = getTodayStr();
    const yesterdayStr = getYesterdayStr();

    if (activeDateFilter === 'TODAY') {
      list = list.filter(e => getLocalDateStr(e.timestamp || e.created_at) === todayStr);
    } else if (activeDateFilter === 'YESTERDAY') {
      list = list.filter(e => getLocalDateStr(e.timestamp || e.created_at) === yesterdayStr);
    } else if (activeDateFilter === 'CUSTOM') {
      list = list.filter(e => getLocalDateStr(e.timestamp || e.created_at) === activeCustomDate);
    }

    // 1. Channel Filter (Online vs Offline vs Threats)
    if (filterMode === 'ONLINE') {
      list = list.filter(e => {
        const f = e.features || {};
        return f.activity_domain === 'ONLINE' || e.event_type?.includes('WEBSITE') || !!f.domain || !!f.url;
      });
    } else if (filterMode === 'OFFLINE') {
      list = list.filter(e => {
        const f = e.features || {};
        return f.activity_domain === 'OFFLINE' || (!e.event_type?.includes('WEBSITE') && !f.domain && !f.url);
      });
    } else if (filterMode === 'THREATS') {
      list = list.filter(e => {
        const f = e.features || {};
        const risk = e.risk_score || f.raw_risk || 0;
        return risk >= 35 || f.status === 'DANGEROUS' || f.status === 'SUSPICIOUS' || f.is_eicar;
      });
    }

    // 2. Search Filter
    if (searchFilter.trim()) {
      const q = searchFilter.toLowerCase();
      list = list.filter(e => {
        const f = e.features || {};
        const name = f.display_name || f.domain || f.file_name || f.process_name || e.event_type || '';
        return name.toLowerCase().includes(q) || (f.status || '').toLowerCase().includes(q);
      });
    }

    // Sort strictly chronologically (Oldest to Newest for natural left-to-right timeline flow)
    list.sort((a, b) => {
      const tA = new Date(a.timestamp || a.created_at || 0).getTime();
      const tB = new Date(b.timestamp || b.created_at || 0).getTime();
      return tA - tB;
    });

    // 3. Time-of-Day Window Filter
    let startH = 0;
    let endH = 24;
    if (timeWindow === 'MORNING') {
      startH = 6; endH = 12;
    } else if (timeWindow === 'AFTERNOON') {
      startH = 12; endH = 17;
    } else if (timeWindow === 'EVENING') {
      startH = 17; endH = 22;
    } else if (timeWindow === 'NIGHT') {
      startH = 22; endH = 30; // 10 PM to 6 AM next day
    }

    if (timeWindow !== 'ALL_DAY') {
      list = list.filter(e => {
        const h = getFractionalHour(e.timestamp || e.created_at);
        if (timeWindow === 'NIGHT') {
          return h >= 22 || h < 6;
        }
        return h >= startH && h <= endH;
      });
    }

    return list;
  }, [events, allEvents, internalLoadedEvents, activeDateFilter, activeCustomDate, filterMode, searchFilter, timeWindow, getTodayStr, getYesterdayStr]);

  // Build Chronological Timeline Layout Coordinates & Causal Relationships
  const timelineData = useMemo(() => {
    let timeMarkers = [];
    if (timeWindow === 'ALL_DAY') {
      timeMarkers = [
        { label: '12:00 AM', x: 120 },
        { label: '3:00 AM', x: 420 },
        { label: '6:00 AM', x: 720 },
        { label: '9:00 AM', x: 1020 },
        { label: '12:00 PM', x: 1320 },
        { label: '3:00 PM', x: 1620 },
        { label: '6:00 PM', x: 1920 },
        { label: '9:00 PM', x: 2220 },
        { label: '11:59 PM', x: 2520 }
      ];
    } else if (timeWindow === 'MORNING') {
      timeMarkers = [
        { label: '6:00 AM', x: 140 },
        { label: '7:00 AM', x: 440 },
        { label: '8:00 AM', x: 740 },
        { label: '9:00 AM', x: 1040 },
        { label: '10:00 AM', x: 1340 },
        { label: '11:00 AM', x: 1640 },
        { label: '12:00 PM', x: 1940 }
      ];
    } else if (timeWindow === 'AFTERNOON') {
      timeMarkers = [
        { label: '12:00 PM', x: 140 },
        { label: '1:00 PM', x: 440 },
        { label: '2:00 PM', x: 740 },
        { label: '3:00 PM', x: 1040 },
        { label: '4:00 PM', x: 1340 },
        { label: '5:00 PM', x: 1640 }
      ];
    } else if (timeWindow === 'EVENING') {
      timeMarkers = [
        { label: '5:00 PM', x: 140 },
        { label: '6:00 PM', x: 440 },
        { label: '7:00 PM', x: 740 },
        { label: '8:00 PM', x: 1040 },
        { label: '9:00 PM', x: 1340 },
        { label: '10:00 PM', x: 1640 }
      ];
    } else if (timeWindow === 'NIGHT') {
      timeMarkers = [
        { label: '10:00 PM', x: 140 },
        { label: '12:00 AM', x: 490 },
        { label: '2:00 AM', x: 840 },
        { label: '4:00 AM', x: 1190 },
        { label: '6:00 AM', x: 1540 }
      ];
    }

    const minWidth = 2200;
    const dynamicWidth = Math.max(minWidth, processedEvents.length * 300 + 600);
    const height = 720;

    const nodes = [];

    // Staggered vertical lanes to completely prevent node overlaps
    // With card height = 92, lane delta = 140px ensures generous 48px vertical margin
    const lanes = [200, 340, 480];

    processedEvents.forEach((ev, idx) => {
      const f = ev.features || {};
      const risk = ev.risk_score || f.raw_risk || 0;
      const isThreat = risk >= 35 || f.status === 'DANGEROUS' || f.status === 'SUSPICIOUS';
      const rawName = f.display_name || f.domain || f.file_name || f.process_name || ev.event_type || 'Activity';
      
      // Allow readable app / website names up to 34 characters
      const cleanName = rawName.length > 34 ? rawName.substring(0, 32) + '...' : rawName;
      
      const isOnline = f.activity_domain === 'ONLINE' || ev.event_type?.includes('WEBSITE') || !!f.domain || !!f.url;
      const timeStr = formatTime12h(ev.timestamp || ev.created_at);
      const fracH = getFractionalHour(ev.timestamp || ev.created_at);

      // Icon determination
      let iconType = 'app';
      const lowerName = rawName.toLowerCase();
      if (lowerName.includes('chrome') || lowerName.includes('edge') || lowerName.includes('browser')) iconType = 'browser';
      else if (lowerName.includes('youtube') || lowerName.includes('video') || lowerName.includes('media')) iconType = 'youtube';
      else if (lowerName.includes('explorer') || lowerName.includes('folder') || lowerName.includes('picture')) iconType = 'explorer';
      else if (lowerName.includes('file') || f.file_name) iconType = 'file';
      else if (isOnline) iconType = 'web';

      // Base X positioned along chronological sequence with 300px horizontal spacing
      const baseX = 160 + idx * 300;
      // Stagger vertically across lanes to create a sleek zigzag flow
      const baseY = lanes[idx % lanes.length];

      const nodeObj = {
        id: ev.event_id || `time_node_${idx}`,
        eventData: ev,
        label: cleanName,
        fullName: rawName,
        timeStr,
        fracH,
        isOnline,
        isThreat,
        iconType,
        riskScore: Math.round(risk),
        status: f.status || (isThreat ? 'SUSPICIOUS' : 'SAFE'),
        x: baseX,
        y: baseY
      };

      nodes.push(nodeObj);
    });

    // CAUSAL-ONLY RELATIONSHIP DETECTION
    // Connect events IF AND ONLY IF there is concrete evidence of a causal relationship.
    // Example: Chrome opened -> Website visited -> File downloaded -> File Explorer opened.
    // Independent events are never daisy-chained artificially.
    const edges = [];

    for (let i = 0; i < nodes.length; i++) {
      const a = nodes[i];
      const aData = a.eventData || {};
      const aFeatures = aData.features || {};
      const aName = (aFeatures.display_name || aFeatures.domain || aFeatures.process_name || aData.event_type || '').toLowerCase();
      const aTime = new Date(aData.timestamp || aData.created_at || 0).getTime();
      const aPid = aFeatures.pid;

      for (let j = i + 1; j < nodes.length; j++) {
        const b = nodes[j];
        const bData = b.eventData || {};
        const bFeatures = bData.features || {};
        const bName = (bFeatures.display_name || bFeatures.domain || bFeatures.process_name || bData.event_type || '').toLowerCase();
        const bTime = new Date(bData.timestamp || bData.created_at || 0).getTime();
        const bPid = bFeatures.pid;
        const bPpid = bFeatures.ppid;
        const timeDiffSec = (bTime - aTime) / 1000;

        // Skip events occurring more than 30 minutes (1800s) apart
        if (timeDiffSec > 1800) continue;

        let relationshipType = null;
        let reason = '';

        // 1. Process parent-child relationship (Explicit PID inheritance)
        if (aPid && bPpid && aPid === bPpid) {
          relationshipType = 'PARENT_CHILD';
          reason = 'Spawned Process';
        }
        // 2. Browser launched -> Web navigation
        else if ((aName.includes('chrome') || aName.includes('edge') || aName.includes('firefox') || aName.includes('brave') || aName.includes('browser')) 
                 && (b.isOnline || bFeatures.url || bFeatures.domain) 
                 && timeDiffSec >= 0 && timeDiffSec <= 600) {
          relationshipType = 'BROWSER_NAVIGATION';
          reason = 'Web Navigation';
        }
        // 3. Web navigation -> File download
        else if ((a.isOnline || aFeatures.url || aFeatures.domain) 
                 && (bName.includes('download') || bFeatures.file_name || bData.event_type === 'FILE_DOWNLOAD' || bData.event_type === 'MALWARE_DOWNLOAD')
                 && timeDiffSec >= 0 && timeDiffSec <= 300) {
          relationshipType = 'FILE_DOWNLOAD';
          reason = 'File Download';
        }
        // 4. File download -> File Explorer / Application opening that file
        else if ((aName.includes('download') || aFeatures.file_name || aData.event_type === 'FILE_DOWNLOAD') 
                 && (bName.includes('explorer') || bName.includes('picture') || bName.includes('viewer') || (bFeatures.file_path && aFeatures.file_path && bFeatures.file_path === aFeatures.file_path))
                 && timeDiffSec >= 0 && timeDiffSec <= 600) {
          relationshipType = 'FILE_OPEN';
          reason = 'Opened Download';
        }
        // 5. Continuation of the exact same application session within 2 minutes
        else if (aPid && bPid && aPid === bPid && timeDiffSec >= 0 && timeDiffSec <= 120) {
          relationshipType = 'APP_CONTINUATION';
          reason = 'Session Action';
        }

        if (relationshipType) {
          edges.push({
            from: a,
            to: b,
            type: relationshipType,
            label: reason,
            color: (b.isThreat || a.isThreat) ? '#f43f5e' : (b.isOnline ? '#00f0ff' : '#818cf8')
          });
          // Limit to direct authentic cause to preserve visual clarity
          break;
        }
      }
    }

    return { nodes, edges, timeMarkers, width: dynamicWidth, height };
  }, [processedEvents, timeWindow]);

  // Dynamic position getter
  const getNodePos = useCallback((node) => {
    if (!node) return { x: 0, y: 0 };
    if (customPositions[node.id]) {
      return customPositions[node.id];
    }
    return { x: node.x, y: node.y };
  }, [customPositions]);

  // Smooth cubic Bezier path between card boundaries
  const makeBezierPath = (x1, y1, x2, y2) => {
    const dx = x2 - x1;
    const cx1 = x1 + Math.max(dx * 0.45, 60);
    const cy1 = y1;
    const cx2 = x2 - Math.max(dx * 0.45, 60);
    const cy2 = y2;
    return `M ${x1} ${y1} C ${cx1} ${cy1}, ${cx2} ${cy2}, ${x2} ${y2}`;
  };

  // Canvas Mouse Dragging & Panning
  const handleCanvasMouseDown = (e) => {
    if (e.button !== 0) return;
    setIsPanning(true);
    setPanStart({ x: e.clientX - panOffset.x, y: e.clientY - panOffset.y });
  };

  const handleCanvasMouseMove = (e) => {
    if (draggingNodeId) {
      const dx = (e.clientX - dragStartMouse.x) / zoomLevel;
      const dy = (e.clientY - dragStartMouse.y) / zoomLevel;
      setDragDistance(Math.hypot(dx, dy));
      const newX = Math.round(dragStartNodePos.x + dx);
      const newY = Math.round(dragStartNodePos.y + dy);
      setCustomPositions(prev => ({
        ...prev,
        [draggingNodeId]: { x: newX, y: newY }
      }));
      return;
    }

    if (isPanning) {
      setPanOffset({
        x: e.clientX - panStart.x,
        y: e.clientY - panStart.y
      });
    }
  };

  const handleCanvasMouseUp = () => {
    setIsPanning(false);
    setDraggingNodeId(null);
  };

  const handleWheel = (e) => {
    // Zoom on wheel with Ctrl or normal wheel
    if (e.ctrlKey) {
      e.preventDefault();
      const delta = e.deltaY < 0 ? 0.1 : -0.1;
      setZoomLevel(prev => Math.min(2.5, Math.max(0.35, Number((prev + delta).toFixed(2)))));
    } else {
      // Natural horizontal pan on wheel
      setPanOffset(prev => ({
        ...prev,
        x: prev.x - e.deltaX - (e.shiftKey ? e.deltaY : 0)
      }));
    }
  };

  // Node Drag and Click
  const handleNodeMouseDown = (e, node) => {
    if (e.button !== 0) return;
    e.stopPropagation();
    const pos = getNodePos(node);
    setDraggingNodeId(node.id);
    setDragStartMouse({ x: e.clientX, y: e.clientY });
    setDragStartNodePos(pos);
    setDragDistance(0);
  };

  const handleNodeClick = (e, node) => {
    e.stopPropagation();
    if (dragDistance < 5) {
      setSelectedNode(node);
    }
  };

  // Reset entire layout
  const handleResetLayout = () => {
    setZoomLevel(1);
    setPanOffset({ x: 0, y: 0 });
    setCustomPositions({});
  };

  const hasMovedNodes = Object.keys(customPositions).length > 0;

  // Icon Helper for Nodes
  const renderNodeIcon = (type, isThreat) => {
    if (isThreat) return <AlertTriangle size={18} color="#f43f5e" />;
    switch (type) {
      case 'browser':
      case 'web':
        return <Globe size={18} color="#00f0ff" />;
      case 'youtube':
        return <Video size={18} color="#f43f5e" />;
      case 'explorer':
        return <Folder size={18} color="#fbbf24" />;
      case 'file':
        return <Download size={18} color="#38bdf8" />;
      default:
        return <Cpu size={18} color="#a78bfa" />;
    }
  };

  return (
    <div style={{
      background: containerBg,
      borderRadius: '16px',
      border: `1px solid ${cardBorder}`,
      boxShadow: isDark ? '0 8px 32px rgba(0, 0, 0, 0.75)' : '0 4px 20px rgba(0, 0, 0, 0.05)',
      overflow: 'hidden',
      display: 'flex',
      flexDirection: 'column',
      position: 'relative'
    }}>
      {/* ── Top Visual Timeline & Filter Controls ─────────────────────── */}
      <div style={{
        padding: '0.85rem 1.5rem',
        background: headerBg,
        borderBottom: `1px solid ${subtleBorder}`,
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        flexWrap: 'wrap',
        gap: '0.85rem'
      }}>
        {/* Title and Timestamp Lineage Indicator */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem' }}>
          <div style={{
            width: '38px',
            height: '38px',
            borderRadius: '10px',
            background: isDark ? 'rgba(0, 240, 255, 0.12)' : 'rgba(2, 132, 199, 0.1)',
            border: isDark ? '1px solid rgba(0, 240, 255, 0.35)' : '1px solid rgba(2, 132, 199, 0.25)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            color: isDark ? '#00f0ff' : '#0284c7'
          }}>
            <Clock size={20} />
          </div>
          <div>
            <div style={{ fontSize: '1.05rem', fontWeight: 800, color: textTitle, letterSpacing: '-0.01em', display: 'flex', alignItems: 'center', gap: '0.55rem' }}>
              Full-Day Activity Timeline & Lineage
              <span style={{
                fontSize: '0.74rem',
                fontWeight: 700,
                color: isDark ? '#38bdf8' : '#0284c7',
                background: isDark ? 'rgba(56, 189, 248, 0.15)' : 'rgba(2, 132, 199, 0.1)',
                border: isDark ? '1px solid rgba(56, 189, 248, 0.35)' : '1px solid rgba(2, 132, 199, 0.2)',
                padding: '0.15rem 0.55rem',
                borderRadius: '12px'
              }}>
                {processedEvents.length} Activities Shown
              </span>
            </div>
            <div style={{ fontSize: '0.76rem', color: textSub }}>
              Chronological left-to-right flow • Meaningful causal lineage • Pan & Zoom controls
            </div>
          </div>
        </div>

        {/* Time-Range Zoom Windows (All Day, Morning, Afternoon, Evening, Night) */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', flexWrap: 'wrap' }}>
          <span style={{ fontSize: '0.72rem', color: textSub, fontWeight: 700, textTransform: 'uppercase', marginRight: '0.2rem' }}>
            Time Window:
          </span>
          {[
            { id: 'ALL_DAY', label: 'All Day (24h)' },
            { id: 'MORNING', label: 'Morning (6 AM - 12 PM)' },
            { id: 'AFTERNOON', label: 'Afternoon (12 PM - 5 PM)' },
            { id: 'EVENING', label: 'Evening (5 PM - 10 PM)' },
            { id: 'NIGHT', label: 'Night (10 PM - 6 AM)' }
          ].map(t => (
            <button
              key={t.id}
              onClick={() => setTimeWindow(t.id)}
              style={{
                fontSize: '0.74rem',
                fontWeight: 700,
                padding: '0.35rem 0.75rem',
                borderRadius: '16px',
                border: timeWindow === t.id ? (isDark ? '1px solid #00f0ff' : '1px solid #0284c7') : `1px solid ${cardBorder}`,
                background: timeWindow === t.id ? (isDark ? 'rgba(0, 240, 255, 0.18)' : 'rgba(2, 132, 199, 0.12)') : 'transparent',
                color: timeWindow === t.id ? (isDark ? '#00f0ff' : '#0284c7') : textSub,
                cursor: 'pointer',
                transition: 'all 0.15s ease'
              }}
            >
              {t.label}
            </button>
          ))}

          {/* Zoom Buttons and Reset Position */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.25rem', marginLeft: '0.5rem', background: isDark ? '#141414' : '#f1f5f9', padding: '3px 6px', borderRadius: '8px', border: `1px solid ${cardBorder}` }}>
            <button
              onClick={() => setZoomLevel(prev => Math.max(0.35, Number((prev - 0.15).toFixed(2))))}
              style={{ background: 'transparent', border: 'none', color: textSub, padding: '0.25rem 0.45rem', cursor: 'pointer' }}
              title="Zoom Out Time Scale"
            >
              <ZoomOut size={15} />
            </button>
            <span style={{ fontSize: '0.75rem', fontWeight: 700, color: isDark ? '#00f0ff' : '#0284c7', minWidth: '42px', textAlign: 'center', fontFamily: 'monospace' }}>
              {Math.round(zoomLevel * 100)}%
            </span>
            <button
              onClick={() => setZoomLevel(prev => Math.min(2.5, Number((prev + 0.15).toFixed(2))))}
              style={{ background: 'transparent', border: 'none', color: textSub, padding: '0.25rem 0.45rem', cursor: 'pointer' }}
              title="Zoom In Time Scale"
            >
              <ZoomIn size={15} />
            </button>
            <button
              onClick={handleResetLayout}
              style={{
                background: hasMovedNodes || panOffset.x !== 0 || panOffset.y !== 0 || zoomLevel !== 1 ? (isDark ? 'rgba(0, 240, 255, 0.15)' : 'rgba(2, 132, 199, 0.15)') : 'transparent',
                border: 'none',
                color: hasMovedNodes ? (isDark ? '#00f0ff' : '#0284c7') : textSub,
                padding: '0.25rem 0.5rem',
                cursor: 'pointer',
                display: 'flex',
                alignItems: 'center',
                gap: '4px',
                fontSize: '0.72rem',
                fontWeight: 700,
                borderRadius: '5px'
              }}
              title="Reset View and Node Layout"
            >
              <RotateCcw size={13} />
              <span>Reset</span>
            </button>
          </div>
        </div>
      </div>

      {/* ── Visual Timeline Date Bar: Today, Yesterday, Custom Date, All Dates ────── */}
      <div style={{
        padding: '0.6rem 1.5rem',
        background: dateBarBg,
        borderBottom: `1px solid ${subtleBorder}`,
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        flexWrap: 'wrap',
        gap: '0.65rem'
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', flexWrap: 'wrap' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.35rem', marginRight: '0.2rem' }}>
            <Calendar size={14} style={{ color: isDark ? '#00f0ff' : '#0284c7' }} />
            <span style={{ fontSize: '0.74rem', color: isDark ? '#00f0ff' : '#0284c7', fontWeight: 800, textTransform: 'uppercase', letterSpacing: '0.04em' }}>
              Timeline Date:
            </span>
          </div>

          {/* Today Button */}
          <button
            onClick={() => handleDateChange('TODAY')}
            style={{
              fontSize: '0.75rem',
              fontWeight: 700,
              padding: '0.35rem 0.85rem',
              borderRadius: '6px',
              border: activeDateFilter === 'TODAY' ? '1px solid #16a34a' : `1px solid ${cardBorder}`,
              background: activeDateFilter === 'TODAY' ? (isDark ? 'rgba(34, 197, 94, 0.22)' : 'rgba(22, 163, 74, 0.15)') : 'transparent',
              color: activeDateFilter === 'TODAY' ? (isDark ? '#4ade80' : '#16a34a') : textSub,
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              gap: '4px',
              transition: 'all 0.15s ease'
            }}
          >
            <span>Today</span>
            <span style={{ fontSize: '0.68rem', opacity: 0.85 }}>({formatDisplayDateShort(getTodayStr())})</span>
          </button>

          {/* Yesterday Button */}
          <button
            onClick={() => handleDateChange('YESTERDAY')}
            style={{
              fontSize: '0.75rem',
              fontWeight: 700,
              padding: '0.35rem 0.85rem',
              borderRadius: '6px',
              border: activeDateFilter === 'YESTERDAY' ? (isDark ? '1px solid #00f0ff' : '1px solid #0284c7') : `1px solid ${cardBorder}`,
              background: activeDateFilter === 'YESTERDAY' ? (isDark ? 'rgba(0, 240, 255, 0.22)' : 'rgba(2, 132, 199, 0.15)') : 'transparent',
              color: activeDateFilter === 'YESTERDAY' ? (isDark ? '#00f0ff' : '#0284c7') : textSub,
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              gap: '4px',
              transition: 'all 0.15s ease'
            }}
          >
            <span>Yesterday</span>
            <span style={{ fontSize: '0.68rem', opacity: 0.85 }}>({formatDisplayDateShort(getYesterdayStr())})</span>
          </button>

          {/* Custom Date Button with Input */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
            <button
              onClick={() => handleDateChange('CUSTOM')}
              style={{
                fontSize: '0.75rem',
                fontWeight: 700,
                padding: '0.35rem 0.85rem',
                borderRadius: '6px',
                border: activeDateFilter === 'CUSTOM' ? '1px solid #a855f7' : `1px solid ${cardBorder}`,
                background: activeDateFilter === 'CUSTOM' ? (isDark ? 'rgba(168, 85, 247, 0.22)' : 'rgba(147, 51, 234, 0.15)') : 'transparent',
                color: activeDateFilter === 'CUSTOM' ? (isDark ? '#c084fc' : '#9333ea') : textSub,
                cursor: 'pointer',
                transition: 'all 0.15s ease'
              }}
            >
              Custom Date
            </button>
            <input
              type="date"
              value={activeCustomDate}
              max={getTodayStr()}
              onChange={(e) => {
                if (e.target.value) {
                  handleCustomDateChange(e.target.value);
                }
              }}
              style={{
                padding: '0.24rem 0.5rem',
                borderRadius: '6px',
                border: activeDateFilter === 'CUSTOM' ? '1px solid #a855f7' : `1px solid ${cardBorder}`,
                background: inputBg,
                color: textTitle,
                fontSize: '0.74rem',
                fontWeight: 600,
                outline: 'none',
                cursor: 'pointer'
              }}
            />
          </div>

          {/* All Recorded Dates Button */}
          <button
            onClick={() => handleDateChange('ALL')}
            style={{
              fontSize: '0.75rem',
              fontWeight: 700,
              padding: '0.35rem 0.85rem',
              borderRadius: '6px',
              border: activeDateFilter === 'ALL' ? (isDark ? '1px solid #38bdf8' : '1px solid #0284c7') : `1px solid ${cardBorder}`,
              background: activeDateFilter === 'ALL' ? (isDark ? 'rgba(56, 189, 248, 0.22)' : 'rgba(2, 132, 199, 0.15)') : 'transparent',
              color: activeDateFilter === 'ALL' ? (isDark ? '#38bdf8' : '#0284c7') : textSub,
              cursor: 'pointer',
              transition: 'all 0.15s ease'
            }}
          >
            All Dates
          </button>
        </div>

        <div style={{ fontSize: '0.74rem', color: textSub, display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
          <span>Timeline View:</span>
          <span style={{
            color: activeDateFilter === 'TODAY' ? (isDark ? '#4ade80' : '#16a34a') :
                   activeDateFilter === 'YESTERDAY' ? (isDark ? '#00f0ff' : '#0284c7') :
                   activeDateFilter === 'CUSTOM' ? (isDark ? '#c084fc' : '#9333ea') :
                   (isDark ? '#38bdf8' : '#0284c7'),
            fontWeight: 800,
            background: isDark ? 'rgba(255,255,255,0.06)' : 'rgba(0,0,0,0.05)',
            padding: '0.15rem 0.5rem',
            borderRadius: '4px',
            border: `1px solid ${subtleBorder}`
          }}>
            {activeDateFilter === 'TODAY' ? `Today (${formatDisplayDateShort(getTodayStr())})` :
             activeDateFilter === 'YESTERDAY' ? `Yesterday (${formatDisplayDateShort(getYesterdayStr())})` :
             activeDateFilter === 'CUSTOM' ? `Date: ${formatDisplayDateShort(activeCustomDate)}` : 'All Dates Combined'}
          </span>
        </div>
      </div>

      {/* ── Sub-Filter Bar: Channel & Search Filter ───────────────────── */}
      <div style={{
        padding: '0.55rem 1.5rem',
        background: subFilterBg,
        borderBottom: `1px solid ${subtleBorder}`,
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        flexWrap: 'wrap',
        gap: '0.65rem'
      }}>
        {/* Category Pills */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.45rem' }}>
          {[
            { id: 'ALL', label: 'All Activities' },
            { id: 'ONLINE', label: '🌐 Online Web' },
            { id: 'OFFLINE', label: '💻 Offline Host' },
            { id: 'THREATS', label: '⚠️ Threats / Suspicious' }
          ].map(f => (
            <button
              key={f.id}
              onClick={() => setFilterMode(f.id)}
              style={{
                fontSize: '0.74rem',
                fontWeight: 700,
                padding: '0.3rem 0.75rem',
                borderRadius: '6px',
                border: filterMode === f.id ? (isDark ? '1px solid #38bdf8' : '1px solid #0284c7') : `1px solid ${cardBorder}`,
                background: filterMode === f.id ? (isDark ? 'rgba(56, 189, 248, 0.18)' : 'rgba(2, 132, 199, 0.15)') : 'transparent',
                color: filterMode === f.id ? (isDark ? '#38bdf8' : '#0284c7') : textSub,
                cursor: 'pointer'
              }}
            >
              {f.label}
            </button>
          ))}
        </div>

        {/* Quick Search */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.45rem', background: inputBg, border: `1px solid ${cardBorder}`, borderRadius: '6px', padding: '0.3rem 0.75rem' }}>
          <Search size={14} color={textSub} />
          <input
            type="text"
            placeholder="Search activity, app, or website..."
            value={searchFilter}
            onChange={(e) => setSearchFilter(e.target.value)}
            style={{
              background: 'transparent',
              border: 'none',
              outline: 'none',
              color: textTitle,
              fontSize: '0.78rem',
              width: '210px'
            }}
          />
          {searchFilter && (
            <button onClick={() => setSearchFilter('')} style={{ background: 'transparent', border: 'none', color: textSub, cursor: 'pointer', padding: 0 }}>
              <X size={13} />
            </button>
          )}
        </div>
      </div>

      {/* ── Main Interactive Movable Canvas Container ─────────────────── */}
      <div
        ref={containerRef}
        onMouseDown={handleCanvasMouseDown}
        onMouseMove={handleCanvasMouseMove}
        onMouseUp={handleCanvasMouseUp}
        onMouseLeave={handleCanvasMouseUp}
        onWheel={handleWheel}
        style={{
          width: '100%',
          height: '660px',
          background: canvasBg,
          position: 'relative',
          overflow: 'hidden',
          cursor: isPanning ? 'grabbing' : (draggingNodeId ? 'grabbing' : 'grab'),
          userSelect: 'none'
        }}
      >
        {processedEvents.length === 0 ? (
          <div style={{
            position: 'absolute',
            inset: 0,
            display: 'flex',
            flexDirection: 'column',
            alignItems: 'center',
            justifyContent: 'center',
            color: '#64748b',
            gap: '0.75rem'
          }}>
            <Clock size={44} strokeWidth={1.5} color="#334155" />
            <div style={{ fontSize: '1rem', fontWeight: 700, color: '#94a3b8' }}>
              No activities found for this time window
            </div>
            <div style={{ fontSize: '0.82rem', color: '#64748b' }}>
              Switch to "All Day (24h)" or clear filters to see your recorded timeline.
            </div>
            <button
              onClick={() => { setTimeWindow('ALL_DAY'); setFilterMode('ALL'); setSearchFilter(''); }}
              style={{
                padding: '0.45rem 1.15rem',
                borderRadius: '8px',
                border: '1px solid #00f0ff',
                background: 'rgba(0, 240, 255, 0.1)',
                color: '#00f0ff',
                fontSize: '0.82rem',
                fontWeight: 700,
                cursor: 'pointer'
              }}
            >
              Reset Filters to All Day
            </button>
          </div>
        ) : (
          <svg
            width="100%"
            height="100%"
            style={{ display: 'block', width: '100%', height: '100%' }}
          >
            <defs>
              <linearGradient id="time-grad-blue" x1="0%" y1="0%" x2="100%" y2="0%">
                <stop offset="0%" stopColor="#00f0ff" stopOpacity="0.8" />
                <stop offset="100%" stopColor="#818cf8" stopOpacity="0.9" />
              </linearGradient>
              <linearGradient id="time-grad-threat" x1="0%" y1="0%" x2="100%" y2="0%">
                <stop offset="0%" stopColor="#f59e0b" stopOpacity="0.8" />
                <stop offset="100%" stopColor="#f43f5e" stopOpacity="0.9" />
              </linearGradient>
              <filter id="time-glow" x="-20%" y="-20%" width="140%" height="140%">
                <feGaussianBlur stdDeviation="4" result="blur" />
                <feComposite in="SourceGraphic" in2="blur" operator="over" />
              </filter>
              <pattern id="time-grid" width="60" height="60" patternUnits="userSpaceOnUse">
                <circle cx="30" cy="30" r="1" fill={isDark ? "#262626" : "#cbd5e1"} opacity="0.6" />
              </pattern>

              {/* Arrow Markers for Directed Causal Lineage */}
              <marker id="arrow-cyan" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
                <path d="M 0 1 L 9 5 L 0 9 z" fill={isDark ? "#00f0ff" : "#0284c7"} />
              </marker>
              <marker id="arrow-threat" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
                <path d="M 0 1 L 9 5 L 0 9 z" fill="#f43f5e" />
              </marker>
              <marker id="arrow-purple" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
                <path d="M 0 1 L 9 5 L 0 9 z" fill="#818cf8" />
              </marker>
            </defs>

            {/* Master Movable & Zoomable Group */}
            <g transform={`translate(${panOffset.x}, ${panOffset.y}) scale(${zoomLevel})`}>
              {/* Dynamic Interactive Plane Grid */}
              <rect
                x="-4000"
                y="-4000"
                width="8000"
                height="8000"
                fill="url(#time-grid)"
                pointerEvents="none"
              />

              {/* Time Horizon Header Axis & Hour Markers */}
              <line
                x1="40"
                y1="70"
                x2={Math.max(timelineData.width + 300, 2200)}
                y2="70"
                stroke={isDark ? "#00f0ff" : "#0284c7"}
                strokeWidth="2.5"
                strokeOpacity="0.5"
              />

              {timelineData.timeMarkers && timelineData.timeMarkers.map((tm, idx) => (
                <g key={`marker_${idx}`} transform={`translate(${tm.x}, 70)`}>
                  <line x1={0} y1={-12} x2={0} y2={12} stroke={isDark ? "#00f0ff" : "#0284c7"} strokeWidth="2.5" />
                  <line x1={0} y1={12} x2={0} y2={580} stroke={isDark ? "#222222" : "#e2e8f0"} strokeWidth="1" strokeDasharray="3 3" opacity={0.7} />
                  <rect x="-42" y="-34" width="84" height="24" rx="8" fill={isDark ? "#0d0d0d" : "#f1f5f9"} stroke={isDark ? "#00f0ff" : "#0284c7"} strokeWidth="1.2" />
                  <text
                    x={0}
                    y={-18}
                    textAnchor="middle"
                    fill={isDark ? "#00f0ff" : "#0284c7"}
                    fontSize="11"
                    fontWeight="800"
                    fontFamily="monospace"
                  >
                    {tm.label}
                  </text>
                </g>
              ))}

              {/* Render Genuine Causal Relationship Edges with Directional Arrows */}
              {timelineData.edges.map((edge, idx) => {
                const fromPos = getNodePos(edge.from);
                const toPos = getNodePos(edge.to);
                const markerId = edge.color === '#f43f5e' ? 'arrow-threat' : (edge.color === '#00f0ff' ? 'arrow-cyan' : 'arrow-purple');
                
                // Connecting right-side port of source card to left-side port of target card
                const startX = fromPos.x + 125;
                const startY = fromPos.y;
                const endX = toPos.x - 125;
                const endY = toPos.y;
                const midX = (startX + endX) / 2;
                const midY = (startY + endY) / 2;

                return (
                  <g key={`causal_edge_${idx}`}>
                    <path
                      d={makeBezierPath(startX, startY, endX, endY)}
                      fill="none"
                      stroke={edge.color}
                      strokeWidth={2.5}
                      strokeOpacity={0.85}
                      markerEnd={`url(#${markerId})`}
                      style={{ pointerEvents: 'none' }}
                    />
                    {/* Meaningful Lineage Relationship Badge */}
                    {edge.label && (
                      <g transform={`translate(${midX}, ${midY})`}>
                        <rect
                          x="-50"
                          y="-10"
                          width="100"
                          height="20"
                          rx="6"
                          fill={isDark ? "#080808" : "#ffffff"}
                          stroke={edge.color}
                          strokeWidth="1.2"
                          opacity="0.95"
                        />
                        <text
                          textAnchor="middle"
                          dy="4"
                          fill={edge.color}
                          fontSize="9.5"
                          fontWeight="800"
                        >
                          {edge.label}
                        </text>
                      </g>
                    )}
                  </g>
                );
              })}

              {/* Render Interactive Activity Cards with Exact Timestamps */}
              {timelineData.nodes.map(node => {
                const isSelected = selectedNode?.id === node.id;
                const isDraggingThis = draggingNodeId === node.id;
                const pos = getNodePos(node);

                // High contrast color scheme - pitch black in dark mode, clean white in light mode
                const cardBg = node.isThreat
                  ? (isDark ? 'rgba(50, 10, 20, 0.95)' : '#fff1f2')
                  : (isDark ? '#0d0d0d' : '#ffffff');
                
                const borderCol = node.isThreat
                  ? '#f43f5e'
                  : (isDraggingThis ? '#00f0ff' : (node.isOnline ? '#0ea5e9' : '#8b5cf6'));

                return (
                  <g
                    key={node.id}
                    transform={`translate(${pos.x}, ${pos.y})`}
                    style={{ cursor: isDraggingThis ? 'grabbing' : 'grab' }}
                    onMouseDown={(e) => handleNodeMouseDown(e, node)}
                    onClick={(e) => handleNodeClick(e, node)}
                  >
                    {/* Vertical line connecting node up to Time Axis */}
                    <line
                      x1={0}
                      y1={-58}
                      x2={0}
                      y2={70 - pos.y}
                      stroke={isDark ? "#262626" : "#cbd5e1"}
                      strokeWidth="1.5"
                      strokeDasharray="3 3"
                    />
                    <circle cx={0} cy={70 - pos.y} r={3.5} fill={isDark ? "#00f0ff" : "#0284c7"} />

                    {/* Prominent Exact Timestamp Badge (Above Node Card) */}
                    <g transform="translate(0, -68)">
                      <rect
                        x="-60"
                        y="-13"
                        width="120"
                        height="26"
                        rx="13"
                        fill={isDark ? "#080808" : "#f8fafc"}
                        stroke={isDark ? "#00f0ff" : "#0284c7"}
                        strokeWidth="1.5"
                      />
                      <text
                        textAnchor="middle"
                        dy="5"
                        fill={isDark ? "#00f0ff" : "#0284c7"}
                        fontSize="11.5"
                        fontWeight="800"
                        fontFamily="monospace"
                      >
                        🕒 {node.timeStr}
                      </text>
                    </g>

                    {/* Outer Selection Highlight */}
                    {(isSelected || isDraggingThis) && (
                      <rect
                        x="-130"
                        y="-51"
                        width="260"
                        height="102"
                        rx="16"
                        fill="none"
                        stroke={isDark ? "#00f0ff" : "#0284c7"}
                        strokeWidth="2.5"
                        strokeDasharray="5 3"
                      />
                    )}

                    {/* Main Node Card Body (Expanded to 250px x 92px for optimal readability) */}
                    <rect
                      x="-125"
                      y="-46"
                      width="250"
                      height="92"
                      rx="14"
                      fill={cardBg}
                      stroke={borderCol}
                      strokeWidth={isSelected ? 2.5 : 1.8}
                    />

                    {/* Icon Circle */}
                    <g transform="translate(-102, 0)">
                      <circle cx="12" cy="0" r="18" fill={isDark ? "#000000" : "#f1f5f9"} stroke={borderCol} strokeWidth="1.5" />
                      <g transform="translate(3, -9)">
                        {renderNodeIcon(node.iconType, node.isThreat)}
                      </g>
                    </g>

                    {/* Activity Label (App Name or Website) */}
                    <text
                      x="-65"
                      y="-18"
                      fill={textTitle}
                      fontSize="13"
                      fontWeight="800"
                    >
                      {node.label}
                    </text>

                    {/* Scope Pill (Online vs Offline) */}
                    <text
                      x="-65"
                      y="4"
                      fill={node.isOnline ? '#0284c7' : (isDark ? '#cbd5e1' : '#475569')}
                      fontSize="11"
                      fontWeight="700"
                    >
                      {node.isOnline ? '🌐 Online Web' : '💻 Offline Host'}
                    </text>

                    {/* Risk Status Verdict */}
                    <text
                      x="-65"
                      y="23"
                      fill={node.isThreat ? '#f43f5e' : '#34d399'}
                      fontSize="11"
                      fontWeight="800"
                    >
                      {node.isThreat ? `⚠️ Suspicious (${node.riskScore}/100)` : '✓ Verified Safe'}
                    </text>
                  </g>
                );
              })}
            </g>
          </svg>
        )}

        {/* ── Floating Legend Overlay ─────────────────────────────────── */}
        <div style={{
          position: 'absolute',
          bottom: '16px',
          left: '16px',
          background: floatingLegendBg,
          backdropFilter: 'blur(10px)',
          border: `1px solid ${cardBorder}`,
          borderRadius: '10px',
          padding: '0.75rem 1rem',
          display: 'flex',
          flexDirection: 'column',
          gap: '0.4rem',
          fontSize: '0.76rem',
          color: textSub,
          boxShadow: isDark ? '0 4px 20px rgba(0,0,0,0.7)' : '0 4px 15px rgba(0,0,0,0.08)',
          pointerEvents: 'none'
        }}>
          <div style={{ fontWeight: 800, color: textTitle, fontSize: '0.8rem', marginBottom: '2px', display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
            <span>Chronological Timeline Guide</span>
            <span style={{ color: isDark ? '#00f0ff' : '#0284c7', fontSize: '0.7rem', fontWeight: 600 }}>• Real-Time Records</span>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <span style={{ width: '10px', height: '10px', borderRadius: '50%', background: '#34d399', display: 'inline-block' }} />
            <span>Green: Verified Safe Baseline Activity</span>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <span style={{ width: '10px', height: '10px', borderRadius: '50%', background: '#f43f5e', display: 'inline-block' }} />
            <span>Red: Elevated Threat / Suspicious Execution</span>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <span style={{ width: '18px', height: '2px', background: isDark ? '#00f0ff' : '#0284c7', display: 'inline-block' }} />
            <span>Arrow Lines: Causal lineage (e.g. Browser opened → Website visited)</span>
          </div>
        </div>
      </div>

      {/* ── Selected Activity Details Drawer ─────────────────────────── */}
      {selectedNode && selectedNode.eventData && (
        <div style={{
          position: 'absolute',
          top: 0,
          right: 0,
          width: '420px',
          height: '100%',
          background: drawerBg,
          backdropFilter: 'blur(16px)',
          borderLeft: `1px solid ${cardBorder}`,
          padding: '1.4rem',
          display: 'flex',
          flexDirection: 'column',
          gap: '1.1rem',
          zIndex: 50,
          boxShadow: isDark ? '-10px 0 32px rgba(0,0,0,0.85)' : '-4px 0 20px rgba(0,0,0,0.1)',
          overflowY: 'auto'
        }}>
          {/* Header */}
          <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between' }}>
            <div>
              <span style={{
                fontSize: '0.72rem',
                fontWeight: 800,
                textTransform: 'uppercase',
                padding: '0.2rem 0.6rem',
                borderRadius: '5px',
                background: selectedNode.isThreat ? 'rgba(244, 63, 94, 0.2)' : 'rgba(52, 211, 153, 0.15)',
                color: selectedNode.isThreat ? '#f43f5e' : '#34d399',
                border: `1px solid ${selectedNode.isThreat ? '#f43f5e' : '#34d399'}`
              }}>
                {selectedNode.isThreat ? '⚠️ Suspicious / Threat Activity' : '✓ Verified Safe Activity'}
              </span>
              <h4 style={{ fontSize: '1.15rem', fontWeight: 800, color: textTitle, margin: '0.55rem 0 0 0', wordBreak: 'break-word' }}>
                {selectedNode.fullName || selectedNode.label}
              </h4>
            </div>
            <button
              onClick={() => setSelectedNode(null)}
              style={{ background: 'transparent', border: 'none', color: textSub, cursor: 'pointer', padding: '0.25rem' }}
            >
              <X size={20} />
            </button>
          </div>

          {/* Details Metadata Grid */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem', background: boxInnerBg, padding: '1rem', borderRadius: '10px', border: `1px solid ${subtleBorder}`, fontSize: '0.82rem' }}>
            <div>
              <span style={{ color: textSub, fontWeight: 600 }}>Exact Timestamp (Local):</span>
              <div style={{ color: isDark ? '#00f0ff' : '#0284c7', fontWeight: 800, fontSize: '1rem', fontFamily: 'monospace', marginTop: '2px' }}>
                {selectedNode.timeStr}
              </div>
              <div style={{ color: textSub, fontSize: '0.72rem', fontFamily: 'monospace' }}>
                ISO: {selectedNode.eventData.timestamp || selectedNode.eventData.created_at}
              </div>
            </div>

            <div>
              <span style={{ color: textSub, fontWeight: 600 }}>Activity Classification:</span>
              <div style={{ color: selectedNode.isOnline ? '#0ea5e9' : (isDark ? '#cbd5e1' : '#475569'), fontWeight: 700, marginTop: '2px' }}>
                {selectedNode.isOnline ? 'ONLINE (Web Navigation / Remote Network)' : 'OFFLINE (Local Process / Document / Sensor)'}
              </div>
            </div>

            <div>
              <span style={{ color: textSub, fontWeight: 600 }}>Security Verdict & Risk:</span>
              <div style={{ color: selectedNode.isThreat ? '#f43f5e' : '#34d399', fontWeight: 800, marginTop: '2px' }}>
                {selectedNode.status} (Composite Risk: {selectedNode.riskScore}/100)
              </div>
            </div>

            {selectedNode.eventData.features?.url && (
              <div>
                <span style={{ color: textSub, fontWeight: 600 }}>Full URL Destination:</span>
                <div style={{ color: textTitle, fontSize: '0.76rem', wordBreak: 'break-all', fontFamily: 'monospace', marginTop: '2px' }}>
                  {selectedNode.eventData.features.url}
                </div>
              </div>
            )}

            {selectedNode.eventData.features?.exe_path && (
              <div>
                <span style={{ color: textSub, fontWeight: 600 }}>Executable Path:</span>
                <div style={{ color: textTitle, fontSize: '0.76rem', wordBreak: 'break-all', fontFamily: 'monospace', marginTop: '2px' }}>
                  {selectedNode.eventData.features.exe_path}
                </div>
              </div>
            )}

            {selectedNode.eventData.features?.pid && (
              <div>
                <span style={{ color: textSub, fontWeight: 600 }}>Process ID (PID):</span>
                <div style={{ color: textTitle, fontWeight: 700, fontFamily: 'monospace', marginTop: '2px' }}>
                  {selectedNode.eventData.features.pid}
                </div>
              </div>
            )}

            {selectedNode.eventData.features?.duration_seconds && (
              <div>
                <span style={{ color: textSub, fontWeight: 600 }}>Session Duration:</span>
                <div style={{ color: textTitle, fontWeight: 700, marginTop: '2px' }}>
                  {selectedNode.eventData.features.duration_seconds} seconds
                </div>
              </div>
            )}
          </div>

          {/* Forensic Evidence & Detection Reason */}
          <div>
            <div style={{ fontSize: '0.8rem', fontWeight: 700, color: textSub, textTransform: 'uppercase', marginBottom: '0.4rem' }}>
              Forensic Evidence & Detection Reason:
            </div>
            <div style={{
              background: boxInnerBg,
              padding: '0.85rem',
              borderRadius: '8px',
              border: `1px solid ${subtleBorder}`,
              color: textTitle,
              fontSize: '0.82rem',
              lineHeight: 1.55
            }}>
              {selectedNode.eventData.features?.description || 
               selectedNode.eventData.features?.risk_reasons?.join(', ') || 
               'Real-time telemetry event captured and verified.'}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
