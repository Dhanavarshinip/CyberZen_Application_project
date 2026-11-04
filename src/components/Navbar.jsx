import React, { useState, useEffect } from 'react';
import { Shield, Activity, AlertTriangle, Laptop, Settings, LogOut, Wifi, WifiOff, ArrowLeft, ArrowRight, Download, HelpCircle, ExternalLink, Globe, CheckCircle2, Sun, Moon } from 'lucide-react';
import { useAuth } from '../context/AuthContext';
import { useTheme } from '../context/ThemeContext';
import { apiClient } from '../services/apiClient';
import ChromeExtensionModal from './ChromeExtensionModal';

export default function Navbar({
  activeTab,
  setActiveTab,
  isOnline,
  connectionStatus = 'ONLINE',
  lastHeartbeat = null,
  pendingSyncCount,
  devices = [],
  selectedDeviceId = null,
  onSelectDevice,
  currentHostDeviceId = null,
  canGoBack = false,
  canGoForward = false,
  onNavigateBack,
  onNavigateForward,
  onOpenWebsite,
  onOpenOnboarding
}) {
  const { user, logout } = useAuth();
  const { isDark, toggleTheme } = useTheme();
  const [showExtensionModal, setShowExtensionModal] = useState(false);
  const [extStatus, setExtStatus] = useState(null);

  useEffect(() => {
    let mounted = true;
    const fetchExt = async () => {
      try {
        const s = await apiClient.getExtensionStatus(selectedDeviceId || currentHostDeviceId);
        if (mounted) setExtStatus(s);
      } catch (e) {}
    };
    fetchExt();
    const interval = setInterval(fetchExt, 10000);
    return () => { mounted = false; clearInterval(interval); };
  }, [selectedDeviceId, currentHostDeviceId]);

  const navItems = [
    { id: 'home', label: 'Home', icon: Shield },
    { id: 'activity', label: 'Activity', icon: Activity },
    { id: 'incidents', label: 'Incidents', icon: AlertTriangle },
    { id: 'devices', label: 'Devices', icon: Laptop },
    { id: 'settings', label: 'Settings', icon: Settings },
    { id: 'download', label: 'Install App', icon: Download },
  ];

  const getConnectionConfig = () => {
    switch (connectionStatus) {
      case 'ONLINE':
        return {
          label: 'Online',
          color: '#4ade80',
          bg: 'rgba(34, 197, 94, 0.15)',
          border: 'rgba(34, 197, 94, 0.35)',
          icon: Wifi
        };
      case 'OFFLINE_MONITORING':
        return {
          label: 'Offline Monitoring',
          color: '#fbbf24',
          bg: 'rgba(245, 158, 11, 0.15)',
          border: 'rgba(245, 158, 11, 0.35)',
          icon: WifiOff
        };
      case 'AGENT_DISCONNECTED':
        return {
          label: 'Agent Disconnected',
          color: '#f87171',
          bg: 'rgba(239, 68, 68, 0.15)',
          border: 'rgba(239, 68, 68, 0.35)',
          icon: WifiOff
        };
      case 'SERVER_UNAVAILABLE':
      default:
        return {
          label: 'Server Unavailable',
          color: '#94a3b8',
          bg: 'rgba(148, 163, 184, 0.15)',
          border: 'rgba(148, 163, 184, 0.35)',
          icon: WifiOff
        };
    }
  };

  const connConfig = getConnectionConfig();
  const ConnIcon = connConfig.icon;

  const effectiveCanGoBack = canGoBack || showExtensionModal;

  const handleBack = () => {
    if (showExtensionModal) {
      setShowExtensionModal(false);
      return;
    }
    if (onNavigateBack) onNavigateBack();
  };

  return (
    <header style={{
      background: isDark ? 'rgba(0, 0, 0, 0.92)' : 'rgba(255, 255, 255, 0.96)',
      borderBottom: isDark ? '1px solid #1e1e1e' : '1px solid #e2e8f0',
      backdropFilter: 'blur(12px)',
      padding: '0.75rem 1.75rem',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'space-between',
      position: 'sticky',
      top: 0,
      zIndex: 50,
      color: isDark ? '#ffffff' : '#0f172a',
      transition: 'background 0.25s ease, border-color 0.25s ease'
    }}>
      {/* Brand & Dual Back / Forward Navigation Controls */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.3rem' }}>
          <button
            id="nav-back-button"
            type="button"
            title={effectiveCanGoBack ? 'Go back' : 'No previous view'}
            disabled={!effectiveCanGoBack}
            onClick={handleBack}
            style={{
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              width: '34px',
              height: '34px',
              borderRadius: '8px',
              border: '1px solid',
              borderColor: effectiveCanGoBack 
                ? (isDark ? '#334155' : '#cbd5e1') 
                : (isDark ? '#1e293b' : '#f1f5f9'),
              background: effectiveCanGoBack 
                ? (isDark ? '#0f172a' : '#ffffff') 
                : 'transparent',
              color: effectiveCanGoBack 
                ? (isDark ? '#00f0ff' : '#0284c7') 
                : (isDark ? '#475569' : '#cbd5e1'),
              cursor: effectiveCanGoBack ? 'pointer' : 'not-allowed',
              opacity: effectiveCanGoBack ? 1 : 0.45,
              transition: 'all 0.15s ease'
            }}
          >
            <ArrowLeft size={16} strokeWidth={2.4} />
          </button>

          <button
            id="nav-forward-button"
            type="button"
            title={canGoForward ? 'Go forward' : 'No forward view'}
            disabled={!canGoForward}
            onClick={onNavigateForward}
            style={{
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              width: '34px',
              height: '34px',
              borderRadius: '8px',
              border: '1px solid',
              borderColor: canGoForward 
                ? (isDark ? '#334155' : '#cbd5e1') 
                : (isDark ? '#1e293b' : '#f1f5f9'),
              background: canGoForward 
                ? (isDark ? '#0f172a' : '#ffffff') 
                : 'transparent',
              color: canGoForward 
                ? (isDark ? '#00f0ff' : '#0284c7') 
                : (isDark ? '#475569' : '#cbd5e1'),
              cursor: canGoForward ? 'pointer' : 'not-allowed',
              opacity: canGoForward ? 1 : 0.45,
              transition: 'all 0.15s ease'
            }}
          >
            <ArrowRight size={16} strokeWidth={2.4} />
          </button>
        </div>

        <div style={{
          width: '36px',
          height: '36px',
          borderRadius: '8px',
          background: isDark 
            ? 'linear-gradient(135deg, rgba(0, 240, 255, 0.2) 0%, rgba(59, 130, 246, 0.3) 100%)'
            : 'linear-gradient(135deg, rgba(2, 132, 199, 0.15) 0%, rgba(59, 130, 246, 0.2) 100%)',
          border: isDark ? '1px solid rgba(0, 240, 255, 0.4)' : '1px solid rgba(2, 132, 199, 0.3)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          color: isDark ? '#00f0ff' : '#0284c7'
        }}>
          <Shield size={20} strokeWidth={2.5} />
        </div>
        <div>
          <div style={{ fontSize: '1.05rem', fontWeight: 800, color: isDark ? '#ffffff' : '#0f172a', letterSpacing: '-0.02em', lineHeight: 1.1 }}>
            Cyber<span style={{ color: isDark ? '#00f0ff' : '#0284c7' }}>Zen</span>
          </div>
          <div style={{ fontSize: '0.68rem', color: isDark ? '#94a3b8' : '#64748b', fontWeight: 500, maxWidth: '420px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title="Intelligent Real-Time Digital Threat Detection, Prevention and Incident Reconstruction">
            Intelligent Real-Time Digital Threat Detection, Prevention and Incident Reconstruction
          </div>
        </div>
      </div>

      {/* Navigation Tabs */}
      <nav style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
        {navItems.map(item => {
          const Icon = item.icon;
          const isActive = activeTab === item.id;
          return (
            <button
              key={item.id}
              onClick={() => setActiveTab(item.id)}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '0.45rem',
                padding: '0.5rem 0.95rem',
                borderRadius: '8px',
                border: isActive 
                  ? (isDark ? '1px solid rgba(0, 240, 255, 0.35)' : '1px solid rgba(2, 132, 199, 0.25)')
                  : '1px solid transparent',
                background: isActive 
                  ? (isDark ? 'rgba(0, 240, 255, 0.12)' : 'rgba(2, 132, 199, 0.1)') 
                  : 'transparent',
                color: isActive 
                  ? (isDark ? '#00f0ff' : '#0284c7') 
                  : (isDark ? '#a1a1aa' : '#475569'),
                fontWeight: isActive ? 700 : 500,
                fontSize: '0.88rem',
                cursor: 'pointer',
                transition: 'all 0.15s ease'
              }}
            >
              <Icon size={16} />
              <span>{item.label}</span>
            </button>
          );
        })}
      </nav>

      {/* Status & User Profile */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
        {/* Chrome Extension Status & Quick Management Button */}
        <button
          type="button"
          title="CyberZen Chrome Extension Status (Click to pair or manage)"
          onClick={() => setShowExtensionModal(true)}
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: '0.45rem',
            padding: '0.4rem 0.75rem',
            borderRadius: '8px',
            border: extStatus?.connected 
              ? (isDark ? '1px solid rgba(34, 197, 94, 0.45)' : '1px solid #bbf7d0')
              : (isDark ? '1px solid rgba(0, 240, 255, 0.35)' : '1px solid #bae6fd'),
            background: extStatus?.connected 
              ? (isDark ? 'rgba(34, 197, 94, 0.15)' : '#f0fdf4') 
              : (isDark ? 'rgba(0, 240, 255, 0.1)' : '#f0f9ff'),
            color: extStatus?.connected 
              ? (isDark ? '#4ade80' : '#16a34a') 
              : (isDark ? '#38bdf8' : '#0284c7'),
            fontSize: '0.78rem',
            fontWeight: 700,
            cursor: 'pointer',
            transition: 'all 0.15s ease'
          }}
        >
          <Globe size={13} />
          <span>{extStatus?.connected ? 'Extension Connected' : 'Pair Chrome Extension'}</span>
          <span style={{
            width: '7px',
            height: '7px',
            borderRadius: '50%',
            background: extStatus?.connected ? '#22c55e' : '#f59e0b',
            display: 'inline-block'
          }} />
        </button>

        {/* Connectivity Status Badge */}
        <div 
          title={lastHeartbeat ? `Last Heartbeat: ${lastHeartbeat}` : 'Connection status'}
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: '0.4rem',
            padding: '0.35rem 0.7rem',
            borderRadius: '20px',
            background: connConfig.bg,
            border: `1px solid ${connConfig.border}`,
            fontSize: '0.75rem',
            fontWeight: 700,
            color: connConfig.color
          }}
        >
          <ConnIcon size={13} />
          <span>{connConfig.label}</span>
        </div>

        {/* User Account & Theme Controls */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          {/* Quick Theme Toggle */}
          <button
            type="button"
            onClick={toggleTheme}
            title={`Switch to ${isDark ? 'Light' : 'Dark'} Mode`}
            style={{
              background: isDark ? 'rgba(255, 255, 255, 0.08)' : 'rgba(0, 0, 0, 0.06)',
              border: `1px solid ${isDark ? '#334155' : '#cbd5e1'}`,
              color: isDark ? '#fbbf24' : '#0284c7',
              padding: '0.4rem',
              borderRadius: '8px',
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              transition: 'all 0.15s ease'
            }}
          >
            {isDark ? <Sun size={15} /> : <Moon size={15} />}
          </button>

          <div 
            title={user?.email ? `${user?.name || 'User'} (${user.email})` : (user?.name || 'User Profile')}
            style={{
              width: '32px',
              height: '32px',
              borderRadius: '50%',
              background: 'rgba(0, 240, 255, 0.15)',
              border: '1px solid rgba(0, 240, 255, 0.4)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              fontSize: '0.82rem',
              fontWeight: 700,
              color: '#00f0ff',
              cursor: 'default',
              userSelect: 'none'
            }}
          >
            {(user?.name || user?.email || 'U').charAt(0).toUpperCase()}
          </div>

          <button
            onClick={logout}
            title="Log Out"
            style={{
              background: 'none',
              border: 'none',
              color: '#94a3b8',
              cursor: 'pointer',
              padding: '0.35rem',
              borderRadius: '6px',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              transition: 'all 0.15s ease'
            }}
          >
            <LogOut size={16} />
          </button>
        </div>
      </div>

      {/* Chrome Extension Pairing & Installation Modal */}
      <ChromeExtensionModal
        isOpen={showExtensionModal}
        onClose={() => setShowExtensionModal(false)}
        user={user}
        deviceId={selectedDeviceId || currentHostDeviceId}
      />
    </header>
  );
}
