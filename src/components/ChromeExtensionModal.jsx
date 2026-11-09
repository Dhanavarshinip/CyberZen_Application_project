import React, { useState, useEffect } from 'react';
import { createPortal } from 'react-dom';
import { 
  Globe, 
  ShieldCheck, 
  ShieldAlert, 
  CheckCircle2, 
  AlertTriangle, 
  Copy, 
  Check, 
  ExternalLink, 
  RefreshCw, 
  X, 
  Terminal, 
  HardDrive,
  Download,
  Laptop
} from 'lucide-react';
import { apiClient } from '../services/apiClient';

export default function ChromeExtensionModal({ isOpen, onClose, user, deviceId }) {
  const [status, setStatus] = useState(null);
  const [isLoading, setIsLoading] = useState(false);
  const [isPairing, setIsPairing] = useState(false);
  const [isLaunching, setIsLaunching] = useState(false);
  const [copied, setCopied] = useState(false);
  const [actionMessage, setActionMessage] = useState(null);
  const [actionError, setActionError] = useState(null);

  const extensionPath = status?.extension_path || 'd:\\CyberThreat_AI_System\\chrome_extension';

  const checkStatus = async () => {
    setIsLoading(true);
    setActionError(null);
    try {
      const res = await apiClient.getExtensionStatus(deviceId);
      setStatus(res);
    } catch (err) {
      console.warn('Check extension status error:', err);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    if (isOpen) {
      checkStatus();
      const interval = setInterval(checkStatus, 6000);
      const handleKey = (e) => {
        if (e.key === 'Escape') onClose();
      };
      window.addEventListener('keydown', handleKey);
      return () => {
        clearInterval(interval);
        window.removeEventListener('keydown', handleKey);
      };
    }
  }, [isOpen, deviceId]);

  const handlePairNow = async () => {
    if (!user?.email) {
      setActionError('Please sign in first to pair your extension.');
      return;
    }
    setIsPairing(true);
    setActionMessage(null);
    setActionError(null);
    try {
      const res = await apiClient.pairExtension(user.email, deviceId, user.id);
      if (res && (res.status === 'SUCCESS' || res.status === 'paired' || res.success || res.paired)) {
        setActionMessage(`Successfully paired! Extension credentials updated for ${user.email}`);
        await checkStatus();
      } else {
        setActionError(res?.message || 'Pairing failed. Please verify the backend is running.');
      }
    } catch (err) {
      setActionError(err.message || 'Pairing request failed.');
    } finally {
      setIsPairing(false);
    }
  };

  const handleLaunchBrowser = async () => {
    setIsLaunching(true);
    setActionMessage(null);
    setActionError(null);
    try {
      const res = await apiClient.launchProtectedBrowser();
      setActionMessage(res?.message || 'Google Chrome launched with CyberZen Extension loaded!');
      setTimeout(checkStatus, 3000);
    } catch (err) {
      setActionError(err.message || 'Could not launch Google Chrome automatically.');
    } finally {
      setIsLaunching(false);
    }
  };

  const handleCopyPath = () => {
    navigator.clipboard.writeText(extensionPath);
    setCopied(true);
    setTimeout(() => setCopied(false), 3000);
  };

  if (!isOpen) return null;

  const isConnected = status?.connected === true;

  const modalContent = (
    <div 
      onClick={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
      style={{
        position: 'fixed',
        top: 0,
        left: 0,
        right: 0,
        bottom: 0,
        width: '100vw',
        height: '100vh',
        zIndex: 999999,
        background: 'rgba(3, 7, 18, 0.85)',
        backdropFilter: 'blur(8px)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        padding: '1.5rem',
        boxSizing: 'border-box',
        overflowY: 'auto'
      }}
    >
      <div 
        onClick={(e) => e.stopPropagation()}
        style={{
          margin: 'auto',
          background: '#0c1527',
          border: '1px solid #1e293b',
          borderRadius: '16px',
          width: '100%',
          maxWidth: '620px',
          maxHeight: 'min(90vh, 760px)',
          boxShadow: '0 24px 64px rgba(0, 0, 0, 0.85)',
          display: 'flex',
          flexDirection: 'column',
          overflow: 'hidden',
          position: 'relative'
        }}
      >
        {/* Header - Always Fixed at Top */}
        <div style={{
          padding: '1.25rem 1.5rem',
          borderBottom: '1px solid #1e293b',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          background: 'rgba(15, 23, 42, 0.95)',
          flexShrink: 0
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
            <div style={{
              width: '40px',
              height: '40px',
              borderRadius: '10px',
              background: isConnected ? 'rgba(34, 197, 94, 0.15)' : 'rgba(2, 132, 199, 0.15)',
              border: `1px solid ${isConnected ? 'rgba(34, 197, 94, 0.35)' : 'rgba(2, 132, 199, 0.35)'}`,
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              color: isConnected ? '#22c55e' : '#38bdf8'
            }}>
              <Globe size={22} />
            </div>
            <div>
              <div style={{ fontSize: '1.1rem', fontWeight: 800, color: '#f8fafc' }}>
                CyberZen Chrome Extension
              </div>
              <div style={{ fontSize: '0.78rem', color: '#94a3b8' }}>
                Real-time browser threat detection & activity synchronization
              </div>
            </div>
          </div>
          <button
            onClick={onClose}
            title="Close (Esc)"
            style={{
              background: 'rgba(255, 255, 255, 0.06)',
              border: '1px solid rgba(255, 255, 255, 0.12)',
              color: '#94a3b8',
              cursor: 'pointer',
              padding: '0.45rem',
              borderRadius: '8px',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              transition: 'all 0.15s ease'
            }}
            onMouseEnter={(e) => { e.currentTarget.style.color = '#ffffff'; e.currentTarget.style.borderColor = '#00f0ff'; }}
            onMouseLeave={(e) => { e.currentTarget.style.color = '#94a3b8'; e.currentTarget.style.borderColor = 'rgba(255, 255, 255, 0.12)'; }}
          >
            <X size={20} />
          </button>
        </div>

        {/* Content Body - Scrollable */}
        <div style={{ padding: '1.5rem', display: 'flex', flexDirection: 'column', gap: '1.25rem', overflowY: 'auto', flex: 1 }}>
          {/* Status Banner */}
          <div style={{
            background: isConnected ? 'rgba(34, 197, 94, 0.1)' : 'rgba(245, 158, 11, 0.1)',
            border: `1px solid ${isConnected ? 'rgba(34, 197, 94, 0.3)' : 'rgba(245, 158, 11, 0.3)'}`,
            borderRadius: '12px',
            padding: '1rem',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            gap: '1rem'
          }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
              {isConnected ? (
                <CheckCircle2 size={24} color="#22c55e" />
              ) : (
                <AlertTriangle size={24} color="#f59e0b" />
              )}
              <div>
                <div style={{ fontSize: '0.95rem', fontWeight: 800, color: isConnected ? '#22c55e' : '#f59e0b' }}>
                  {isConnected ? 'Connected & Protecting Browser' : 'Extension Not Connected'}
                </div>
                <div style={{ fontSize: '0.75rem', color: '#cbd5e1', marginTop: '2px' }}>
                  {isConnected 
                    ? `Paired to: ${status?.user_email || user?.email} • Heartbeat verified`
                    : 'Install or pair the extension to capture web threats and browsing telemetry.'}
                </div>
              </div>
            </div>

            <button
              onClick={checkStatus}
              disabled={isLoading}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '0.35rem',
                padding: '0.35rem 0.65rem',
                borderRadius: '6px',
                background: '#1e293b',
                border: '1px solid #334155',
                color: '#cbd5e1',
                fontSize: '0.75rem',
                cursor: 'pointer'
              }}
            >
              <RefreshCw size={13} className={isLoading ? 'animate-spin' : ''} />
              <span>Refresh</span>
            </button>
          </div>

          {/* Action Alerts */}
          {actionMessage && (
            <div style={{
              background: 'rgba(34, 197, 94, 0.15)',
              border: '1px solid #22c55e',
              color: '#86efac',
              padding: '0.75rem 1rem',
              borderRadius: '8px',
              fontSize: '0.8rem',
              fontWeight: 600
            }}>
              ✓ {actionMessage}
            </div>
          )}
          {actionError && (
            <div style={{
              background: 'rgba(239, 68, 68, 0.15)',
              border: '1px solid #ef4444',
              color: '#fca5a5',
              padding: '0.75rem 1rem',
              borderRadius: '8px',
              fontSize: '0.8rem',
              fontWeight: 600
            }}>
              ⚠️ {actionError}
            </div>
          )}

          {/* User & Device Association Card */}
          <div style={{
            background: '#070b16',
            border: '1px solid #1e293b',
            borderRadius: '10px',
            padding: '1rem',
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))',
            gap: '0.85rem'
          }}>
            <div>
              <div style={{ fontSize: '0.72rem', color: '#64748b', fontWeight: 700, textTransform: 'uppercase' }}>
                Registered User Account
              </div>
              <div style={{ fontSize: '0.88rem', fontWeight: 700, color: '#f8fafc', marginTop: '2px' }}>
                {user?.email || 'Not Signed In'}
              </div>
            </div>

            <div>
              <div style={{ fontSize: '0.72rem', color: '#64748b', fontWeight: 700, textTransform: 'uppercase' }}>
                Enrolled Workstation Device
              </div>
              <div style={{ fontSize: '0.88rem', fontWeight: 700, color: '#00f0ff', fontFamily: 'monospace', marginTop: '2px' }}>
                {deviceId}
              </div>
            </div>
          </div>

          {/* Action Buttons: 1-Click Launch & Account Pairing */}
          <div style={{ display: 'flex', gap: '0.75rem', flexWrap: 'wrap' }}>
            <button
              onClick={handleLaunchBrowser}
              disabled={isLaunching}
              style={{
                flex: 1,
                minWidth: '200px',
                padding: '0.75rem 1rem',
                borderRadius: '8px',
                background: 'linear-gradient(135deg, #0284c7 0%, #0369a1 100%)',
                color: '#ffffff',
                border: 'none',
                fontSize: '0.85rem',
                fontWeight: 700,
                cursor: isLaunching ? 'not-allowed' : 'pointer',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                gap: '0.5rem',
                boxShadow: '0 4px 12px rgba(2, 132, 199, 0.35)'
              }}
            >
              <Globe size={16} />
              <span>{isLaunching ? 'Launching Chrome...' : 'Launch Chrome with Extension'}</span>
            </button>

            <a
              href="./cyberzen-chrome-extension.zip"
              download="cyberzen-chrome-extension.zip"
              style={{
                flex: 1,
                minWidth: '200px',
                padding: '0.75rem 1rem',
                borderRadius: '8px',
                background: '#064e3b',
                color: '#6ee7b7',
                border: '1px solid #059669',
                fontSize: '0.85rem',
                fontWeight: 700,
                cursor: 'pointer',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                gap: '0.5rem',
                textDecoration: 'none'
              }}
            >
              <Download size={16} />
              <span>Download Extension (.zip)</span>
            </a>

            <button
              onClick={handlePairNow}
              disabled={isPairing}
              style={{
                flex: 1,
                minWidth: '200px',
                padding: '0.75rem 1rem',
                borderRadius: '8px',
                background: '#1e293b',
                color: '#38bdf8',
                border: '1px solid #0284c7',
                fontSize: '0.85rem',
                fontWeight: 700,
                cursor: isPairing ? 'not-allowed' : 'pointer',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                gap: '0.5rem'
              }}
            >
              <ShieldCheck size={16} />
              <span>{isPairing ? 'Syncing...' : 'Pair Active Account Now'}</span>
            </button>
          </div>

          {/* Step-by-Step Installation Guide */}
          <div style={{
            background: '#070b16',
            border: '1px solid #1e293b',
            borderRadius: '10px',
            padding: '1.25rem',
            display: 'flex',
            flexDirection: 'column',
            gap: '0.75rem'
          }}>
            <div style={{ fontSize: '0.85rem', fontWeight: 800, color: '#f8fafc', display: 'flex', alignItems: 'center', gap: '0.45rem' }}>
              <span>Manual Chrome Extension Setup (One-Time)</span>
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.65rem', fontSize: '0.8rem', color: '#cbd5e1' }}>
              <div style={{ display: 'flex', alignItems: 'flex-start', gap: '0.5rem' }}>
                <span style={{ width: '20px', height: '20px', borderRadius: '50%', background: '#1e293b', color: '#00f0ff', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: '0.75rem', fontWeight: 700, flexShrink: 0 }}>
                  1
                </span>
                <span>Open Google Chrome and navigate to <code style={{ color: '#00f0ff', background: '#0f172a', padding: '1px 5px', borderRadius: '4px' }}>chrome://extensions</code></span>
              </div>

              <div style={{ display: 'flex', alignItems: 'flex-start', gap: '0.5rem' }}>
                <span style={{ width: '20px', height: '20px', borderRadius: '50%', background: '#1e293b', color: '#00f0ff', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: '0.75rem', fontWeight: 700, flexShrink: 0 }}>
                  2
                </span>
                <span>Enable <strong>Developer mode</strong> using the toggle switch in the top-right corner.</span>
              </div>

              <div style={{ display: 'flex', alignItems: 'flex-start', gap: '0.5rem' }}>
                <span style={{ width: '20px', height: '20px', borderRadius: '50%', background: '#1e293b', color: '#00f0ff', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: '0.75rem', fontWeight: 700, flexShrink: 0 }}>
                  3
                </span>
                <div style={{ flex: 1 }}>
                  <span>Click <strong>Load unpacked</strong> and select the extension folder:</span>
                  <div style={{
                    marginTop: '0.4rem',
                    background: '#0c1527',
                    border: '1px solid #334155',
                    borderRadius: '6px',
                    padding: '0.4rem 0.65rem',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    gap: '0.5rem',
                    fontFamily: 'monospace',
                    fontSize: '0.78rem',
                    color: '#38bdf8'
                  }}>
                    <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {extensionPath}
                    </span>
                    <button
                      onClick={handleCopyPath}
                      style={{
                        background: '#1e293b',
                        border: '1px solid #475569',
                        color: copied ? '#22c55e' : '#cbd5e1',
                        borderRadius: '4px',
                        padding: '0.25rem 0.5rem',
                        cursor: 'pointer',
                        display: 'flex',
                        alignItems: 'center',
                        gap: '0.25rem',
                        fontSize: '0.72rem',
                        fontWeight: 700,
                        flexShrink: 0
                      }}
                    >
                      {copied ? <Check size={12} /> : <Copy size={12} />}
                      <span>{copied ? 'Copied' : 'Copy Path'}</span>
                    </button>
                  </div>
                </div>
              </div>

              <div style={{ display: 'flex', alignItems: 'flex-start', gap: '0.5rem' }}>
                <span style={{ width: '20px', height: '20px', borderRadius: '50%', background: '#1e293b', color: '#00f0ff', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: '0.75rem', fontWeight: 700, flexShrink: 0 }}>
                  4
                </span>
                <span>Click the extension icon in your Chrome toolbar and click <strong>"Sync with App"</strong>.</span>
              </div>
            </div>
          </div>

          {/* Privacy and Security Guarantee */}
          <div style={{
            background: 'rgba(15, 23, 42, 0.4)',
            border: '1px solid #1e293b',
            borderRadius: '8px',
            padding: '0.75rem 1rem',
            fontSize: '0.74rem',
            color: '#94a3b8',
            lineHeight: 1.5
          }}>
            🔒 <strong style={{ color: '#cbd5e1' }}>Privacy Protection:</strong> The CyberZen extension inspects URLs, navigation domains, and download metadata to protect against phishing and malicious software. It <strong>never</strong> accesses passwords, cookies, or personal banking data.
          </div>
        </div>

        {/* Footer */}
        <div style={{
          padding: '1rem 1.5rem',
          borderTop: '1px solid #1e293b',
          display: 'flex',
          justifyContent: 'flex-end',
          background: 'rgba(15, 23, 42, 0.6)'
        }}>
          <button
            onClick={onClose}
            style={{
              padding: '0.5rem 1.25rem',
              borderRadius: '8px',
              background: '#1e293b',
              color: '#f8fafc',
              border: '1px solid #334155',
              fontSize: '0.85rem',
              fontWeight: 700,
              cursor: 'pointer'
            }}
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );

  return typeof document !== 'undefined' ? createPortal(modalContent, document.body) : modalContent;
}
