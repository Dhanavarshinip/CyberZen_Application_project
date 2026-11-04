import React, { useState, useEffect } from 'react';
import { Shield, Eye, HardDrive, Wifi, Globe, Lock, AlertTriangle, CheckCircle2, X, Power, UserCheck, Laptop, Cpu } from 'lucide-react';
import { apiClient } from '../../services/apiClient';

export default function FirstLaunchOnboardingModal({
  isOpen,
  onClose,
  onToggleMonitoring,
  isMonitoringActive,
  user = null,
  monitorDeviceId = null,
  onDeviceEnrolled = null
}) {
  if (!isOpen) return null;

  const [activeTab, setActiveTab] = useState('enrollment'); // 'enrollment', 'data', 'privacy', 'permissions', 'controls'
  const [consentAcknowledged, setConsentAcknowledged] = useState(false);
  const [deviceName, setDeviceName] = useState(() => 'Primary Laptop');
  const [hardwareId, setHardwareId] = useState(monitorDeviceId || '');
  const [isEnrolling, setIsEnrolling] = useState(false);
  const [enrollSuccess, setEnrollSuccess] = useState(false);
  const [enrollError, setEnrollError] = useState(null);

  useEffect(() => {
    if (monitorDeviceId && !hardwareId) {
      setHardwareId(monitorDeviceId);
    }
    // Fetch monitoring status if hardwareId is empty
    if (!hardwareId) {
      apiClient.getMonitoringStatus().then(st => {
        if (st?.device_id && st.device_id !== 'UNKNOWN') {
          setHardwareId(st.device_id);
        }
      }).catch(() => {});
    }
  }, [monitorDeviceId, hardwareId]);

  const handleEnrollDevice = async () => {
    if (!user?.id) {
      setEnrollError('User session required to enroll device. Please sign in first.');
      return;
    }
    setIsEnrolling(true);
    setEnrollError(null);
    try {
      const devId = hardwareId || `DEV_${Math.random().toString(36).substring(2, 10).toUpperCase()}`;
      const res = await apiClient.enrollDevice({
        device_id: devId,
        device_name: deviceName.trim() || 'My Laptop',
        os_info: typeof navigator !== 'undefined' ? navigator.userAgent : 'Windows 10/11 x64',
        user_id: user.id
      });
      if (res && res.device) {
        setEnrollSuccess(true);
        if (onDeviceEnrolled) onDeviceEnrolled(res.device);
      } else {
        setEnrollError('Device enrollment response invalid.');
      }
    } catch (err) {
      setEnrollError(err.message || 'Enrollment failed.');
    } finally {
      setIsEnrolling(false);
    }
  };

  const handleComplete = () => {
    localStorage.setItem('cyberthreat_onboarding_completed', 'true');
    if (onToggleMonitoring && !isMonitoringActive) {
      onToggleMonitoring(true);
    }
    onClose();
  };

  const handleWithdrawConsent = () => {
    if (confirm('Withdrawing consent will stop all host telemetry collectors and pause active AI protection. Do you wish to continue?')) {
      if (onToggleMonitoring && isMonitoringActive) {
        onToggleMonitoring(false);
      }
      localStorage.removeItem('cyberthreat_onboarding_completed');
      onClose();
    }
  };

  return (
    <div style={{
      position: 'fixed',
      top: 0, left: 0, right: 0, bottom: 0,
      background: 'rgba(9, 13, 22, 0.88)',
      backdropFilter: 'blur(6px)',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      zIndex: 200,
      padding: '1.5rem'
    }}>
      <div style={{
        background: '#0f172a',
        border: '1px solid #00f0ff',
        borderRadius: '16px',
        padding: '2rem',
        width: '100%',
        maxWidth: '720px',
        maxHeight: '90vh',
        overflowY: 'auto',
        boxShadow: '0 0 40px rgba(0, 240, 255, 0.2)',
        display: 'flex',
        flexDirection: 'column',
        gap: '1.5rem',
        color: '#f8fafc'
      }}>
        
        {/* Header */}
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
            <div style={{
              width: '42px', height: '42px', borderRadius: '10px',
              background: 'rgba(0, 240, 255, 0.15)', color: '#00f0ff',
              display: 'flex', alignItems: 'center', justifyContent: 'center'
            }}>
              <Shield size={24} />
            </div>
            <div>
              <h2 style={{ fontSize: '1.35rem', fontWeight: 800, margin: 0, color: '#f8fafc' }}>
                Onboarding & Device Enrollment
              </h2>
              <p style={{ fontSize: '0.82rem', color: '#94a3b8', margin: 0 }}>
                Intelligent Real-Time Digital Threat Detection, Prevention and Incident Reconstruction
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            style={{ background: 'none', border: 'none', color: '#94a3b8', cursor: 'pointer', padding: '0.25rem' }}
          >
            <X size={20} />
          </button>
        </div>

        {/* Tab Switcher */}
        <div style={{
          display: 'flex',
          gap: '0.5rem',
          borderBottom: '1px solid #1e293b',
          paddingBottom: '0.5rem',
          overflowX: 'auto'
        }}>
          <button
            onClick={() => setActiveTab('enrollment')}
            style={{
              padding: '0.45rem 0.85rem',
              borderRadius: '6px',
              border: 'none',
              background: activeTab === 'enrollment' ? 'rgba(0, 240, 255, 0.15)' : 'transparent',
              color: activeTab === 'enrollment' ? '#00f0ff' : '#94a3b8',
              fontSize: '0.82rem',
              fontWeight: 600,
              cursor: 'pointer'
            }}
          >
            1. Device Enrollment
          </button>

          <button
            onClick={() => setActiveTab('data')}
            style={{
              padding: '0.45rem 0.85rem',
              borderRadius: '6px',
              border: 'none',
              background: activeTab === 'data' ? 'rgba(0, 240, 255, 0.15)' : 'transparent',
              color: activeTab === 'data' ? '#00f0ff' : '#94a3b8',
              fontSize: '0.82rem',
              fontWeight: 600,
              cursor: 'pointer'
            }}
          >
            2. What We Collect
          </button>

          <button
            onClick={() => setActiveTab('privacy')}
            style={{
              padding: '0.45rem 0.85rem',
              borderRadius: '6px',
              border: 'none',
              background: activeTab === 'privacy' ? 'rgba(0, 240, 255, 0.15)' : 'transparent',
              color: activeTab === 'privacy' ? '#00f0ff' : '#94a3b8',
              fontSize: '0.82rem',
              fontWeight: 600,
              cursor: 'pointer'
            }}
          >
            3. Privacy Guarantee
          </button>

          <button
            onClick={() => setActiveTab('permissions')}
            style={{
              padding: '0.45rem 0.85rem',
              borderRadius: '6px',
              border: 'none',
              background: activeTab === 'permissions' ? 'rgba(0, 240, 255, 0.15)' : 'transparent',
              color: activeTab === 'permissions' ? '#00f0ff' : '#94a3b8',
              fontSize: '0.82rem',
              fontWeight: 600,
              cursor: 'pointer'
            }}
          >
            4. Windows Permissions
          </button>

          <button
            onClick={() => setActiveTab('controls')}
            style={{
              padding: '0.45rem 0.85rem',
              borderRadius: '6px',
              border: 'none',
              background: activeTab === 'controls' ? 'rgba(0, 240, 255, 0.15)' : 'transparent',
              color: activeTab === 'controls' ? '#00f0ff' : '#94a3b8',
              fontSize: '0.82rem',
              fontWeight: 600,
              cursor: 'pointer'
            }}
          >
            5. Controls & Withdrawal
          </button>
        </div>

        {/* Tab Content */}
        <div style={{ minHeight: '260px' }}>
          {activeTab === 'enrollment' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
              <div style={{
                background: 'rgba(0, 240, 255, 0.05)',
                border: '1px solid rgba(0, 240, 255, 0.25)',
                borderRadius: '8px',
                padding: '1rem',
                display: 'flex',
                alignItems: 'center',
                gap: '0.75rem'
              }}>
                <Laptop size={24} style={{ color: '#00f0ff', flexShrink: 0 }} />
                <div>
                  <div style={{ fontWeight: 700, color: '#f8fafc', fontSize: '0.9rem' }}>
                    Physical Laptop Hardware Identified
                  </div>
                  <div style={{ fontSize: '0.8rem', color: '#94a3b8', marginTop: '0.15rem' }}>
                    This application binds strictly to this physical computer. Telemetry and incidents remain private to this device and your verified account.
                  </div>
                </div>
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))', gap: '1rem' }}>
                <div style={{ background: '#090d16', border: '1px solid #1e293b', borderRadius: '8px', padding: '1rem' }}>
                  <label style={{ display: 'block', fontSize: '0.75rem', color: '#64748b', textTransform: 'uppercase', fontWeight: 700, marginBottom: '0.35rem' }}>
                    Detected Hardware Device ID
                  </label>
                  <div style={{ fontFamily: 'monospace', fontSize: '0.82rem', color: '#00f0ff', background: '#0f172a', padding: '0.5rem', borderRadius: '6px', border: '1px solid #1e293b', wordBreak: 'break-all' }}>
                    {hardwareId || 'Detecting hardware identity...'}
                  </div>
                </div>

                <div style={{ background: '#090d16', border: '1px solid #1e293b', borderRadius: '8px', padding: '1rem' }}>
                  <label style={{ display: 'block', fontSize: '0.75rem', color: '#64748b', textTransform: 'uppercase', fontWeight: 700, marginBottom: '0.35rem' }}>
                    Custom Device Name
                  </label>
                  <input
                    type="text"
                    value={deviceName}
                    onChange={(e) => setDeviceName(e.target.value)}
                    placeholder="e.g. Primary Work Laptop"
                    style={{
                      width: '100%',
                      padding: '0.5rem 0.75rem',
                      borderRadius: '6px',
                      border: '1px solid #334155',
                      background: '#0f172a',
                      color: '#f8fafc',
                      fontSize: '0.85rem'
                    }}
                  />
                </div>
              </div>

              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '1rem' }}>
                <div>
                  {enrollSuccess ? (
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.45rem', color: '#4ade80', fontSize: '0.85rem', fontWeight: 600 }}>
                      <CheckCircle2 size={16} />
                      <span>Device enrolled successfully! Ready for real-time protection.</span>
                    </div>
                  ) : enrollError ? (
                    <div style={{ color: '#f87171', fontSize: '0.82rem' }}>
                      {enrollError}
                    </div>
                  ) : (
                    <div style={{ color: '#94a3b8', fontSize: '0.8rem' }}>
                      Click below to enroll this laptop under account <strong>{user?.email || 'current user'}</strong>.
                    </div>
                  )}
                </div>

                <button
                  onClick={handleEnrollDevice}
                  disabled={isEnrolling || enrollSuccess}
                  style={{
                    padding: '0.65rem 1.4rem',
                    borderRadius: '8px',
                    border: 'none',
                    background: enrollSuccess ? '#10b981' : '#00f0ff',
                    color: '#090d16',
                    fontSize: '0.85rem',
                    fontWeight: 700,
                    cursor: (isEnrolling || enrollSuccess) ? 'not-allowed' : 'pointer'
                  }}
                >
                  {isEnrolling ? 'Enrolling...' : enrollSuccess ? '✓ Device Enrolled' : 'Confirm & Enroll This Laptop'}
                </button>
              </div>
            </div>
          )}

          {activeTab === 'data' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
              <p style={{ fontSize: '0.88rem', color: '#cbd5e1', lineHeight: 1.5, margin: 0 }}>
                CyberZen collects only the system indicators essential for autonomous defense and threat reconstruction:
              </p>

              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '0.75rem' }}>
                <div style={{ background: '#090d16', border: '1px solid #1e293b', borderRadius: '8px', padding: '0.85rem' }}>
                  <div style={{ fontWeight: 700, color: '#00f0ff', fontSize: '0.85rem', marginBottom: '0.2rem' }}>
                    Process Launches & Hierarchy
                  </div>
                  <div style={{ fontSize: '0.78rem', color: '#94a3b8', lineHeight: 1.4 }}>
                    PID, image path, and parent-child tree to identify suspicious executions (e.g. scripts spawned from temporary folders or commercial adware).
                  </div>
                </div>

                <div style={{ background: '#090d16', border: '1px solid #1e293b', borderRadius: '8px', padding: '0.85rem' }}>
                  <div style={{ fontWeight: 700, color: '#38bdf8', fontSize: '0.85rem', marginBottom: '0.2rem' }}>
                    Downloads & Desktop Files
                  </div>
                  <div style={{ fontSize: '0.78rem', color: '#94a3b8', lineHeight: 1.4 }}>
                    Metadata and cryptographic SHA-256 hashes of newly saved executables to detect double extensions and EICAR malware test signatures.
                  </div>
                </div>

                <div style={{ background: '#090d16', border: '1px solid #1e293b', borderRadius: '8px', padding: '0.85rem' }}>
                  <div style={{ fontWeight: 700, color: '#a855f7', fontSize: '0.85rem', marginBottom: '0.2rem' }}>
                    Network Sockets & Remote Endpoints
                  </div>
                  <div style={{ fontSize: '0.78rem', color: '#94a3b8', lineHeight: 1.4 }}>
                    Remote IP addresses and destination ports to classify private LAN traffic vs non-standard egress channels (e.g. ports 4444, 1337).
                  </div>
                </div>

                <div style={{ background: '#090d16', border: '1px solid #1e293b', borderRadius: '8px', padding: '0.85rem' }}>
                  <div style={{ fontWeight: 700, color: '#4ade80', fontSize: '0.85rem', marginBottom: '0.2rem' }}>
                    Browser Navigation (Via Extension)
                  </div>
                  <div style={{ fontSize: '0.78rem', color: '#94a3b8', lineHeight: 1.4 }}>
                    Navigated domain reputation and page/video title to detect phishing sites, separate piracy advisories from malware, and log web context.
                  </div>
                </div>
              </div>

              <div style={{ background: 'rgba(0, 240, 255, 0.05)', border: '1px solid rgba(0, 240, 255, 0.2)', borderRadius: '8px', padding: '0.75rem', fontSize: '0.8rem', color: '#94a3b8' }}>
                <strong style={{ color: '#00f0ff' }}>Storage Location:</strong> All telemetry is saved locally in <code>%LOCALAPPDATA%/CyberThreatAI/data/cyberthreat.db</code> (SQLite WAL mode). Data is never sold or shared with third parties.
              </div>
            </div>
          )}

          {activeTab === 'privacy' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
              <div style={{
                background: 'rgba(34, 197, 94, 0.08)',
                border: '1px solid rgba(34, 197, 94, 0.25)',
                borderRadius: '8px',
                padding: '1rem',
                color: '#4ade80',
                fontSize: '0.85rem',
                fontWeight: 600
              }}>
                Strict Privacy Boundary: Zero Intrusive Content Snooping
              </div>

              <p style={{ fontSize: '0.85rem', color: '#cbd5e1', lineHeight: 1.6, margin: 0 }}>
                CyberZen enforces non-invasive cybersecurity telemetry. It does <strong>NOT</strong>:
              </p>

              <ul style={{ color: '#94a3b8', fontSize: '0.82rem', lineHeight: 1.8, margin: 0, paddingLeft: '1.25rem' }}>
                <li>Record keystrokes or keylog text entered into applications or passwords.</li>
                <li>Capture webcam feeds, microphone audio, or full desktop screenshots.</li>
                <li>Read or upload the contents of your personal documents, emails, or private chat messages.</li>
                <li>Intercept or decrypt HTTPS SSL/TLS encrypted payload contents.</li>
                <li>Claim omniscient visibility into kernel activity that the OS security boundary does not expose.</li>
              </ul>
            </div>
          )}

          {activeTab === 'permissions' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
              <p style={{ fontSize: '0.85rem', color: '#cbd5e1', lineHeight: 1.5, margin: 0 }}>
                Actual Windows Permission Architecture:
              </p>

              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
                <div style={{ background: '#090d16', border: '1px solid #1e293b', borderRadius: '8px', padding: '0.85rem' }}>
                  <div style={{ fontWeight: 700, color: '#f8fafc', fontSize: '0.85rem' }}>
                    Standard User Privileges (Default & Recommended)
                  </div>
                  <div style={{ fontSize: '0.8rem', color: '#94a3b8', marginTop: '0.2rem' }}>
                    Enumerate user processes, watch Downloads and Desktop folders, inspect user sockets, and receive Chrome extension events. Runs without UAC elevation prompts.
                  </div>
                </div>

                <div style={{ background: '#090d16', border: '1px solid #1e293b', borderRadius: '8px', padding: '0.85rem' }}>
                  <div style={{ fontWeight: 700, color: '#fbbf24', fontSize: '0.85rem' }}>
                    Administrator Privileges (Optional)
                  </div>
                  <div style={{ fontSize: '0.8rem', color: '#94a3b8', marginTop: '0.2rem' }}>
                    Only required if you want full host socket inspection across system-owned processes (SYSTEM, LOCAL SERVICE) or to configure Windows Firewall rules.
                  </div>
                </div>
              </div>
            </div>
          )}

          {activeTab === 'controls' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
              <p style={{ fontSize: '0.85rem', color: '#cbd5e1', lineHeight: 1.5, margin: 0 }}>
                You maintain complete authority over monitoring. You can pause or stop monitoring at any time:
              </p>

              <div style={{ display: 'flex', gap: '1rem', flexWrap: 'wrap' }}>
                <button
                  onClick={() => onToggleMonitoring && onToggleMonitoring(!isMonitoringActive)}
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: '0.5rem',
                    padding: '0.65rem 1.15rem',
                    borderRadius: '8px',
                    border: '1px solid #334155',
                    background: '#090d16',
                    color: isMonitoringActive ? '#fbbf24' : '#4ade80',
                    fontSize: '0.82rem',
                    fontWeight: 600,
                    cursor: 'pointer'
                  }}
                >
                  <Power size={14} />
                  <span>{isMonitoringActive ? 'Pause Host Monitoring' : 'Resume Host Monitoring'}</span>
                </button>

                <button
                  onClick={handleWithdrawConsent}
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: '0.5rem',
                    padding: '0.65rem 1.15rem',
                    borderRadius: '8px',
                    border: '1px solid rgba(239, 68, 68, 0.4)',
                    background: 'rgba(239, 68, 68, 0.1)',
                    color: '#f87171',
                    fontSize: '0.82rem',
                    fontWeight: 600,
                    cursor: 'pointer'
                  }}
                >
                  <AlertTriangle size={14} />
                  <span>Withdraw Consent & Stop</span>
                </button>
              </div>

              <div style={{ fontSize: '0.78rem', color: '#64748b', lineHeight: 1.5 }}>
                Stopping the application gracefully shuts down all background observation threads, closes SQLite connections cleanly, and leaves system files untouched.
              </div>
            </div>
          )}
        </div>

        {/* Footer & Acknowledge */}
        <div style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          borderTop: '1px solid #1e293b',
          paddingTop: '1rem',
          flexWrap: 'wrap',
          gap: '1rem'
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <input
              type="checkbox"
              id="ack-consent"
              checked={consentAcknowledged}
              onChange={(e) => setConsentAcknowledged(e.target.checked)}
              style={{ accentColor: '#00f0ff', cursor: 'pointer', width: '16px', height: '16px' }}
            />
            <label htmlFor="ack-consent" style={{ fontSize: '0.82rem', color: '#cbd5e1', cursor: 'pointer' }}>
              I have reviewed the monitoring scope and grant permission to monitor this enrolled device
            </label>
          </div>

          <button
            onClick={handleComplete}
            disabled={!consentAcknowledged}
            style={{
              padding: '0.65rem 1.5rem',
              borderRadius: '8px',
              border: 'none',
              background: consentAcknowledged ? '#00f0ff' : '#1e293b',
              color: consentAcknowledged ? '#090d16' : '#64748b',
              fontSize: '0.85rem',
              fontWeight: 700,
              cursor: consentAcknowledged ? 'pointer' : 'not-allowed',
              transition: 'all 0.15s ease'
            }}
          >
            Acknowledge & Continue
          </button>
        </div>

      </div>
    </div>
  );
}
