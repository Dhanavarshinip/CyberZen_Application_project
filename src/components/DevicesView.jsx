import React, { useState, useEffect } from 'react';
import { Laptop, Plus, CheckCircle2, Wifi, WifiOff, Shield, RefreshCw, AlertCircle, Trash2, X, Edit3, Key, ShieldAlert, Copy, Check } from 'lucide-react';
import { useAuth } from '../context/AuthContext';
import { useTheme } from '../context/ThemeContext';
import { apiClient } from '../services/apiClient';

export default function DevicesView({ onDeviceRegistered }) {
  const { user } = useAuth();
  const { isDark } = useTheme();

  const cardBg = isDark ? '#0a0a0a' : '#ffffff';
  const cardBorder = isDark ? '#1e1e1e' : '#e2e8f0';
  const textPrimary = isDark ? '#ffffff' : '#0f172a';
  const textSecondary = isDark ? '#cbd5e1' : '#475569';
  const textMuted = isDark ? '#94a3b8' : '#64748b';
  const subtleBg = isDark ? '#141414' : '#f8fafc';
  const [devices, setDevices] = useState([]);
  const [isLoading, setIsLoading] = useState(false);
  const [showAddModal, setShowAddModal] = useState(false);
  const [newDeviceName, setNewDeviceName] = useState('');
  const [newDeviceId, setNewDeviceId] = useState('');
  const [newOsInfo, setNewOsInfo] = useState('Windows 11 (64-bit)');

  // Enrolled device key confirmation modal
  const [enrolledResult, setEnrolledResult] = useState(null);
  const [copiedKey, setCopiedKey] = useState(false);

  // Rename state
  const [renamingDevice, setRenamingDevice] = useState(null);
  const [renameValue, setRenameValue] = useState('');
  const [isRenaming, setIsRenaming] = useState(false);

  // Revoke state
  const [confirmRevoke, setConfirmRevoke] = useState(null);
  const [isRevoking, setIsRevoking] = useState(false);

  // Device removal state
  const [confirmRemove, setConfirmRemove] = useState(null);
  const [removeError, setRemoveError] = useState('');
  const [removeResult, setRemoveResult] = useState(null);
  const [isRemoving, setIsRemoving] = useState(false);

  const fetchDevices = async () => {
    if (!user?.id) return;
    setIsLoading(true);
    try {
      const res = await apiClient.getDevices(user.id);
      if (res && res.devices) {
        setDevices(res.devices);
      }
    } catch (err) {
      console.warn('Failed to load devices:', err);
    } finally {
      setIsLoading(false);
    }
  };

  const isDeviceConnected = (dev) => {
    if (dev.is_revoked || dev.status === 'REVOKED') return false;
    if (!dev.last_seen) return false;
    const lastSeen = new Date(dev.last_seen);
    const diff = Date.now() - lastSeen.getTime();
    return diff < 5 * 60 * 1000;
  };

  const formatLastSeen = (ts) => {
    if (!ts) return 'Never';
    const d = new Date(ts);
    const diff = Date.now() - d.getTime();
    if (diff < 60000) return 'Just now';
    if (diff < 3600000) return `${Math.floor(diff / 60000)}m ago`;
    if (diff < 86400000) return `${Math.floor(diff / 3600000)}h ago`;
    return d.toLocaleDateString();
  };

  useEffect(() => {
    fetchDevices();
  }, [user]);

  const handleEnrollDevice = async (e) => {
    e.preventDefault();
    if (!newDeviceName.trim()) return;

    try {
      const res = await apiClient.enrollDevice(
        newDeviceName.trim(),
        newOsInfo.trim(),
        newDeviceId.trim() || null,
        user.id
      );
      setShowAddModal(false);
      setNewDeviceName('');
      setNewDeviceId('');
      setEnrolledResult(res.device);
      await fetchDevices();
      if (onDeviceRegistered) onDeviceRegistered();
    } catch (err) {
      alert('Failed to enroll device: ' + err.message);
    }
  };

  const handleRename = async (e) => {
    e.preventDefault();
    if (!renamingDevice || !renameValue.trim()) return;
    setIsRenaming(true);
    try {
      await apiClient.renameDevice(renamingDevice.device_id, renameValue.trim());
      setRenamingDevice(null);
      setRenameValue('');
      await fetchDevices();
      if (onDeviceRegistered) onDeviceRegistered();
    } catch (err) {
      alert('Rename failed: ' + err.message);
    } finally {
      setIsRenaming(false);
    }
  };

  const handleRevoke = async () => {
    if (!confirmRevoke) return;
    setIsRevoking(true);
    try {
      await apiClient.revokeDevice(confirmRevoke.device_id);
      setConfirmRevoke(null);
      await fetchDevices();
      if (onDeviceRegistered) onDeviceRegistered();
    } catch (err) {
      alert('Revocation failed: ' + err.message);
    } finally {
      setIsRevoking(false);
    }
  };

  const handleRemoveDevice = async () => {
    if (!confirmRemove) return;
    setIsRemoving(true);
    setRemoveError('');

    try {
      await apiClient.removeDevice(confirmRemove.device_id);
      setRemoveResult(confirmRemove);
      setConfirmRemove(null);
      await fetchDevices();
      if (onDeviceRegistered) onDeviceRegistered();
      setTimeout(() => setRemoveResult(null), 5000);
    } catch (err) {
      setRemoveError(err.message || 'Removal failed. Please try again.');
    } finally {
      setIsRemoving(false);
    }
  };

  const copyKeyToClipboard = (key) => {
    if (!key) return;
    navigator.clipboard.writeText(key);
    setCopiedKey(true);
    setTimeout(() => setCopiedKey(false), 2000);
  };

  return (
    <div style={{ padding: '2rem 1.5rem', maxWidth: '1100px', margin: '0 auto', display: 'flex', flexDirection: 'column', gap: '2rem', color: textPrimary }}>
      
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '1rem' }}>
        <div>
          <h2 style={{ fontSize: '1.6rem', fontWeight: 800, color: textPrimary, margin: '0 0 0.35rem 0', letterSpacing: '-0.02em' }}>
            Registered Devices
          </h2>
          <p style={{ fontSize: '0.85rem', color: textMuted, margin: 0 }}>
            Physical computers and laptops authorized under your security monitoring account.
          </p>
        </div>

        <div style={{ display: 'flex', gap: '0.75rem' }}>
          <button
            onClick={fetchDevices}
            disabled={isLoading}
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '0.45rem',
              padding: '0.55rem 1rem',
              borderRadius: '8px',
              border: `1px solid ${cardBorder}`,
              background: subtleBg,
              color: textSecondary,
              fontSize: '0.85rem',
              fontWeight: 600,
              cursor: isLoading ? 'not-allowed' : 'pointer'
            }}
          >
            <RefreshCw size={14} className={isLoading ? 'animate-spin' : ''} style={{ color: isDark ? '#00f0ff' : '#0284c7' }} />
            <span>Refresh</span>
          </button>

          <button
            onClick={() => setShowAddModal(true)}
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '0.45rem',
              padding: '0.55rem 1.15rem',
              borderRadius: '8px',
              border: 'none',
              background: '#00f0ff',
              color: '#090d16',
              fontSize: '0.85rem',
              fontWeight: 700,
              cursor: 'pointer',
              boxShadow: '0 0 15px rgba(0, 240, 255, 0.25)'
            }}
          >
            <Plus size={16} />
            <span>Enroll Device</span>
          </button>
        </div>
      </div>

      {/* Removal Notification Banner */}
      {removeResult && (
        <div style={{
          background: 'rgba(34, 197, 94, 0.1)',
          border: '1px solid rgba(34, 197, 94, 0.3)',
          borderRadius: '10px',
          padding: '0.85rem 1.25rem',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          color: '#4ade80',
          fontSize: '0.85rem',
          fontWeight: 600
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <CheckCircle2 size={16} />
            <span>Device removed successfully. Historical telemetry data preserved.</span>
          </div>
          <button
            onClick={() => setRemoveResult(null)}
            style={{ background: 'none', border: 'none', color: '#4ade80', cursor: 'pointer', padding: '0.2rem' }}
          >
            <X size={15} />
          </button>
        </div>
      )}

      {/* Devices Grid */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: '1.25rem' }}>
        {devices.length === 0 ? (
          <div style={{
            gridColumn: '1 / -1',
            background: '#0f172a',
            border: '1px solid #1e293b',
            borderRadius: '12px',
            padding: '3.5rem 2rem',
            textAlign: 'center',
            color: '#94a3b8'
          }}>
            <Laptop size={40} style={{ color: '#00f0ff', margin: '0 auto 0.75rem auto', display: 'block' }} />
            <div style={{ fontSize: '1rem', fontWeight: 700, color: '#f8fafc', marginBottom: '0.35rem' }}>
              No devices registered yet.
            </div>
            <div style={{ fontSize: '0.82rem', lineHeight: 1.6, maxWidth: '500px', margin: '0 auto' }}>
              To enroll this computer or a secondary laptop, click <strong>Enroll Device</strong> above. CyberZen will generate a persistent device identity and secure credentials.
            </div>
          </div>
        ) : (
          devices.map(dev => {
            const isRevoked = dev.is_revoked || dev.status === 'REVOKED';
            const connected = isDeviceConnected(dev);
            
            return (
              <div
                key={dev.device_id}
                style={{
                  background: cardBg,
                  border: `1px solid ${isRevoked ? 'rgba(239, 68, 68, 0.4)' : connected ? (isDark ? 'rgba(0, 240, 255, 0.35)' : 'rgba(2, 132, 199, 0.35)') : cardBorder}`,
                  borderRadius: '12px',
                  padding: '1.25rem',
                  display: 'flex',
                  flexDirection: 'column',
                  justifyContent: 'space-between',
                  gap: '1rem',
                  position: 'relative',
                  boxShadow: isDark ? '0 4px 16px rgba(0, 0, 0, 0.5)' : '0 1px 4px rgba(0, 0, 0, 0.05)'
                }}
              >
                <div>
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.75rem' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem' }}>
                      <div style={{
                        width: '38px',
                        height: '38px',
                        borderRadius: '8px',
                        background: isRevoked ? 'rgba(239, 68, 68, 0.1)' : connected ? (isDark ? 'rgba(0, 240, 255, 0.15)' : 'rgba(2, 132, 199, 0.1)') : (isDark ? 'rgba(255, 255, 255, 0.05)' : '#f1f5f9'),
                        color: isRevoked ? '#f87171' : connected ? (isDark ? '#00f0ff' : '#0284c7') : textMuted,
                        border: `1px solid ${isRevoked ? 'rgba(239, 68, 68, 0.3)' : connected ? (isDark ? 'rgba(0, 240, 255, 0.3)' : 'rgba(2, 132, 199, 0.3)') : cardBorder}`,
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'center'
                      }}>
                        <Laptop size={18} />
                      </div>
                      <div>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '0.45rem' }}>
                          <h3 style={{ fontSize: '0.95rem', fontWeight: 700, color: textPrimary, margin: 0 }}>
                            {dev.device_name || 'Primary Laptop'}
                          </h3>
                          <button
                            onClick={() => {
                              setRenamingDevice(dev);
                              setRenameValue(dev.device_name || '');
                            }}
                            title="Rename Device"
                            style={{ background: 'none', border: 'none', color: '#64748b', cursor: 'pointer', padding: '0.1rem' }}
                          >
                            <Edit3 size={13} />
                          </button>
                        </div>
                        <div style={{ fontSize: '0.75rem', color: '#94a3b8' }}>
                          {dev.os_info || 'Windows'}
                        </div>
                      </div>
                    </div>

                    <div style={{
                      display: 'flex',
                      alignItems: 'center',
                      gap: '0.35rem',
                      padding: '0.2rem 0.55rem',
                      borderRadius: '20px',
                      background: isRevoked
                        ? 'rgba(239, 68, 68, 0.15)'
                        : connected
                        ? 'rgba(34, 197, 94, 0.15)'
                        : 'rgba(245, 158, 11, 0.15)',
                      border: `1px solid ${
                        isRevoked
                          ? 'rgba(239, 68, 68, 0.4)'
                          : connected
                          ? 'rgba(34, 197, 94, 0.4)'
                          : 'rgba(245, 158, 11, 0.4)'
                      }`,
                      fontSize: '0.7rem',
                      fontWeight: 700,
                      color: isRevoked ? '#f87171' : connected ? '#4ade80' : '#fbbf24'
                    }}>
                      {isRevoked ? <ShieldAlert size={12} /> : connected ? <Wifi size={12} /> : <WifiOff size={12} />}
                      <span>{isRevoked ? 'REVOKED' : connected ? 'ONLINE' : 'DISCONNECTED'}</span>
                    </div>
                  </div>

                  {/* Device ID & Stats */}
                  <div style={{
                    background: '#090d16',
                    borderRadius: '8px',
                    border: '1px solid #1e293b',
                    padding: '0.75rem',
                    display: 'flex',
                    flexDirection: 'column',
                    gap: '0.45rem',
                    fontSize: '0.78rem'
                  }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                      <span style={{ color: '#94a3b8' }}>Device ID</span>
                      <span style={{ color: '#00f0ff', fontFamily: 'monospace', fontWeight: 600 }}>
                        {dev.device_id.length > 20 ? `${dev.device_id.slice(0, 10)}...${dev.device_id.slice(-6)}` : dev.device_id}
                      </span>
                    </div>
                    <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                      <span style={{ color: '#94a3b8' }}>Last Seen</span>
                      <span style={{ color: '#f8fafc', fontWeight: 500 }}>{formatLastSeen(dev.last_seen)}</span>
                    </div>
                    <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                      <span style={{ color: '#94a3b8' }}>Enrolled On</span>
                      <span style={{ color: '#f8fafc', fontWeight: 500 }}>
                        {dev.created_at ? new Date(dev.created_at).toLocaleDateString() : 'Active'}
                      </span>
                    </div>
                  </div>
                </div>

                {/* Bottom Actions */}
                <div style={{
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  paddingTop: '0.5rem',
                  borderTop: '1px solid #1e293b',
                  fontSize: '0.75rem'
                }}>
                  <span style={{ color: '#64748b' }}>Account Isolated</span>
                  <div style={{ display: 'flex', gap: '0.45rem' }}>
                    {!isRevoked && (
                      <button
                        onClick={() => setConfirmRevoke(dev)}
                        title="Revoke device credentials"
                        style={{
                          padding: '0.3rem 0.6rem',
                          borderRadius: '6px',
                          border: '1px solid rgba(245, 158, 11, 0.4)',
                          background: 'rgba(245, 158, 11, 0.1)',
                          color: '#fbbf24',
                          fontSize: '0.72rem',
                          fontWeight: 600,
                          cursor: 'pointer'
                        }}
                      >
                        Revoke Access
                      </button>
                    )}
                    <button
                      onClick={() => setConfirmRemove(dev)}
                      title="Remove device registration"
                      style={{
                        display: 'flex',
                        alignItems: 'center',
                        gap: '0.3rem',
                        padding: '0.3rem 0.6rem',
                        borderRadius: '6px',
                        border: '1px solid rgba(239, 68, 68, 0.4)',
                        background: 'rgba(239, 68, 68, 0.1)',
                        color: '#f87171',
                        fontSize: '0.72rem',
                        fontWeight: 600,
                        cursor: 'pointer'
                      }}
                    >
                      <Trash2 size={12} />
                      <span>Remove</span>
                    </button>
                  </div>
                </div>
              </div>
            );
          })
        )}
      </div>

      {/* Enroll Device Modal */}
      {showAddModal && (
        <div style={{
          position: 'fixed',
          top: 0, left: 0, right: 0, bottom: 0,
          background: 'rgba(9, 13, 22, 0.8)',
          backdropFilter: 'blur(4px)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          zIndex: 100,
          padding: '1rem'
        }}>
          <div style={{
            background: '#0f172a',
            border: '1px solid #1e293b',
            borderRadius: '12px',
            padding: '2rem',
            width: '100%',
            maxWidth: '440px',
            boxShadow: '0 20px 25px -5px rgba(0, 0, 0, 0.5)'
          }}>
            <h3 style={{ fontSize: '1.2rem', fontWeight: 800, color: '#f8fafc', margin: '0 0 0.5rem 0' }}>
              Enroll Device
            </h3>
            <p style={{ fontSize: '0.85rem', color: '#94a3b8', margin: '0 0 1.25rem 0' }}>
              Issue persistent credentials for this computer or a secondary machine.
            </p>

            <form onSubmit={handleEnrollDevice} style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
              <div>
                <label style={{ display: 'block', fontSize: '0.8rem', fontWeight: 600, color: '#cbd5e1', marginBottom: '0.35rem' }}>
                  Device Name
                </label>
                <input
                  type="text"
                  required
                  placeholder="e.g. Workstation Laptop"
                  value={newDeviceName}
                  onChange={(e) => setNewDeviceName(e.target.value)}
                  style={{
                    width: '100%',
                    padding: '0.65rem 0.85rem',
                    borderRadius: '8px',
                    border: '1px solid #334155',
                    background: '#111726',
                    color: '#f8fafc',
                    fontSize: '0.85rem',
                    boxSizing: 'border-box'
                  }}
                />
              </div>

              <div>
                <label style={{ display: 'block', fontSize: '0.8rem', fontWeight: 600, color: '#cbd5e1', marginBottom: '0.35rem' }}>
                  Device ID (Optional - auto-generated if blank)
                </label>
                <input
                  type="text"
                  placeholder="Leave blank for unique auto-generated ID"
                  value={newDeviceId}
                  onChange={(e) => setNewDeviceId(e.target.value)}
                  style={{
                    width: '100%',
                    padding: '0.65rem 0.85rem',
                    borderRadius: '8px',
                    border: '1px solid #334155',
                    background: '#111726',
                    color: '#f8fafc',
                    fontSize: '0.85rem',
                    boxSizing: 'border-box'
                  }}
                />
              </div>

              <div>
                <label style={{ display: 'block', fontSize: '0.8rem', fontWeight: 600, color: '#cbd5e1', marginBottom: '0.35rem' }}>
                  Operating System
                </label>
                <input
                  type="text"
                  value={newOsInfo}
                  onChange={(e) => setNewOsInfo(e.target.value)}
                  style={{
                    width: '100%',
                    padding: '0.65rem 0.85rem',
                    borderRadius: '8px',
                    border: '1px solid #334155',
                    background: '#111726',
                    color: '#f8fafc',
                    fontSize: '0.85rem',
                    boxSizing: 'border-box'
                  }}
                />
              </div>

              <div style={{ display: 'flex', gap: '0.75rem', marginTop: '0.5rem' }}>
                <button
                  type="button"
                  onClick={() => setShowAddModal(false)}
                  style={{
                    flex: 1,
                    padding: '0.75rem',
                    borderRadius: '8px',
                    border: '1px solid #334155',
                    background: '#1e293b',
                    color: '#cbd5e1',
                    fontSize: '0.85rem',
                    fontWeight: 600,
                    cursor: 'pointer'
                  }}
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  style={{
                    flex: 1,
                    padding: '0.75rem',
                    borderRadius: '8px',
                    border: 'none',
                    background: '#00f0ff',
                    color: '#090d16',
                    fontSize: '0.85rem',
                    fontWeight: 700,
                    cursor: 'pointer'
                  }}
                >
                  Enroll
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Enrolled Confirmation Dialog */}
      {enrolledResult && (
        <div style={{
          position: 'fixed',
          top: 0, left: 0, right: 0, bottom: 0,
          background: 'rgba(9, 13, 22, 0.85)',
          backdropFilter: 'blur(5px)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          zIndex: 110,
          padding: '1rem'
        }}>
          <div style={{
            background: '#0f172a',
            border: '1px solid #00f0ff',
            borderRadius: '12px',
            padding: '2rem',
            width: '100%',
            maxWidth: '480px',
            boxShadow: '0 0 30px rgba(0, 240, 255, 0.2)'
          }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem', marginBottom: '1rem' }}>
              <div style={{ width: '40px', height: '40px', borderRadius: '10px', background: 'rgba(0, 240, 255, 0.15)', display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#00f0ff' }}>
                <Key size={22} />
              </div>
              <div>
                <h3 style={{ fontSize: '1.2rem', fontWeight: 800, color: '#f8fafc', margin: 0 }}>
                  Device Enrolled Successfully
                </h3>
                <p style={{ fontSize: '0.8rem', color: '#94a3b8', margin: 0 }}>
                  Persistent credentials generated
                </p>
              </div>
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem', marginBottom: '1.5rem' }}>
              <div>
                <span style={{ fontSize: '0.75rem', color: '#94a3b8', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Device ID</span>
                <div style={{ fontFamily: 'monospace', fontSize: '0.9rem', color: '#00f0ff', background: '#090d16', padding: '0.5rem 0.75rem', borderRadius: '6px', border: '1px solid #1e293b', marginTop: '0.25rem' }}>
                  {enrolledResult.device_id}
                </div>
              </div>

              {enrolledResult.device_key && (
                <div>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <span style={{ fontSize: '0.75rem', color: '#94a3b8', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Device Authentication Secret</span>
                    <button
                      onClick={() => copyKeyToClipboard(enrolledResult.device_key)}
                      style={{ background: 'none', border: 'none', color: '#00f0ff', fontSize: '0.75rem', cursor: 'pointer', display: 'flex', alignItems: 'center', gap: '0.25rem' }}
                    >
                      {copiedKey ? <Check size={12} /> : <Copy size={12} />}
                      <span>{copiedKey ? 'Copied' : 'Copy Secret'}</span>
                    </button>
                  </div>
                  <div style={{ fontFamily: 'monospace', fontSize: '0.85rem', color: '#f8fafc', background: '#090d16', padding: '0.5rem 0.75rem', borderRadius: '6px', border: '1px solid #1e293b', marginTop: '0.25rem', wordBreak: 'break-all' }}>
                    {enrolledResult.device_key}
                  </div>
                </div>
              )}
            </div>

            <button
              onClick={() => setEnrolledResult(null)}
              style={{
                width: '100%',
                padding: '0.75rem',
                borderRadius: '8px',
                border: 'none',
                background: '#00f0ff',
                color: '#090d16',
                fontWeight: 700,
                fontSize: '0.9rem',
                cursor: 'pointer'
              }}
            >
              Done
            </button>
          </div>
        </div>
      )}

      {/* Rename Device Modal */}
      {renamingDevice && (
        <div style={{
          position: 'fixed',
          top: 0, left: 0, right: 0, bottom: 0,
          background: 'rgba(9, 13, 22, 0.8)',
          backdropFilter: 'blur(4px)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          zIndex: 100,
          padding: '1rem'
        }}>
          <div style={{
            background: '#0f172a',
            border: '1px solid #1e293b',
            borderRadius: '12px',
            padding: '2rem',
            width: '100%',
            maxWidth: '420px',
            boxShadow: '0 20px 25px -5px rgba(0, 0, 0, 0.5)'
          }}>
            <h3 style={{ fontSize: '1.2rem', fontWeight: 800, color: '#f8fafc', margin: '0 0 0.5rem 0' }}>
              Rename Device
            </h3>
            <p style={{ fontSize: '0.85rem', color: '#94a3b8', margin: '0 0 1.25rem 0' }}>
              Enter a new friendly name for <strong>{renamingDevice.device_id}</strong>.
            </p>

            <form onSubmit={handleRename} style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
              <div>
                <input
                  type="text"
                  required
                  value={renameValue}
                  onChange={(e) => setRenameValue(e.target.value)}
                  style={{
                    width: '100%',
                    padding: '0.75rem 0.95rem',
                    borderRadius: '8px',
                    border: '1px solid #334155',
                    background: '#111726',
                    color: '#f8fafc',
                    fontSize: '0.9rem',
                    boxSizing: 'border-box'
                  }}
                />
              </div>

              <div style={{ display: 'flex', gap: '0.75rem', marginTop: '0.5rem' }}>
                <button
                  type="button"
                  onClick={() => setRenamingDevice(null)}
                  disabled={isRenaming}
                  style={{
                    flex: 1,
                    padding: '0.75rem',
                    borderRadius: '8px',
                    border: '1px solid #334155',
                    background: '#1e293b',
                    color: '#cbd5e1',
                    fontSize: '0.85rem',
                    fontWeight: 600,
                    cursor: 'pointer'
                  }}
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={isRenaming}
                  style={{
                    flex: 1,
                    padding: '0.75rem',
                    borderRadius: '8px',
                    border: 'none',
                    background: '#00f0ff',
                    color: '#090d16',
                    fontSize: '0.85rem',
                    fontWeight: 700,
                    cursor: isRenaming ? 'not-allowed' : 'pointer'
                  }}
                >
                  {isRenaming ? 'Saving...' : 'Save Name'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Revoke Device Confirmation Modal */}
      {confirmRevoke && (
        <div style={{
          position: 'fixed',
          top: 0, left: 0, right: 0, bottom: 0,
          background: 'rgba(9, 13, 22, 0.8)',
          backdropFilter: 'blur(4px)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          zIndex: 100,
          padding: '1rem'
        }}>
          <div style={{
            background: '#0f172a',
            border: '1px solid rgba(245, 158, 11, 0.4)',
            borderRadius: '12px',
            padding: '2rem',
            width: '100%',
            maxWidth: '440px',
            boxShadow: '0 20px 25px -5px rgba(0, 0, 0, 0.5)'
          }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginBottom: '1rem' }}>
              <div style={{ width: '40px', height: '40px', borderRadius: '10px', background: 'rgba(245, 158, 11, 0.15)', color: '#fbbf24', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                <ShieldAlert size={20} />
              </div>
              <div>
                <h3 style={{ fontSize: '1.2rem', fontWeight: 800, color: '#f8fafc', margin: 0 }}>
                  Revoke Device Access
                </h3>
                <p style={{ fontSize: '0.8rem', color: '#94a3b8', margin: 0 }}>
                  Disable telemetry from this device
                </p>
              </div>
            </div>

            <p style={{ fontSize: '0.88rem', color: '#cbd5e1', lineHeight: 1.5, margin: '0 0 1rem 0' }}>
              Are you sure you want to revoke credentials for <strong style={{ color: '#f8fafc' }}>{confirmRevoke.device_name || confirmRevoke.device_id}</strong>?
            </p>

            <div style={{ background: '#090d16', border: '1px solid #1e293b', borderRadius: '8px', padding: '0.75rem', marginBottom: '1.25rem', fontSize: '0.8rem', color: '#94a3b8' }}>
              Further telemetry transmissions from this device will be blocked. All historical activity records and incidents remain preserved.
            </div>

            <div style={{ display: 'flex', gap: '0.75rem' }}>
              <button
                type="button"
                onClick={() => setConfirmRevoke(null)}
                disabled={isRevoking}
                style={{
                  flex: 1,
                  padding: '0.75rem',
                  borderRadius: '8px',
                  border: '1px solid #334155',
                  background: '#1e293b',
                  color: '#cbd5e1',
                  fontSize: '0.85rem',
                  fontWeight: 600,
                  cursor: 'pointer'
                }}
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={handleRevoke}
                disabled={isRevoking}
                style={{
                  flex: 1,
                  padding: '0.75rem',
                  borderRadius: '8px',
                  border: 'none',
                  background: '#f59e0b',
                  color: '#090d16',
                  fontSize: '0.85rem',
                  fontWeight: 700,
                  cursor: isRevoking ? 'not-allowed' : 'pointer'
                }}
              >
                {isRevoking ? 'Revoking...' : 'Confirm Revoke'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Remove Device Confirmation Modal */}
      {confirmRemove && (
        <div style={{
          position: 'fixed',
          top: 0, left: 0, right: 0, bottom: 0,
          background: 'rgba(9, 13, 22, 0.8)',
          backdropFilter: 'blur(4px)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          zIndex: 100,
          padding: '1rem'
        }}>
          <div style={{
            background: '#0f172a',
            border: '1px solid rgba(239, 68, 68, 0.4)',
            borderRadius: '12px',
            padding: '2rem',
            width: '100%',
            maxWidth: '440px',
            boxShadow: '0 20px 25px -5px rgba(0, 0, 0, 0.5)'
          }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginBottom: '1rem' }}>
              <div style={{
                width: '40px', height: '40px', borderRadius: '10px',
                background: 'rgba(239, 68, 68, 0.15)', color: '#f87171',
                border: '1px solid rgba(239, 68, 68, 0.3)',
                display: 'flex', alignItems: 'center', justifyContent: 'center'
              }}>
                <Trash2 size={20} />
              </div>
              <div>
                <h3 style={{ fontSize: '1.2rem', fontWeight: 800, color: '#f8fafc', margin: 0 }}>
                  Remove Device
                </h3>
                <p style={{ fontSize: '0.8rem', color: '#94a3b8', margin: 0 }}>
                  Confirm removal from registry
                </p>
              </div>
            </div>

            <p style={{ fontSize: '0.88rem', color: '#cbd5e1', lineHeight: 1.5, margin: '0 0 1rem 0' }}>
              Are you sure you want to remove <strong style={{ color: '#f8fafc' }}>{confirmRemove.device_name || confirmRemove.device_id}</strong>?
            </p>

            <div style={{
              background: 'rgba(34, 197, 94, 0.1)',
              border: '1px solid rgba(34, 197, 94, 0.3)',
              borderRadius: '8px',
              padding: '0.75rem',
              marginBottom: '1.25rem',
              fontSize: '0.8rem',
              color: '#4ade80',
              display: 'flex',
              gap: '0.5rem',
              alignItems: 'center'
            }}>
              <CheckCircle2 size={16} style={{ flexShrink: 0 }} />
              <span>Historical events and incidents associated with this device will remain safely preserved in your database.</span>
            </div>

            {removeError && (
              <div style={{
                background: 'rgba(239, 68, 68, 0.15)',
                border: '1px solid rgba(239, 68, 68, 0.3)',
                borderRadius: '8px',
                padding: '0.65rem 0.85rem',
                marginBottom: '1rem',
                fontSize: '0.82rem',
                color: '#f87171'
              }}>
                {removeError}
              </div>
            )}

            <div style={{ display: 'flex', gap: '0.75rem' }}>
              <button
                type="button"
                onClick={() => { setConfirmRemove(null); setRemoveError(''); }}
                disabled={isRemoving}
                style={{
                  flex: 1,
                  padding: '0.75rem',
                  borderRadius: '8px',
                  border: '1px solid #334155',
                  background: '#1e293b',
                  color: '#cbd5e1',
                  fontSize: '0.85rem',
                  fontWeight: 600,
                  cursor: isRemoving ? 'not-allowed' : 'pointer'
                }}
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={handleRemoveDevice}
                disabled={isRemoving}
                style={{
                  flex: 1,
                  padding: '0.75rem',
                  borderRadius: '8px',
                  border: 'none',
                  background: '#ef4444',
                  color: '#ffffff',
                  fontSize: '0.85rem',
                  fontWeight: 700,
                  cursor: isRemoving ? 'not-allowed' : 'pointer'
                }}
              >
                {isRemoving ? 'Removing...' : 'Confirm Remove'}
              </button>
            </div>
          </div>
        </div>
      )}

    </div>
  );
}
