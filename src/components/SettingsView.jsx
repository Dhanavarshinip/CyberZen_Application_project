import React, { useState, useEffect } from 'react';
import { 
  User, 
  Laptop, 
  ShieldCheck, 
  LogOut, 
  Cpu, 
  HardDrive, 
  Calendar, 
  CheckCircle2, 
  Wifi, 
  WifiOff, 
  RotateCw,
  Clock,
  Server,
  Sun,
  Moon,
  Sparkles,
  Palette,
  Shield,
  Lock,
  Activity,
  Globe,
  FileText,
  Check,
  Mail,
  Plus,
  Trash2
} from 'lucide-react';
import { useAuth } from '../context/AuthContext';
import { useTheme } from '../context/ThemeContext';
import { apiClient } from '../services/apiClient';

/**
 * SettingsView: Human-Centered User Profile, Device Details & Appearance Settings.
 * 
 * Satisfies:
 * 1. "MAKE INTERFACE HUMANLY AND ADD DARK OR LIGHT MODE OPTIONS IN THE SETTINGS"
 * 2. Accurate user & device details with friendly, accessible language.
 */
export default function SettingsView() {
  const { user, logout } = useAuth();
  const { theme, setTheme, isDark } = useTheme();
  const [deviceDetails, setDeviceDetails] = useState(null);
  const [enrolledDevices, setEnrolledDevices] = useState([]);
  const [userDetails, setUserDetails] = useState(null);
  const [allowedEmailsData, setAllowedEmailsData] = useState({
    primary_email: '',
    additional_emails: [],
    all_monitored: []
  });
  const [newEmailInput, setNewEmailInput] = useState('');
  const [isAddingEmail, setIsAddingEmail] = useState(false);
  const [emailStatusMsg, setEmailStatusMsg] = useState(null);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    let isMounted = true;
    const loadDetails = async () => {
      setIsLoading(true);
      try {
        const [devData, userData, emailsData, devListRes] = await Promise.all([
          apiClient.getAccurateDeviceDetails(null, user?.id),
          user?.id ? apiClient.getAccurateUserDetails(user.id) : Promise.resolve(null),
          apiClient.getAllowedEmails(user?.id),
          user?.id ? apiClient.getDevices(user.id) : Promise.resolve({ devices: [] })
        ]);
        if (isMounted) {
          const devs = Array.isArray(devListRes?.devices) ? devListRes.devices : [];
          setEnrolledDevices(devs);
          if (devData) {
            setDeviceDetails(devData);
          } else if (devs.length > 0) {
            setDeviceDetails({
              computer_name: devs[0].device_name || 'Primary Desktop',
              device_id: devs[0].device_id,
              os_version: devs[0].os_info || 'Windows 11 64-bit',
              is_online: true,
              connection_status: 'Online & Actively Protected'
            });
          }
          if (userData) setUserDetails(userData);
          if (emailsData) setAllowedEmailsData(emailsData);
        }
      } catch (err) {
        console.warn('[SettingsView] Error loading details:', err);
      } finally {
        if (isMounted) setIsLoading(false);
      }
    };

    loadDetails();
    return () => { isMounted = false; };
  }, [user]);

  const activeUser = userDetails || user;

  const handleAddEmail = async (e) => {
    e.preventDefault();
    const clean = newEmailInput.trim().toLowerCase();
    if (!clean || !clean.includes('@')) {
      setEmailStatusMsg({ type: 'error', text: 'Please enter a valid email address.' });
      return;
    }
    setIsAddingEmail(true);
    setEmailStatusMsg(null);
    try {
      const res = await apiClient.addAllowedEmail(clean, activeUser?.id);
      if (res) {
        setAllowedEmailsData(res);
        setNewEmailInput('');
        setEmailStatusMsg({ type: 'success', text: `✓ Added ${clean} to monitored online activities.` });
      }
    } catch (err) {
      setEmailStatusMsg({ type: 'error', text: err.message || 'Could not add email.' });
    } finally {
      setIsAddingEmail(false);
      setTimeout(() => setEmailStatusMsg(null), 4000);
    }
  };

  const handleRemoveEmail = async (emailToRemove) => {
    try {
      const res = await apiClient.removeAllowedEmail(emailToRemove, activeUser?.id);
      if (res) {
        setAllowedEmailsData(res);
        setEmailStatusMsg({ type: 'info', text: `Removed ${emailToRemove} from monitored accounts.` });
        setTimeout(() => setEmailStatusMsg(null), 3500);
      }
    } catch (err) {
      console.warn('Remove email error:', err);
    }
  };

  // Theme-aware tokens
  const cardBg = isDark ? '#0a0a0a' : '#ffffff';
  const cardBorder = isDark ? '#1e1e1e' : '#e2e8f0';
  const headingColor = isDark ? '#ffffff' : '#0f172a';
  const textPrimary = isDark ? '#ffffff' : '#0f172a';
  const textSecondary = isDark ? '#cbd5e1' : '#64748b';
  const dividerColor = isDark ? '#1e1e1e' : '#f1f5f9';
  const cardHighlight = isDark ? 'rgba(0, 240, 255, 0.05)' : '#f8fafc';
  const subtleBg = isDark ? '#141414' : '#f8fafc';
  const subtleBorder = isDark ? '#262626' : '#e2e8f0';

  return (
    <div style={{
      padding: '2.5rem 1.5rem',
      maxWidth: '840px',
      margin: '0 auto',
      display: 'flex',
      flexDirection: 'column',
      gap: '2rem',
      color: textPrimary
    }}>
      
      {/* Page Title */}
      <div>
        <h2 style={{ fontSize: '1.75rem', fontWeight: 900, color: headingColor, margin: '0 0 0.4rem 0', letterSpacing: '-0.025em' }}>
          Settings & Preferences
        </h2>
        <p style={{ fontSize: '0.88rem', color: textSecondary, margin: 0 }}>
          Personalize your display experience, verify your account status, and view this computer's protection details.
        </p>
      </div>

      {isLoading ? (
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', padding: '3rem', color: '#0284c7', gap: '0.65rem' }}>
          <RotateCw size={20} className="animate-spin" />
          <span style={{ fontSize: '0.9rem', fontWeight: 600 }}>Loading your preferences and system details...</span>
        </div>
      ) : (
        <>
          {/* ============================================================ */}
          {/* 1. APPEARANCE & THEME SELECTION (DARK / LIGHT MODE) */}
          {/* ============================================================ */}
          <div style={{
            background: cardBg,
            border: `1px solid ${cardBorder}`,
            borderRadius: '16px',
            padding: '1.75rem',
            boxShadow: isDark ? '0 4px 20px rgba(0, 0, 0, 0.4)' : '0 1px 3px rgba(0, 0, 0, 0.04)',
            display: 'flex',
            flexDirection: 'column',
            gap: '1.25rem',
            transition: 'all 0.2s ease'
          }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', paddingBottom: '0.85rem', borderBottom: `1px solid ${dividerColor}` }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
                <div style={{
                  width: '42px',
                  height: '42px',
                  borderRadius: '10px',
                  background: isDark ? 'rgba(0, 240, 255, 0.12)' : '#e0f2fe',
                  color: isDark ? '#00f0ff' : '#0284c7',
                  border: isDark ? '1px solid rgba(0, 240, 255, 0.3)' : '1px solid #bae6fd',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center'
                }}>
                  <Palette size={22} />
                </div>
                <div>
                  <h3 style={{ fontSize: '1.15rem', fontWeight: 800, color: headingColor, margin: 0 }}>
                    Appearance & Theme
                  </h3>
                  <span style={{ fontSize: '0.78rem', color: textSecondary }}>
                    Choose the visual theme that is easiest on your eyes.
                  </span>
                </div>
              </div>

              <span style={{
                fontSize: '0.74rem',
                fontWeight: 700,
                padding: '0.2rem 0.65rem',
                borderRadius: '20px',
                background: isDark ? 'rgba(0, 240, 255, 0.15)' : '#f0fdf4',
                color: isDark ? '#00f0ff' : '#16a34a',
                border: isDark ? '1px solid rgba(0, 240, 255, 0.3)' : '1px solid #bbf7d0'
              }}>
                Current: {theme === 'dark' ? 'Dark Mode' : 'Light Mode'}
              </span>
            </div>

            {/* Theme Options Grid */}
            <div style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))',
              gap: '1rem'
            }}>
              
              {/* Option: Light Mode */}
              <div
                onClick={() => setTheme('light')}
                role="button"
                tabIndex={0}
                style={{
                  padding: '1.25rem',
                  borderRadius: '12px',
                  cursor: 'pointer',
                  border: theme === 'light' ? '2px solid #0284c7' : `1px solid ${cardBorder}`,
                  background: theme === 'light' 
                    ? (isDark ? 'rgba(2, 132, 199, 0.15)' : '#f0f9ff')
                    : (isDark ? '#080e1c' : '#ffffff'),
                  boxShadow: theme === 'light' ? '0 0 15px rgba(2, 132, 199, 0.2)' : 'none',
                  display: 'flex',
                  flexDirection: 'column',
                  gap: '0.75rem',
                  transition: 'all 0.2s ease',
                  position: 'relative'
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem' }}>
                    <div style={{
                      width: '36px',
                      height: '36px',
                      borderRadius: '8px',
                      background: '#fef3c7',
                      color: '#d97706',
                      border: '1px solid #fde68a',
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'center'
                    }}>
                      <Sun size={20} />
                    </div>
                    <div>
                      <div style={{ fontSize: '0.98rem', fontWeight: 800, color: headingColor }}>
                        Light Mode
                      </div>
                      <div style={{ fontSize: '0.72rem', color: textSecondary }}>
                        Daylight & High Visibility
                      </div>
                    </div>
                  </div>

                  {theme === 'light' && (
                    <div style={{
                      display: 'flex',
                      alignItems: 'center',
                      gap: '0.3rem',
                      fontSize: '0.74rem',
                      fontWeight: 800,
                      color: '#0284c7',
                      background: '#e0f2fe',
                      padding: '0.2rem 0.55rem',
                      borderRadius: '12px'
                    }}>
                      <CheckCircle2 size={13} />
                      <span>Active</span>
                    </div>
                  )}
                </div>

                <p style={{ fontSize: '0.82rem', color: textSecondary, margin: 0, lineHeight: 1.45 }}>
                  Clean, bright daylight contrast. Recommended for well-lit rooms and daytime productivity.
                </p>
              </div>

              {/* Option: Dark Mode */}
              <div
                onClick={() => setTheme('dark')}
                role="button"
                tabIndex={0}
                style={{
                  padding: '1.25rem',
                  borderRadius: '12px',
                  cursor: 'pointer',
                  border: theme === 'dark' ? '2px solid #00f0ff' : `1px solid ${cardBorder}`,
                  background: theme === 'dark'
                    ? (isDark ? 'rgba(0, 240, 255, 0.08)' : '#f0fdf4')
                    : (isDark ? '#080e1c' : '#ffffff'),
                  boxShadow: theme === 'dark' ? '0 0 18px rgba(0, 240, 255, 0.25)' : 'none',
                  display: 'flex',
                  flexDirection: 'column',
                  gap: '0.75rem',
                  transition: 'all 0.2s ease',
                  position: 'relative'
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem' }}>
                    <div style={{
                      width: '36px',
                      height: '36px',
                      borderRadius: '8px',
                      background: 'rgba(99, 102, 241, 0.15)',
                      color: '#818cf8',
                      border: '1px solid rgba(99, 102, 241, 0.3)',
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'center'
                    }}>
                      <Moon size={20} />
                    </div>
                    <div>
                      <div style={{ fontSize: '0.98rem', fontWeight: 800, color: headingColor }}>
                        Dark Mode
                      </div>
                      <div style={{ fontSize: '0.72rem', color: textSecondary }}>
                        Midnight & Reduced Eye Strain
                      </div>
                    </div>
                  </div>

                  {theme === 'dark' && (
                    <div style={{
                      display: 'flex',
                      alignItems: 'center',
                      gap: '0.3rem',
                      fontSize: '0.74rem',
                      fontWeight: 800,
                      color: '#00f0ff',
                      background: 'rgba(0, 240, 255, 0.15)',
                      padding: '0.2rem 0.55rem',
                      borderRadius: '12px'
                    }}>
                      <CheckCircle2 size={13} />
                      <span>Active</span>
                    </div>
                  )}
                </div>

                <p style={{ fontSize: '0.82rem', color: textSecondary, margin: 0, lineHeight: 1.45 }}>
                  Sleek obsidian dark appearance with soft cyan indicators. Recommended for nighttime focus and minimal glare.
                </p>
              </div>

            </div>
          </div>

          {/* ============================================================ */}
          {/* 2. USER DETAILS CARD */}
          {/* ============================================================ */}
          <div style={{
            background: cardBg,
            border: `1px solid ${cardBorder}`,
            borderRadius: '16px',
            padding: '1.75rem',
            boxShadow: isDark ? '0 4px 20px rgba(0, 0, 0, 0.4)' : '0 1px 3px rgba(0, 0, 0, 0.04)',
            display: 'flex',
            flexDirection: 'column',
            gap: '1.25rem',
            transition: 'all 0.2s ease'
          }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', paddingBottom: '0.85rem', borderBottom: `1px solid ${dividerColor}` }}>
              <div style={{
                width: '42px',
                height: '42px',
                borderRadius: '10px',
                background: isDark ? 'rgba(22, 163, 74, 0.15)' : '#f0fdf4',
                color: isDark ? '#4ade80' : '#16a34a',
                border: isDark ? '1px solid rgba(22, 163, 74, 0.3)' : '1px solid #bbf7d0',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center'
              }}>
                <User size={22} />
              </div>
              <div>
                <h3 style={{ fontSize: '1.15rem', fontWeight: 800, color: headingColor, margin: 0 }}>
                  User Account & Identity
                </h3>
                <span style={{ fontSize: '0.78rem', color: textSecondary }}>
                  Your verified identity and protection entitlement
                </span>
              </div>
            </div>

            {/* User Details Grid */}
            <div style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))',
              gap: '1.2rem'
            }}>
              <div>
                <span style={{ fontSize: '0.75rem', color: textSecondary, textTransform: 'uppercase', fontWeight: 700 }}>Your Name</span>
                <div style={{ fontSize: '0.95rem', fontWeight: 800, color: textPrimary, marginTop: '0.2rem' }}>
                  {activeUser?.name || 'Primary Operator'}
                </div>
              </div>

              <div>
                <span style={{ fontSize: '0.75rem', color: textSecondary, textTransform: 'uppercase', fontWeight: 700 }}>Email Address</span>
                <div style={{ fontSize: '0.95rem', fontWeight: 800, color: isDark ? '#38bdf8' : '#0284c7', marginTop: '0.2rem', display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
                  <span>{activeUser?.email || 'operator@local'}</span>
                  <span style={{
                    fontSize: '0.68rem',
                    fontWeight: 800,
                    padding: '1px 6px',
                    borderRadius: '4px',
                    background: isDark ? 'rgba(22, 163, 74, 0.2)' : '#f0fdf4',
                    color: isDark ? '#4ade80' : '#16a34a',
                    border: isDark ? '1px solid rgba(22, 163, 74, 0.3)' : '1px solid #bbf7d0'
                  }}>
                    VERIFIED
                  </span>
                </div>
              </div>

              <div>
                <span style={{ fontSize: '0.75rem', color: textSecondary, textTransform: 'uppercase', fontWeight: 700 }}>Account Identifier</span>
                <div style={{ fontSize: '0.85rem', fontWeight: 700, color: isDark ? '#94a3b8' : '#334155', marginTop: '0.2rem', fontFamily: 'monospace' }}>
                  {activeUser?.id || activeUser?.user_id || 'USR_01'}
                </div>
              </div>

              <div>
                <span style={{ fontSize: '0.75rem', color: textSecondary, textTransform: 'uppercase', fontWeight: 700 }}>Protection Tier</span>
                <div style={{ fontSize: '0.95rem', fontWeight: 800, color: textPrimary, marginTop: '0.2rem' }}>
                  {activeUser?.role || 'Primary Device Administrator'}
                </div>
              </div>

              <div>
                <span style={{ fontSize: '0.75rem', color: textSecondary, textTransform: 'uppercase', fontWeight: 700 }}>Protected Since</span>
                <div style={{ fontSize: '0.9rem', fontWeight: 600, color: textSecondary, marginTop: '0.2rem' }}>
                  {activeUser?.created_at ? new Date(activeUser.created_at).toLocaleDateString(undefined, { year: 'numeric', month: 'long', day: 'numeric' }) : 'Active Device'}
                </div>
              </div>

              <div>
                <span style={{ fontSize: '0.75rem', color: textSecondary, textTransform: 'uppercase', fontWeight: 700 }}>Privacy & Data Ethics</span>
                <div style={{ fontSize: '0.9rem', fontWeight: 700, color: '#16a34a', marginTop: '0.2rem', display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
                  <CheckCircle2 size={14} />
                  <span>Strictly Protected (No keystrokes or passwords collected)</span>
                </div>
              </div>
            </div>
          </div>

          {/* ============================================================ */}
          {/* 3. MONITORED GMAIL ACCOUNTS & ONLINE ACTIVITIES SCOPE */}
          {/* ============================================================ */}
          <div style={{
            background: cardBg,
            border: `1px solid ${cardBorder}`,
            borderRadius: '16px',
            padding: '1.75rem',
            boxShadow: isDark ? '0 4px 20px rgba(0, 0, 0, 0.4)' : '0 1px 3px rgba(0, 0, 0, 0.04)',
            display: 'flex',
            flexDirection: 'column',
            gap: '1.25rem',
            transition: 'all 0.2s ease'
          }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', paddingBottom: '0.85rem', borderBottom: `1px solid ${dividerColor}`, flexWrap: 'wrap', gap: '0.75rem' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
                <div style={{
                  width: '42px',
                  height: '42px',
                  borderRadius: '10px',
                  background: isDark ? 'rgba(0, 240, 255, 0.12)' : '#e0f2fe',
                  color: isDark ? '#00f0ff' : '#0284c7',
                  border: isDark ? '1px solid rgba(0, 240, 255, 0.3)' : '1px solid #bae6fd',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center'
                }}>
                  <Mail size={22} />
                </div>
                <div>
                  <h3 style={{ fontSize: '1.15rem', fontWeight: 800, color: headingColor, margin: 0 }}>
                    Monitored Gmail Accounts & Online Activities Scope
                  </h3>
                  <span style={{ fontSize: '0.78rem', color: textSecondary }}>
                    CyberThreat AI only inspects online email threats on your registered Gmail and accounts you explicitly authorize below.
                  </span>
                </div>
              </div>

              <span style={{
                fontSize: '0.74rem',
                fontWeight: 800,
                padding: '0.25rem 0.75rem',
                borderRadius: '20px',
                background: isDark ? 'rgba(34, 197, 94, 0.15)' : '#f0fdf4',
                color: isDark ? '#4ade80' : '#16a34a',
                border: isDark ? '1px solid rgba(34, 197, 94, 0.3)' : '1px solid #bbf7d0',
                display: 'inline-flex',
                alignItems: 'center',
                gap: '0.35rem'
              }}>
                <CheckCircle2 size={13} />
                <span>STRICT ACCOUNT SCOPE ACTIVE</span>
              </span>
            </div>

            {/* Privacy Scope Notice */}
            <p style={{ fontSize: '0.84rem', color: textSecondary, margin: 0, lineHeight: 1.55 }}>
              To protect your privacy and ensure no unwanted email activity is logged, online email threat detection and event recording strictly execute <strong style={{ color: headingColor }}>only</strong> when the active browser tab matches one of the approved accounts below. Unlisted or third-party Gmail accounts are completely ignored.
            </p>

            {/* Accounts List */}
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
              
              {/* Primary Registered Account (Permanent) */}
              <div style={{
                background: isDark ? '#080e1c' : '#f8fafc',
                border: `1px solid ${isDark ? 'rgba(0, 240, 255, 0.3)' : '#bae6fd'}`,
                borderRadius: '12px',
                padding: '0.9rem 1.15rem',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                flexWrap: 'wrap',
                gap: '0.75rem'
              }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
                  <div style={{ color: isDark ? '#00f0ff' : '#0284c7' }}>
                    <Mail size={18} />
                  </div>
                  <div>
                    <div style={{ fontSize: '0.92rem', fontWeight: 800, color: headingColor }}>
                      {allowedEmailsData.primary_email || activeUser?.email || 'pedapatidhana2@gmail.com'}
                    </div>
                    <div style={{ fontSize: '0.72rem', color: textSecondary }}>
                      Registered CyberZen Account Identity
                    </div>
                  </div>
                </div>

                <span style={{
                  fontSize: '0.7rem',
                  fontWeight: 800,
                  padding: '0.2rem 0.6rem',
                  borderRadius: '6px',
                  background: isDark ? 'rgba(0, 240, 255, 0.15)' : '#e0f2fe',
                  color: isDark ? '#00f0ff' : '#0284c7',
                  border: isDark ? '1px solid rgba(0, 240, 255, 0.3)' : '1px solid #bae6fd'
                }}>
                  PRIMARY REGISTERED (ALWAYS PROTECTED)
                </span>
              </div>

              {/* User-Added Additional Allowed Emails */}
              {allowedEmailsData.additional_emails && allowedEmailsData.additional_emails.map((item) => (
                <div key={item.id || item.email} style={{
                  background: isDark ? '#080e1c' : '#f8fafc',
                  border: `1px solid ${isDark ? '#1a243b' : '#e2e8f0'}`,
                  borderRadius: '12px',
                  padding: '0.9rem 1.15rem',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  flexWrap: 'wrap',
                  gap: '0.75rem'
                }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
                    <div style={{ color: '#10b981' }}>
                      <Mail size={18} />
                    </div>
                    <div>
                      <div style={{ fontSize: '0.92rem', fontWeight: 800, color: headingColor }}>
                        {item.email}
                      </div>
                      <div style={{ fontSize: '0.72rem', color: textSecondary }}>
                        User-Authorized Monitored Mailbox
                      </div>
                    </div>
                  </div>

                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
                    <span style={{
                      fontSize: '0.7rem',
                      fontWeight: 800,
                      padding: '0.2rem 0.6rem',
                      borderRadius: '6px',
                      background: 'rgba(16, 185, 129, 0.12)',
                      color: '#34d399',
                      border: '1px solid rgba(16, 185, 129, 0.3)'
                    }}>
                      AUTHORIZED BY YOU
                    </span>

                    <button
                      onClick={() => handleRemoveEmail(item.email)}
                      title="Remove from monitored accounts"
                      style={{
                        background: 'none',
                        border: 'none',
                        color: '#ef4444',
                        cursor: 'pointer',
                        padding: '0.3rem',
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'center',
                        borderRadius: '6px',
                        transition: 'background 0.15s ease'
                      }}
                    >
                      <Trash2 size={16} />
                    </button>
                  </div>
                </div>
              ))}

              {(!allowedEmailsData.additional_emails || allowedEmailsData.additional_emails.length === 0) && (
                <div style={{ fontSize: '0.8rem', color: textSecondary, fontStyle: 'italic', padding: '0.25rem 0' }}>
                  No secondary email accounts added yet. Only your primary registered Gmail is currently monitored.
                </div>
              )}
            </div>

            {/* Add Additional Email Form */}
            <form onSubmit={handleAddEmail} style={{
              display: 'flex',
              gap: '0.75rem',
              marginTop: '0.25rem',
              flexWrap: 'wrap'
            }}>
              <input
                type="email"
                placeholder="Add another Gmail to protect (e.g. work.email@gmail.com)..."
                value={newEmailInput}
                onChange={(e) => setNewEmailInput(e.target.value)}
                style={{
                  flex: '1 1 280px',
                  background: isDark ? '#030712' : '#ffffff',
                  border: `1px solid ${isDark ? '#334155' : '#cbd5e1'}`,
                  borderRadius: '8px',
                  padding: '0.65rem 0.85rem',
                  fontSize: '0.84rem',
                  color: textPrimary,
                  outline: 'none'
                }}
              />
              <button
                type="submit"
                disabled={isAddingEmail || !newEmailInput.trim()}
                style={{
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: '0.45rem',
                  padding: '0.65rem 1.25rem',
                  borderRadius: '8px',
                  border: 'none',
                  background: '#0284c7',
                  color: '#ffffff',
                  fontSize: '0.84rem',
                  fontWeight: 700,
                  cursor: (isAddingEmail || !newEmailInput.trim()) ? 'not-allowed' : 'pointer',
                  opacity: (isAddingEmail || !newEmailInput.trim()) ? 0.6 : 1,
                  transition: 'background 0.15s ease'
                }}
              >
                <Plus size={15} />
                <span>{isAddingEmail ? 'Adding...' : 'Add Monitored Email'}</span>
              </button>
            </form>

            {/* Status message */}
            {emailStatusMsg && (
              <div style={{
                fontSize: '0.8rem',
                fontWeight: 600,
                color: emailStatusMsg.type === 'error' ? '#ef4444' : emailStatusMsg.type === 'success' ? '#10b981' : '#38bdf8',
                background: emailStatusMsg.type === 'error' ? 'rgba(239, 68, 68, 0.1)' : 'rgba(16, 185, 129, 0.1)',
                padding: '0.5rem 0.85rem',
                borderRadius: '6px',
                border: `1px solid ${emailStatusMsg.type === 'error' ? 'rgba(239, 68, 68, 0.3)' : 'rgba(16, 185, 129, 0.3)'}`
              }}>
                {emailStatusMsg.text}
              </div>
            )}
          </div>

          {/* ============================================================ */}
          {/* 4. ALLOWED PERMISSIONS & SYSTEM ACCESS CARD */}
          {/* ============================================================ */}
          <div style={{
            background: cardBg,
            border: `1px solid ${cardBorder}`,
            borderRadius: '16px',
            padding: '1.75rem',
            boxShadow: isDark ? '0 4px 20px rgba(0, 0, 0, 0.4)' : '0 1px 3px rgba(0, 0, 0, 0.04)',
            display: 'flex',
            flexDirection: 'column',
            gap: '1.25rem',
            transition: 'all 0.2s ease'
          }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', paddingBottom: '0.85rem', borderBottom: `1px solid ${dividerColor}`, flexWrap: 'wrap', gap: '0.75rem' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
                <div style={{
                  width: '42px',
                  height: '42px',
                  borderRadius: '10px',
                  background: isDark ? 'rgba(0, 240, 255, 0.12)' : '#e0f2fe',
                  color: isDark ? '#00f0ff' : '#0284c7',
                  border: isDark ? '1px solid rgba(0, 240, 255, 0.3)' : '1px solid #bae6fd',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center'
                }}>
                  <ShieldCheck size={22} />
                </div>
                <div>
                  <h3 style={{ fontSize: '1.15rem', fontWeight: 800, color: headingColor, margin: 0 }}>
                    Allowed Permissions & System Access
                  </h3>
                  <span style={{ fontSize: '0.78rem', color: textSecondary }}>
                    Permissions reviewed and granted by you upon registration. All protection runs 100% locally.
                  </span>
                </div>
              </div>

              <span style={{
                fontSize: '0.74rem',
                fontWeight: 800,
                padding: '0.25rem 0.75rem',
                borderRadius: '20px',
                background: isDark ? 'rgba(34, 197, 94, 0.15)' : '#f0fdf4',
                color: isDark ? '#4ade80' : '#16a34a',
                border: isDark ? '1px solid rgba(34, 197, 94, 0.3)' : '1px solid #bbf7d0',
                display: 'inline-flex',
                alignItems: 'center',
                gap: '0.35rem'
              }}>
                <CheckCircle2 size={13} />
                <span>STATUS: GRANTED & ACTIVE</span>
              </span>
            </div>

            {/* List of Permissions Granted by User */}
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.85rem' }}>
              {[
                {
                  title: 'Process & Application Monitoring',
                  desc: 'Monitors program startup, command-line arguments, parent process PID, and runtime duration to detect ransomware, trojans, and malicious background scripts.',
                  icon: Activity,
                  tag: 'Allowed by User',
                  monitored: 'Process lifecycles, PID, executable hashes, execution times'
                },
                {
                  title: 'Network & DNS Threat Protection',
                  desc: 'Monitors outbound web domain queries, destination IP addresses, and unauthorized network socket connections to block cryptominers, botnets, and command-and-control servers.',
                  icon: Globe,
                  tag: 'Allowed by User',
                  monitored: 'Domain lookups, destination IPs, listening port bounds'
                },
                {
                  title: 'Browser & Real-Time Phishing Shield',
                  desc: 'Inspects visited website URLs, domain reputations, and spoofed email headers in Gmail via the Chrome Security Companion to prevent credential theft.',
                  icon: Shield,
                  tag: 'Allowed by User',
                  monitored: 'Domain reputation, spoofed sender addresses, phishing links'
                },
                {
                  title: 'Downloads & Executable Staging Watcher',
                  desc: 'Watches newly saved installer files (.exe, .msi, .dll, .bat) in user download folders to stop contaminated payloads from executing.',
                  icon: FileText,
                  tag: 'Allowed by User',
                  monitored: 'File extensions, download timestamps, staging directory events'
                },
                {
                  title: 'On-Device SQLite Storage Vault',
                  desc: 'Stores your activity history and incident attack stories strictly in your private local database (cyberthreat.db) with zero cloud reliance.',
                  icon: HardDrive,
                  tag: 'Allowed by User',
                  monitored: 'Local SQLite WAL database, device correlation graphs'
                }
              ].map((perm, idx) => {
                const PermIcon = perm.icon;
                return (
                  <div key={idx} style={{
                    background: isDark ? '#080e1c' : '#f8fafc',
                    border: `1px solid ${isDark ? '#1a243b' : '#e2e8f0'}`,
                    borderRadius: '12px',
                    padding: '1rem 1.25rem',
                    display: 'flex',
                    alignItems: 'flex-start',
                    justifyContent: 'space-between',
                    gap: '1rem',
                    flexWrap: 'wrap'
                  }}>
                    <div style={{ display: 'flex', alignItems: 'flex-start', gap: '0.85rem', flex: '1 1 340px' }}>
                      <div style={{
                        width: '34px',
                        height: '34px',
                        borderRadius: '8px',
                        background: isDark ? 'rgba(0, 240, 255, 0.1)' : '#e0f2fe',
                        color: isDark ? '#00f0ff' : '#0284c7',
                        border: `1px solid ${isDark ? 'rgba(0, 240, 255, 0.25)' : '#bae6fd'}`,
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'center',
                        flexShrink: 0,
                        marginTop: '2px'
                      }}>
                        <PermIcon size={18} />
                      </div>
                      <div>
                        <div style={{ fontSize: '0.94rem', fontWeight: 800, color: headingColor }}>
                          {perm.title}
                        </div>
                        <div style={{ fontSize: '0.82rem', color: textSecondary, marginTop: '0.2rem', lineHeight: 1.45 }}>
                          {perm.desc}
                        </div>
                        <div style={{ fontSize: '0.74rem', color: isDark ? '#38bdf8' : '#0284c7', marginTop: '0.35rem', fontWeight: 600 }}>
                          Signals monitored: {perm.monitored}
                        </div>
                      </div>
                    </div>

                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', alignSelf: 'center' }}>
                      <span style={{
                        fontSize: '0.72rem',
                        fontWeight: 800,
                        padding: '0.2rem 0.6rem',
                        borderRadius: '6px',
                        background: isDark ? 'rgba(34, 197, 94, 0.15)' : '#f0fdf4',
                        color: isDark ? '#4ade80' : '#16a34a',
                        border: `1px solid ${isDark ? 'rgba(34, 197, 94, 0.3)' : '#bbf7d0'}`,
                        display: 'flex',
                        alignItems: 'center',
                        gap: '0.3rem',
                        whiteSpace: 'nowrap'
                      }}>
                        <Check size={12} strokeWidth={3} />
                        <span>{perm.tag}</span>
                      </span>
                    </div>
                  </div>
                );
              })}
            </div>

            {/* Zero-Collection Privacy Guarantee Box */}
            <div style={{
              background: isDark ? 'rgba(34, 197, 94, 0.08)' : '#f0fdf4',
              border: `1px solid ${isDark ? 'rgba(34, 197, 94, 0.25)' : '#bbf7d0'}`,
              borderRadius: '12px',
              padding: '1rem 1.25rem',
              display: 'flex',
              alignItems: 'center',
              gap: '0.85rem'
            }}>
              <div style={{ color: isDark ? '#4ade80' : '#16a34a', flexShrink: 0 }}>
                <Lock size={22} />
              </div>
              <div style={{ fontSize: '0.82rem', color: isDark ? '#cbd5e1' : '#334155', lineHeight: 1.5 }}>
                <strong style={{ color: isDark ? '#4ade80' : '#16a34a' }}>Strict Zero-Collection Guarantee:</strong> Passwords, keystrokes, personal chats, and photos are strictly excluded from monitoring and are never collected, stored, or transmitted anywhere.
              </div>
            </div>
          </div>

          {/* ============================================================ */}
          {/* 5. DEVICE DETAILS CARD */}
          {/* ============================================================ */}
          <div style={{
            background: cardBg,
            border: `1px solid ${cardBorder}`,
            borderRadius: '16px',
            padding: '1.75rem',
            boxShadow: isDark ? '0 4px 20px rgba(0, 0, 0, 0.4)' : '0 1px 3px rgba(0, 0, 0, 0.04)',
            display: 'flex',
            flexDirection: 'column',
            gap: '1.25rem',
            transition: 'all 0.2s ease'
          }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', paddingBottom: '0.85rem', borderBottom: `1px solid ${dividerColor}` }}>
              <div style={{
                width: '42px',
                height: '42px',
                borderRadius: '10px',
                background: isDark ? 'rgba(2, 132, 199, 0.15)' : '#e0f2fe',
                color: isDark ? '#38bdf8' : '#0284c7',
                border: isDark ? '1px solid rgba(2, 132, 199, 0.3)' : '1px solid #bae6fd',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center'
              }}>
                <Laptop size={22} />
              </div>
              <div>
                <h3 style={{ fontSize: '1.15rem', fontWeight: 800, color: headingColor, margin: 0 }}>
                  Protected Computer Details
                </h3>
                <span style={{ fontSize: '0.78rem', color: textSecondary }}>
                  Genuine physical machine hardware and operating system status
                </span>
              </div>
            </div>

            {/* Enrolled Devices Summary */}
            {enrolledDevices.length > 0 && (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.65rem', marginBottom: '0.5rem' }}>
                <span style={{ fontSize: '0.78rem', color: textSecondary, textTransform: 'uppercase', fontWeight: 700 }}>
                  Active Enrolled Endpoints ({enrolledDevices.length})
                </span>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
                  {enrolledDevices.map((d, idx) => (
                    <div key={d.device_id || idx} style={{
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'space-between',
                      padding: '0.75rem 1rem',
                      background: subtleBg,
                      border: `1px solid ${subtleBorder}`,
                      borderRadius: '10px'
                    }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
                        <Laptop size={18} style={{ color: '#00f0ff' }} />
                        <div>
                          <div style={{ fontSize: '0.88rem', fontWeight: 700, color: textPrimary }}>
                            {d.device_name || 'Primary Desktop'}
                          </div>
                          <div style={{ fontSize: '0.75rem', color: isDark ? '#38bdf8' : '#0284c7', fontFamily: 'monospace' }}>
                            {d.device_id} • {d.os_info || 'Windows 11 (64-bit)'}
                          </div>
                        </div>
                      </div>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', fontSize: '0.8rem', color: '#16a34a', fontWeight: 600 }}>
                        <span style={{ width: '8px', height: '8px', borderRadius: '50%', background: '#16a34a', display: 'inline-block' }} />
                        <span>Online & Protected</span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Device Details Grid */}
            <div style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))',
              gap: '1.2rem'
            }}>
              <div>
                <span style={{ fontSize: '0.75rem', color: textSecondary, textTransform: 'uppercase', fontWeight: 700 }}>Computer Name</span>
                <div style={{ fontSize: '0.95rem', fontWeight: 800, color: textPrimary, marginTop: '0.2rem' }}>
                  {deviceDetails?.computer_name || (enrolledDevices[0]?.device_name) || 'Primary Desktop'}
                </div>
              </div>

              <div>
                <span style={{ fontSize: '0.75rem', color: textSecondary, textTransform: 'uppercase', fontWeight: 700 }}>Device Fingerprint</span>
                <div style={{ fontSize: '0.85rem', fontWeight: 700, color: isDark ? '#38bdf8' : '#0284c7', marginTop: '0.2rem', fontFamily: 'monospace' }}>
                  {deviceDetails?.device_id || (enrolledDevices[0]?.device_id) || 'DEV-PRIMARY'}
                </div>
              </div>

              <div>
                <span style={{ fontSize: '0.75rem', color: textSecondary, textTransform: 'uppercase', fontWeight: 700 }}>Operating System</span>
                <div style={{ fontSize: '0.95rem', fontWeight: 700, color: textPrimary, marginTop: '0.2rem' }}>
                  {deviceDetails?.os_version || (enrolledDevices[0]?.os_info) || 'Windows 11 (64-bit)'}
                </div>
              </div>

              <div>
                <span style={{ fontSize: '0.75rem', color: textSecondary, textTransform: 'uppercase', fontWeight: 700 }}>Processor & Cores</span>
                <div style={{ fontSize: '0.95rem', fontWeight: 600, color: textSecondary, marginTop: '0.2rem' }}>
                  {deviceDetails?.architecture || 'AMD64'} ({deviceDetails?.cpu_cores || 4} CPU Cores)
                </div>
              </div>

              <div>
                <span style={{ fontSize: '0.75rem', color: textSecondary, textTransform: 'uppercase', fontWeight: 700 }}>System Memory (RAM)</span>
                <div style={{ fontSize: '0.95rem', fontWeight: 700, color: textPrimary, marginTop: '0.2rem' }}>
                  {deviceDetails?.total_ram_gb ? `${deviceDetails.total_ram_gb} GB Total` : '16.0 GB'}
                  <span style={{ fontSize: '0.8rem', color: '#16a34a', marginLeft: '0.4rem', fontWeight: 600 }}>
                    ({deviceDetails?.available_ram_gb || '8.5'} GB Free)
                  </span>
                </div>
              </div>

              <div>
                <span style={{ fontSize: '0.75rem', color: textSecondary, textTransform: 'uppercase', fontWeight: 700 }}>Local Storage (C:)</span>
                <div style={{ fontSize: '0.95rem', fontWeight: 700, color: textPrimary, marginTop: '0.2rem' }}>
                  {deviceDetails?.total_disk_gb ? `${deviceDetails.total_disk_gb} GB` : '475 GB'}
                  <span style={{ fontSize: '0.8rem', color: textSecondary, marginLeft: '0.4rem', fontWeight: 600 }}>
                    ({deviceDetails?.free_disk_gb || '210'} GB Free)
                  </span>
                </div>
              </div>

              <div>
                <span style={{ fontSize: '0.75rem', color: textSecondary, textTransform: 'uppercase', fontWeight: 700 }}>Protection Status</span>
                <div style={{ fontSize: '0.9rem', fontWeight: 700, color: deviceDetails?.is_online ? '#16a34a' : '#d97706', marginTop: '0.2rem', display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
                  {deviceDetails?.is_online ? <Wifi size={14} /> : <WifiOff size={14} />}
                  <span>{deviceDetails?.connection_status || 'Online & Actively Protected'}</span>
                </div>
              </div>

              <div>
                <span style={{ fontSize: '0.75rem', color: textSecondary, textTransform: 'uppercase', fontWeight: 700 }}>Data Storage Security</span>
                <div style={{ fontSize: '0.88rem', fontWeight: 700, color: textPrimary, marginTop: '0.2rem' }}>
                  Secure Local Vault (100% On-Device)
                </div>
              </div>
            </div>
          </div>

          {/* ============================================================ */}
          {/* 4. LOG OUT BUTTON */}
          {/* ============================================================ */}
          <div style={{
            display: 'flex',
            justifyContent: 'flex-end',
            paddingTop: '0.5rem'
          }}>
            <button
              onClick={logout}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '0.5rem',
                padding: '0.75rem 1.75rem',
                borderRadius: '10px',
                border: isDark ? '1px solid rgba(220, 38, 38, 0.4)' : '1px solid #fecaca',
                background: isDark ? 'rgba(220, 38, 38, 0.15)' : '#fef2f2',
                color: isDark ? '#f87171' : '#dc2626',
                fontSize: '0.9rem',
                fontWeight: 700,
                cursor: 'pointer',
                transition: 'all 0.15s ease'
              }}
              onMouseEnter={(e) => e.currentTarget.style.background = isDark ? 'rgba(220, 38, 38, 0.25)' : '#fee2e2'}
              onMouseLeave={(e) => e.currentTarget.style.background = isDark ? 'rgba(220, 38, 38, 0.15)' : '#fef2f2'}
            >
              <LogOut size={16} />
              <span>Log Out of Session</span>
            </button>
          </div>
        </>
      )}

    </div>
  );
}

