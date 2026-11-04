import React, { useState } from 'react';
import { Bell, Search, LogOut, ShieldAlert, Check, User, ChevronDown } from 'lucide-react';
import { useAuth } from '../../context/AuthContext';

export default function Header() {
  const { user, logout } = useAuth();
  const [showNotifications, setShowNotifications] = useState(false);
  const [showUserMenu, setShowUserMenu] = useState(false);

  // Dynamic Greeting based on local time
  const getGreeting = () => {
    const hour = new Date().getHours();
    if (hour < 12) return 'Good morning';
    if (hour < 18) return 'Good afternoon';
    return 'Good evening';
  };

  // Formatted date string
  const currentDateStr = new Date().toLocaleDateString('en-US', {
    weekday: 'long',
    year: 'numeric',
    month: 'short',
    day: 'numeric'
  });

  const userName = user ? user.name : 'Security Specialist';

  return (
    <header style={{
      height: '70px',
      padding: '0 2rem',
      background: 'rgba(12, 16, 26, 0.7)',
      backdropFilter: 'blur(12px)',
      borderBottom: '1px solid var(--border-subtle)',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'space-between',
      position: 'sticky',
      top: 0,
      zIndex: 90
    }}>
      
      {/* Greeting & Date */}
      <div>
        <h1 style={{ fontSize: '1.25rem', fontWeight: 700, color: 'var(--text-primary)', letterSpacing: '-0.01em' }}>
          {getGreeting()}, <span style={{ color: 'var(--accent-cyan)' }}>{userName}</span>
        </h1>
        <p style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
          {currentDateStr} • Threat Prevention Engine Online
        </p>
      </div>

      {/* Right Controls: Search, Notifications, Profile */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '1.25rem' }}>
        
        {/* Global Search Input */}
        <div style={{ position: 'relative', width: '240px' }}>
          <Search size={15} style={{ position: 'absolute', left: '12px', top: '50%', transform: 'translateY(-50%)', color: 'var(--text-muted)' }} />
          <input
            type="text"
            placeholder="Search IPs, events, devices..."
            style={{
              width: '100%',
              padding: '0.45rem 0.85rem 0.45rem 2.2rem',
              borderRadius: '8px',
              border: '1px solid var(--border-subtle)',
              background: 'rgba(7, 9, 14, 0.6)',
              color: 'var(--text-primary)',
              fontSize: '0.8rem',
              outline: 'none'
            }}
          />
        </div>

        {/* Notifications Icon Dropdown */}
        <div style={{ position: 'relative' }}>
          <button
            onClick={() => { setShowNotifications(!showNotifications); setShowUserMenu(false); }}
            style={{
              background: 'rgba(255,255,255,0.04)',
              border: '1px solid var(--border-subtle)',
              borderRadius: '10px',
              padding: '0.55rem',
              color: 'var(--text-secondary)',
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              position: 'relative'
            }}
          >
            <Bell size={18} />
            <span style={{
              position: 'absolute',
              top: '4px',
              right: '4px',
              width: '8px',
              height: '8px',
              borderRadius: '50%',
              background: '#f43f5e',
              boxShadow: '0 0 8px #f43f5e'
            }}></span>
          </button>

          {/* Notifications Dropdown Panel */}
          {showNotifications && (
            <div className="glass-panel" style={{
              position: 'absolute',
              right: 0,
              top: '50px',
              width: '320px',
              padding: '1rem',
              zIndex: 100,
              display: 'flex',
              flexDirection: 'column',
              gap: '0.75rem'
            }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: '1px solid var(--border-subtle)', paddingBottom: '0.5rem' }}>
                <span style={{ fontSize: '0.85rem', fontWeight: 700 }}>Security Alerts</span>
                <span style={{ fontSize: '0.7rem', color: 'var(--accent-cyan)' }}>3 New</span>
              </div>

              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem', fontSize: '0.8rem' }}>
                <div style={{ background: 'rgba(244,63,94,0.1)', padding: '0.6rem', borderRadius: '6px', borderLeft: '3px solid #f43f5e' }}>
                  <strong style={{ color: '#f43f5e', display: 'block' }}>Tor Exit Anomaly Blocked</strong>
                  <span style={{ color: 'var(--text-secondary)', fontSize: '0.75rem' }}>11:20 AM • IP 185.220.101.45</span>
                </div>
                <div style={{ background: 'rgba(245,158,11,0.1)', padding: '0.6rem', borderRadius: '6px', borderLeft: '3px solid #f59e0b' }}>
                  <strong style={{ color: '#f59e0b', display: 'block' }}>High Volume API Burst</strong>
                  <span style={{ color: 'var(--text-secondary)', fontSize: '0.75rem' }}>01:50 PM • Workstation-03</span>
                </div>
              </div>
            </div>
          )}
        </div>

        {/* User Profile Menu */}
        <div style={{ position: 'relative' }}>
          <button
            onClick={() => { setShowUserMenu(!showUserMenu); setShowNotifications(false); }}
            style={{
              background: 'rgba(255,255,255,0.04)',
              border: '1px solid var(--border-subtle)',
              borderRadius: '10px',
              padding: '0.35rem 0.65rem 0.35rem 0.4rem',
              display: 'flex',
              alignItems: 'center',
              gap: '0.5rem',
              cursor: 'pointer'
            }}
          >
            <img
              src={user?.avatar || 'https://images.unsplash.com/photo-1534528741775-53994a69daeb?w=150'}
              alt="Profile"
              style={{ width: '30px', height: '30px', borderRadius: '50%', border: '1px solid var(--accent-cyan)' }}
            />
            <span style={{ fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-primary)' }}>
              {userName}
            </span>
            <ChevronDown size={14} style={{ color: 'var(--text-muted)' }} />
          </button>

          {/* User Profile Dropdown */}
          {showUserMenu && (
            <div className="glass-panel" style={{
              position: 'absolute',
              right: 0,
              top: '50px',
              width: '200px',
              padding: '0.75rem',
              zIndex: 100,
              display: 'flex',
              flexDirection: 'column',
              gap: '0.5rem'
            }}>
              <div style={{ borderBottom: '1px solid var(--border-subtle)', paddingBottom: '0.5rem' }}>
                <div style={{ fontSize: '0.85rem', fontWeight: 700 }}>{userName}</div>
                <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>{user?.email || 'secops@digitalguard.ai'}</div>
              </div>

              <button
                onClick={logout}
                style={{
                  background: 'rgba(244,63,94,0.1)',
                  border: '1px solid rgba(244,63,94,0.3)',
                  color: '#f43f5e',
                  borderRadius: '6px',
                  padding: '0.45rem',
                  fontSize: '0.8rem',
                  fontWeight: 600,
                  display: 'flex',
                  alignItems: 'center',
                  gap: '0.4rem',
                  cursor: 'pointer',
                  justifyContent: 'center',
                  marginTop: '0.2rem'
                }}
              >
                <LogOut size={14} /> Sign Out
              </button>
            </div>
          )}
        </div>

      </div>

    </header>
  );
}
