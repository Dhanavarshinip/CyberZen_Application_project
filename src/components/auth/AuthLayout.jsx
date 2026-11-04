import React, { useState } from 'react';
import { Shield, Globe, Sun, Moon } from 'lucide-react';
import { useTheme } from '../../context/ThemeContext';
import LoginForm from './LoginForm';
import SignupForm from './SignupForm';

export default function AuthLayout({ onOpenWebsite, defaultMode = 'login' }) {
  const [authMode, setAuthMode] = useState(defaultMode); // 'login' | 'signup'
  const { isDark, toggleTheme } = useTheme();

  return (
    <div style={{
      minHeight: '100vh',
      display: 'flex',
      flexDirection: 'column',
      alignItems: 'center',
      justifyContent: 'center',
      background: isDark ? '#000000' : '#f8fafc',
      padding: '2.5rem 1.5rem',
      fontFamily: 'Inter, system-ui, -apple-system, sans-serif',
      color: isDark ? '#ffffff' : '#0f172a',
      position: 'relative',
      overflow: 'hidden',
      transition: 'background 0.2s ease, color 0.2s ease'
    }}>
      {/* Light / Dark Mode Quick Switcher Pill (Top Right on Login Page) */}
      <div style={{
        position: 'fixed',
        top: '1.25rem',
        right: '1.5rem',
        zIndex: 50
      }}>
        <button
          type="button"
          onClick={toggleTheme}
          title={`Switch to ${isDark ? 'Light' : 'Dark'} Mode`}
          style={{
            display: 'inline-flex',
            alignItems: 'center',
            gap: '0.5rem',
            padding: '0.45rem 0.95rem',
            borderRadius: '999px',
            background: isDark ? 'rgba(24, 24, 27, 0.85)' : 'rgba(255, 255, 255, 0.95)',
            border: `1.5px solid ${isDark ? '#3f3f46' : '#cbd5e1'}`,
            color: isDark ? '#fbbf24' : '#0284c7',
            cursor: 'pointer',
            fontSize: '0.8rem',
            fontWeight: 800,
            boxShadow: isDark ? '0 4px 15px rgba(0, 0, 0, 0.5)' : '0 4px 15px rgba(0, 0, 0, 0.08)',
            backdropFilter: 'blur(12px)',
            transition: 'all 0.18s ease'
          }}
        >
          {isDark ? <Sun size={15} /> : <Moon size={15} />}
          <span>{isDark ? 'Light Mode' : 'Dark Mode'}</span>
        </button>
      </div>

      {/* Full Animative Cybersecurity Image Background */}
      <div style={{
        position: 'fixed',
        inset: -20,
        zIndex: 0,
        overflow: 'hidden',
        pointerEvents: 'none'
      }}>
        <img
          src="/cyberzen-cyber-bg.jpg"
          alt="Cyber Defense Matrix"
          onError={(e) => { e.currentTarget.style.display = 'none'; }}
          style={{
            width: '100%',
            height: '100%',
            objectFit: 'cover',
            filter: isDark ? 'brightness(0.5) contrast(1.25) grayscale(0.2)' : 'brightness(1.05) opacity(0.12) contrast(1.1) grayscale(0.4)',
            animation: 'authBgFloat 26s ease-in-out infinite alternate',
            transformOrigin: 'center center'
          }}
        />
        {/* Layered Cyber Scrim & Radial Vignette */}
        <div style={{
          position: 'absolute',
          inset: 0,
          background: isDark
            ? 'linear-gradient(180deg, rgba(0, 0, 0, 0.8) 0%, rgba(0, 0, 0, 0.94) 100%), radial-gradient(circle at 50% 30%, rgba(255, 255, 255, 0.04) 0%, transparent 70%)'
            : 'linear-gradient(180deg, rgba(248, 250, 252, 0.82) 0%, rgba(241, 245, 249, 0.94) 100%)'
        }} />
      </div>

      {/* Cyber Grid Lines Overlay */}
      <div style={{
        position: 'fixed',
        inset: 0,
        backgroundImage: isDark
          ? `linear-gradient(rgba(255, 255, 255, 0.03) 1px, transparent 1px), linear-gradient(90deg, rgba(255, 255, 255, 0.03) 1px, transparent 1px)`
          : `linear-gradient(rgba(0, 0, 0, 0.04) 1px, transparent 1px), linear-gradient(90deg, rgba(0, 0, 0, 0.04) 1px, transparent 1px)`,
        backgroundSize: '40px 40px, 40px 40px',
        pointerEvents: 'none',
        zIndex: 1
      }} />

      {/* Foreground Container */}
      <div style={{
        position: 'relative',
        zIndex: 10,
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        width: '100%',
        maxWidth: '440px'
      }}>
        {/* Brand Header */}
        <div style={{ textAlign: 'center', marginBottom: '1.75rem' }}>
          <div style={{
            width: '58px',
            height: '58px',
            borderRadius: '16px',
            background: isDark ? '#09090b' : '#f0f9ff',
            border: `1.5px solid ${isDark ? '#3f3f46' : '#bae6fd'}`,
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            color: isDark ? '#ffffff' : '#0284c7',
            margin: '0 auto 1rem auto',
            boxShadow: isDark ? '0 8px 25px rgba(0, 0, 0, 0.8)' : '0 8px 20px rgba(2, 132, 199, 0.15)'
          }}>
            <Shield size={30} strokeWidth={2.4} />
          </div>
          <div style={{
            display: 'inline-flex',
            alignItems: 'center',
            gap: '0.4rem',
            padding: '0.3rem 0.85rem',
            background: isDark ? '#09090b' : '#f0fdf4',
            border: `1px solid ${isDark ? '#27272a' : '#bbf7d0'}`,
            borderRadius: '999px',
            fontSize: '0.74rem',
            color: isDark ? '#e4e4e7' : '#16a34a',
            fontWeight: 700,
            marginBottom: '0.75rem',
            boxShadow: isDark ? '0 4px 12px rgba(0, 0, 0, 0.5)' : '0 2px 8px rgba(0, 0, 0, 0.04)'
          }}>
            <span>🛡️ Windows Desktop Operations Center</span>
          </div>
          <h1 style={{
            fontSize: '1.9rem',
            fontWeight: 900,
            color: isDark ? '#ffffff' : '#0f172a',
            letterSpacing: '-0.02em',
            margin: '0 0 0.4rem 0',
            textShadow: isDark ? '0 2px 10px rgba(0, 0, 0, 0.8)' : 'none'
          }}>
            CyberZen
          </h1>
          <p style={{ fontSize: '0.82rem', color: isDark ? '#a1a1aa' : '#64748b', margin: 0, maxWidth: '440px', lineHeight: 1.45 }}>
            Intelligent Real-Time Digital Threat Detection, Prevention and Incident Reconstruction
          </p>
        </div>

        {/* Mode Switch Tabs & Form Card */}
        <div style={{
          width: '100%',
          background: isDark ? 'rgba(9, 9, 11, 0.95)' : 'rgba(255, 255, 255, 0.98)',
          backdropFilter: 'blur(25px)',
          WebkitBackdropFilter: 'blur(25px)',
          border: `1px solid ${isDark ? '#27272a' : '#e2e8f0'}`,
          borderRadius: '18px',
          padding: '1.75rem 1.5rem',
          boxShadow: isDark ? '0 25px 60px rgba(0, 0, 0, 0.95)' : '0 20px 45px rgba(0, 0, 0, 0.08)'
        }}>
          {/* Mode Switch Tabs */}
          <div style={{
            display: 'flex',
            background: isDark ? '#09090b' : '#f1f5f9',
            padding: '0.3rem',
            borderRadius: '10px',
            border: `1px solid ${isDark ? '#27272a' : '#e2e8f0'}`,
            width: '100%',
            marginBottom: '1.5rem'
          }}>
            <button
              onClick={() => setAuthMode('signup')}
              style={{
                flex: 1,
                padding: '0.55rem',
                borderRadius: '7px',
                border: authMode === 'signup' 
                  ? (isDark ? '1px solid #ffffff' : '1px solid #0284c7') 
                  : 'none',
                background: authMode === 'signup' 
                  ? (isDark ? '#ffffff' : '#0284c7') 
                  : 'transparent',
                color: authMode === 'signup' 
                  ? (isDark ? '#000000' : '#ffffff') 
                  : (isDark ? '#a1a1aa' : '#64748b'),
                fontSize: '0.84rem',
                fontWeight: 800,
                cursor: 'pointer',
                transition: 'all 0.15s ease'
              }}
            >
              Create Account
            </button>
            <button
              onClick={() => setAuthMode('login')}
              style={{
                flex: 1,
                padding: '0.55rem',
                borderRadius: '7px',
                border: authMode === 'login' 
                  ? (isDark ? '1px solid #ffffff' : '1px solid #0284c7') 
                  : 'none',
                background: authMode === 'login' 
                  ? (isDark ? '#ffffff' : '#0284c7') 
                  : 'transparent',
                color: authMode === 'login' 
                  ? (isDark ? '#000000' : '#ffffff') 
                  : (isDark ? '#a1a1aa' : '#64748b'),
                fontSize: '0.84rem',
                fontWeight: 800,
                cursor: 'pointer',
                transition: 'all 0.15s ease'
              }}
            >
              Sign In
            </button>
          </div>

          {/* Centered Form */}
          <div style={{ width: '100%' }}>
            {authMode === 'login' ? (
              <LoginForm onSwitchToSignup={() => setAuthMode('signup')} />
            ) : (
              <SignupForm onSwitchToLogin={() => setAuthMode('login')} />
            )}
          </div>
        </div>

        {/* Optional Website Portal Link */}
        {onOpenWebsite && (
          <div style={{ marginTop: '2rem', textAlign: 'center' }}>
            <button
              onClick={onOpenWebsite}
              style={{
                background: isDark ? '#000000' : '#ffffff',
                border: `1px solid ${isDark ? '#27272a' : '#cbd5e1'}`,
                padding: '0.45rem 1rem',
                borderRadius: '8px',
                color: isDark ? '#a1a1aa' : '#64748b',
                fontSize: '0.78rem',
                display: 'inline-flex',
                alignItems: 'center',
                gap: '0.45rem',
                cursor: 'pointer',
                transition: 'all 0.15s ease'
              }}
            >
              <Globe size={13} />
              <span>View Public Documentation & Web Portal</span>
            </button>
          </div>
        )}
      </div>

      <style>{`
        @keyframes authBgFloat {
          0% { transform: scale(1) translate(0px, 0px); }
          50% { transform: scale(1.07) translate(-1.5%, -1%); }
          100% { transform: scale(1.03) translate(1%, 0.8%); }
        }
      `}</style>
    </div>
  );
}
