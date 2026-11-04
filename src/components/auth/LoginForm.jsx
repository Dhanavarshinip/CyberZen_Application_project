import React, { useState } from 'react';
import { useAuth } from '../../context/AuthContext';
import { useTheme } from '../../context/ThemeContext';

export default function LoginForm({ onSwitchToSignup }) {
  const { login, isLoading, authError, setAuthError } = useAuth();
  const { isDark } = useTheme();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');

  const handleSubmit = async (e) => {
    e.preventDefault();
    try {
      await login(email, password);
    } catch (err) {
      // Error handled by AuthContext
    }
  };

  return (
    <div style={{ width: '100%', display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
      <div style={{ textAlign: 'center', marginBottom: '0.5rem' }}>
        <h2 style={{ fontSize: '1.25rem', fontWeight: 800, color: isDark ? '#ffffff' : '#0f172a', margin: 0 }}>
          Sign In
        </h2>
      </div>

      {authError && (
        <div style={{
          background: 'rgba(239, 68, 68, 0.12)',
          border: '1px solid rgba(239, 68, 68, 0.3)',
          borderRadius: '8px',
          padding: '0.65rem 0.85rem',
          color: '#f87171',
          fontSize: '0.82rem',
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center'
        }}>
          <span>{authError}</span>
          <button 
            onClick={() => setAuthError(null)} 
            style={{ background: 'none', border: 'none', color: '#f87171', cursor: 'pointer', fontSize: '1.1rem', lineHeight: 1 }}
          >
            &times;
          </button>
        </div>
      )}

      <form onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
        <div>
          <label style={{ display: 'block', fontSize: '0.82rem', fontWeight: 700, color: isDark ? '#d4d4d8' : '#334155', marginBottom: '0.35rem' }}>
            Email / Username
          </label>
          <input
            type="text"
            required
            autoComplete="username"
            placeholder="Enter your email or username"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            style={{
              width: '100%',
              padding: '0.75rem 0.95rem',
              borderRadius: '8px',
              border: `1px solid ${isDark ? '#27272a' : '#cbd5e1'}`,
              background: isDark ? '#09090b' : '#ffffff',
              color: isDark ? '#ffffff' : '#0f172a',
              fontSize: '0.9rem',
              outline: 'none',
              boxSizing: 'border-box',
              transition: 'border-color 0.15s ease'
            }}
            onFocus={(e) => e.target.style.borderColor = isDark ? '#00f0ff' : '#0284c7'}
            onBlur={(e) => e.target.style.borderColor = isDark ? '#27272a' : '#cbd5e1'}
          />
        </div>

        <div>
          <label style={{ display: 'block', fontSize: '0.82rem', fontWeight: 700, color: isDark ? '#d4d4d8' : '#334155', marginBottom: '0.35rem' }}>
            Password
          </label>
          <input
            type="password"
            required
            autoComplete="current-password"
            placeholder="Enter your password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            style={{
              width: '100%',
              padding: '0.75rem 0.95rem',
              borderRadius: '8px',
              border: `1px solid ${isDark ? '#27272a' : '#cbd5e1'}`,
              background: isDark ? '#09090b' : '#ffffff',
              color: isDark ? '#ffffff' : '#0f172a',
              fontSize: '0.9rem',
              outline: 'none',
              boxSizing: 'border-box',
              transition: 'border-color 0.15s ease'
            }}
            onFocus={(e) => e.target.style.borderColor = isDark ? '#00f0ff' : '#0284c7'}
            onBlur={(e) => e.target.style.borderColor = isDark ? '#27272a' : '#cbd5e1'}
          />
        </div>

        <button
          type="submit"
          disabled={isLoading}
          style={{
            marginTop: '0.5rem',
            padding: '0.85rem',
            borderRadius: '8px',
            border: isDark ? '1.5px solid #ffffff' : 'none',
            background: isDark ? '#ffffff' : '#0284c7',
            color: isDark ? '#000000' : '#ffffff',
            fontSize: '0.95rem',
            fontWeight: 800,
            cursor: isLoading ? 'not-allowed' : 'pointer',
            opacity: isLoading ? 0.7 : 1,
            boxShadow: isDark ? '0 4px 15px rgba(255, 255, 255, 0.15)' : '0 4px 15px rgba(2, 132, 199, 0.25)',
            transition: 'all 0.15s ease'
          }}
        >
          {isLoading ? 'Signing In...' : 'Sign In'}
        </button>
      </form>

      <div style={{ textAlign: 'center', marginTop: '0.75rem' }}>
        <button
          type="button"
          onClick={onSwitchToSignup}
          style={{
            background: 'none',
            border: 'none',
            color: isDark ? '#a1a1aa' : '#64748b',
            fontSize: '0.85rem',
            fontWeight: 600,
            cursor: 'pointer'
          }}
        >
          Don't have an account? <span style={{ color: isDark ? '#ffffff' : '#0284c7', fontWeight: 800, textDecoration: 'underline' }}>Create Account</span>
        </button>
      </div>
    </div>
  );
}
