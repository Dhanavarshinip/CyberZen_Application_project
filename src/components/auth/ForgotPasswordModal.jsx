import React, { useState } from 'react';
import { ShieldAlert, X, Mail, CheckCircle2, ArrowRight } from 'lucide-react';
import { useTheme } from '../../context/ThemeContext';

export default function ForgotPasswordModal({ isOpen, onClose }) {
  const { isDark } = useTheme();
  const [resetEmail, setResetEmail] = useState('');
  const [submitted, setSubmitted] = useState(false);

  if (!isOpen) return null;

  const handleSubmit = (e) => {
    e.preventDefault();
    if (resetEmail) {
      setSubmitted(true);
    }
  };

  const bgModal = isDark ? '#09090b' : '#ffffff';
  const textPrimary = isDark ? '#ffffff' : '#0f172a';
  const textMuted = isDark ? '#a1a1aa' : '#64748b';
  const borderCol = isDark ? '#27272a' : '#e2e8f0';
  const inputBg = isDark ? '#18181b' : '#f8fafc';

  return (
    <div style={{
      position: 'fixed',
      top: 0, left: 0, right: 0, bottom: 0,
      background: 'rgba(0, 0, 0, 0.75)',
      backdropFilter: 'blur(8px)',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      zIndex: 2000,
      padding: '1rem'
    }}>
      <div style={{
        width: '100%',
        maxWidth: '480px',
        padding: '1.75rem',
        display: 'flex',
        flexDirection: 'column',
        gap: '1.25rem',
        background: bgModal,
        border: `1px solid ${borderCol}`,
        borderRadius: '12px',
        boxShadow: isDark ? '0 20px 40px rgba(0,0,0,0.8)' : '0 20px 40px rgba(0,0,0,0.15)'
      }}>
        
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
            <ShieldAlert size={22} style={{ color: '#06b6d4' }} />
            <h3 style={{ fontSize: '1.1rem', fontWeight: 700, color: textPrimary, margin: 0 }}>Reset Password</h3>
          </div>
          <button onClick={onClose} style={{ background: 'none', border: 'none', color: textMuted, cursor: 'pointer' }}>
            <X size={20} />
          </button>
        </div>

        {submitted ? (
          <div style={{ textAlign: 'center', padding: '1rem 0' }}>
            <CheckCircle2 size={48} style={{ color: '#10b981', margin: '0 auto 1rem' }} />
            <h4 style={{ fontSize: '1rem', fontWeight: 600, color: textPrimary, marginBottom: '0.5rem' }}>Password Reset Link Dispatched</h4>
            <p style={{ fontSize: '0.85rem', color: textMuted, marginBottom: '1.5rem' }}>
              We have dispatched a secure password reset link to <strong style={{ color: '#06b6d4' }}>{resetEmail}</strong>.
            </p>
            <button
              onClick={onClose}
              style={{
                width: '100%',
                padding: '0.75rem',
                borderRadius: '8px',
                border: 'none',
                background: isDark ? '#ffffff' : '#0f172a',
                color: isDark ? '#000000' : '#ffffff',
                fontWeight: 700,
                cursor: 'pointer'
              }}
            >
              Return to Login
            </button>
          </div>
        ) : (
          <form onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
            <p style={{ fontSize: '0.85rem', color: textMuted, margin: 0 }}>
              Enter your registered email address. We will send a secure tokenized password reset link.
            </p>

            <div style={{ position: 'relative' }}>
              <Mail size={16} style={{ position: 'absolute', left: '14px', top: '50%', transform: 'translateY(-50%)', color: textMuted }} />
              <input
                type="email"
                required
                placeholder="name@example.com"
                value={resetEmail}
                onChange={(e) => setResetEmail(e.target.value)}
                style={{
                  width: '100%',
                  padding: '0.75rem 1rem 0.75rem 2.5rem',
                  borderRadius: '8px',
                  border: `1px solid ${borderCol}`,
                  background: inputBg,
                  color: textPrimary,
                  fontSize: '0.85rem',
                  outline: 'none',
                  boxSizing: 'border-box'
                }}
              />
            </div>

            <div style={{ display: 'flex', gap: '0.75rem', marginTop: '0.5rem' }}>
              <button
                type="button"
                onClick={onClose}
                style={{
                  flex: 1,
                  padding: '0.75rem',
                  borderRadius: '8px',
                  border: `1px solid ${borderCol}`,
                  background: 'transparent',
                  color: textPrimary,
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
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  gap: '0.4rem',
                  padding: '0.75rem',
                  borderRadius: '8px',
                  border: 'none',
                  background: isDark ? '#ffffff' : '#0f172a',
                  color: isDark ? '#000000' : '#ffffff',
                  fontWeight: 700,
                  cursor: 'pointer'
                }}
              >
                Send Link <ArrowRight size={14} />
              </button>
            </div>
          </form>
        )}

      </div>
    </div>
  );
}
