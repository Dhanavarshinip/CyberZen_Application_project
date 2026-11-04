import React, { useState } from 'react';
import { useAuth } from '../../context/AuthContext';
import { useTheme } from '../../context/ThemeContext';
import { apiClient } from '../../services/apiClient';

export default function SignupForm({ onSwitchToLogin }) {
  const { signup, isLoading, authError, setAuthError } = useAuth();
  const { isDark } = useTheme();
  const [name, setName] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [consentAccepted, setConsentAccepted] = useState(false);
  const [localError, setLocalError] = useState('');
  const [otpCode, setOtpCode] = useState('');
  const [isVerifying, setIsVerifying] = useState(false);
  const [verificationSuccess, setVerificationSuccess] = useState(false);
  const [showOtpScreen, setShowOtpScreen] = useState(false);
  const [registeredEmail, setRegisteredEmail] = useState('');

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLocalError('');
    if (!name.trim()) {
      setLocalError('Please enter your full name.');
      return;
    }
    if (!email.trim() || !email.includes('@')) {
      setLocalError('Please enter a valid email address.');
      return;
    }
    if (password !== confirmPassword) {
      setLocalError('Passwords do not match.');
      return;
    }
    if (password.length < 6) {
      setLocalError('Password must be at least 6 characters.');
      return;
    }
    if (!consentAccepted) {
      setLocalError('You must acknowledge and accept the privacy notice and monitoring consent.');
      return;
    }
    try {
      await signup(name, email, password, consentAccepted);
      // Successfully registered and logged in directly
    } catch (err) {
      // Handled in context
    }
  };

  const handleVerifyOtp = async (e) => {
    e.preventDefault();
    if (!otpCode.trim()) {
      setLocalError('Please enter the 6-digit verification code.');
      return;
    }
    setIsVerifying(true);
    setLocalError('');
    try {
      await apiClient.verifyEmail(registeredEmail || email, otpCode);
      setVerificationSuccess(true);
      setTimeout(() => {
        if (onSwitchToLogin) onSwitchToLogin();
      }, 2000);
    } catch (err) {
      setLocalError(err.message || 'Verification failed. Please check the code.');
    } finally {
      setIsVerifying(false);
    }
  };

  const handleResendOtp = async () => {
    try {
      await apiClient.resendVerification(registeredEmail || email);
      setLocalError('A fresh verification code has been dispatched.');
    } catch (err) {
      setLocalError(err.message || 'Could not resend code.');
    }
  };

  const activeError = localError || authError;

  const inputBg = isDark ? '#09090b' : '#ffffff';
  const inputBorder = isDark ? '#27272a' : '#cbd5e1';
  const inputFocusBorder = isDark ? '#3b82f6' : '#2563eb';
  const textColor = isDark ? '#ffffff' : '#0f172a';
  const mutedTextColor = isDark ? '#a1a1aa' : '#64748b';
  const labelColor = isDark ? '#d4d4d8' : '#334155';
  const buttonBg = isDark ? '#ffffff' : '#0f172a';
  const buttonTextColor = isDark ? '#09090b' : '#ffffff';

  if (showOtpScreen) {
    return (
      <div style={{ width: '100%', display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
        <div style={{ textAlign: 'center', marginBottom: '0.5rem' }}>
          <h2 style={{ fontSize: '1.25rem', fontWeight: 700, color: textColor, margin: 0 }}>
            Verify Your Email
          </h2>
          <p style={{ fontSize: '0.82rem', color: mutedTextColor, marginTop: '0.35rem' }}>
            We sent a 6-digit verification code to <strong style={{ color: textColor }}>{registeredEmail}</strong>
          </p>
        </div>

        {verificationSuccess ? (
          <div style={{
            background: 'rgba(16, 185, 129, 0.15)',
            border: '1px solid #10b981',
            borderRadius: '8px',
            padding: '1rem',
            textAlign: 'center',
            color: '#10b981',
            fontSize: '0.9rem',
            fontWeight: 600
          }}>
            ✓ Email verified successfully! Redirecting to sign in...
          </div>
        ) : (
          <form onSubmit={handleVerifyOtp} style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
            {activeError && (
              <div style={{
                background: 'rgba(239, 68, 68, 0.12)',
                border: '1px solid rgba(239, 68, 68, 0.3)',
                borderRadius: '8px',
                padding: '0.65rem 0.85rem',
                color: '#f87171',
                fontSize: '0.82rem'
              }}>
                {activeError}
              </div>
            )}
            <div>
              <label style={{ display: 'block', fontSize: '0.82rem', fontWeight: 600, color: labelColor, marginBottom: '0.35rem' }}>
                Enter 6-Digit Code
              </label>
              <input
                type="text"
                required
                maxLength={6}
                placeholder="123456"
                value={otpCode}
                onChange={(e) => setOtpCode(e.target.value.replace(/\D/g, ''))}
                style={{
                  width: '100%',
                  padding: '0.75rem',
                  borderRadius: '8px',
                  background: inputBg,
                  border: `1.5px solid ${inputBorder}`,
                  color: textColor,
                  fontSize: '1.5rem',
                  letterSpacing: '6px',
                  textAlign: 'center',
                  outline: 'none',
                  boxSizing: 'border-box'
                }}
              />
            </div>

            <button
              type="submit"
              disabled={isVerifying}
              style={{
                width: '100%',
                padding: '0.85rem',
                borderRadius: '8px',
                border: 'none',
                background: buttonBg,
                color: buttonTextColor,
                fontWeight: 800,
                fontSize: '0.95rem',
                cursor: isVerifying ? 'not-allowed' : 'pointer',
                transition: 'all 0.15s ease'
              }}
            >
              {isVerifying ? 'Verifying...' : 'Confirm Verification Code'}
            </button>

            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: '0.5rem', fontSize: '0.82rem' }}>
              <button
                type="button"
                onClick={handleResendOtp}
                style={{ background: 'none', border: 'none', color: textColor, cursor: 'pointer', padding: 0, textDecoration: 'underline' }}
              >
                Resend Code
              </button>
              <button
                type="button"
                onClick={() => setShowOtpScreen(false)}
                style={{ background: 'none', border: 'none', color: mutedTextColor, cursor: 'pointer', padding: 0 }}
              >
                Back to Registration
              </button>
            </div>
          </form>
        )}
      </div>
    );
  }

  return (
    <div style={{ width: '100%', display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
      <div style={{ textAlign: 'center', marginBottom: '0.5rem' }}>
        <h2 style={{ fontSize: '1.25rem', fontWeight: 800, color: textColor, margin: 0 }}>
          Create Account
        </h2>
        <p style={{ fontSize: '0.82rem', color: mutedTextColor, marginTop: '0.35rem' }}>
          Real-time threat monitoring and behavioral digital twin defense
        </p>
      </div>

      {activeError && (
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
          <span>{activeError}</span>
          <button 
            onClick={() => { setLocalError(''); setAuthError(null); }} 
            style={{ background: 'none', border: 'none', color: '#f87171', cursor: 'pointer', fontSize: '1.1rem', lineHeight: 1 }}
          >
            &times;
          </button>
        </div>
      )}

      <form onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: '0.9rem' }}>
        <div>
          <label style={{ display: 'block', fontSize: '0.82rem', fontWeight: 700, color: labelColor, marginBottom: '0.35rem' }}>
            Full Name
          </label>
          <input
            type="text"
            required
            autoComplete="name"
            placeholder="Your name"
            value={name}
            onChange={(e) => setName(e.target.value)}
            style={{
              width: '100%',
              padding: '0.75rem 0.95rem',
              borderRadius: '8px',
              border: `1px solid ${inputBorder}`,
              background: inputBg,
              color: textColor,
              fontSize: '0.9rem',
              outline: 'none',
              boxSizing: 'border-box',
              transition: 'border-color 0.15s ease'
            }}
            onFocus={(e) => e.target.style.borderColor = inputFocusBorder}
            onBlur={(e) => e.target.style.borderColor = inputBorder}
          />
        </div>

        <div>
          <label style={{ display: 'block', fontSize: '0.82rem', fontWeight: 700, color: labelColor, marginBottom: '0.35rem' }}>
            Email Address
          </label>
          <input
            type="email"
            required
            autoComplete="email"
            placeholder="you@example.com"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            style={{
              width: '100%',
              padding: '0.75rem 0.95rem',
              borderRadius: '8px',
              border: `1px solid ${inputBorder}`,
              background: inputBg,
              color: textColor,
              fontSize: '0.9rem',
              outline: 'none',
              boxSizing: 'border-box',
              transition: 'border-color 0.15s ease'
            }}
            onFocus={(e) => e.target.style.borderColor = inputFocusBorder}
            onBlur={(e) => e.target.style.borderColor = inputBorder}
          />
        </div>

        <div>
          <label style={{ display: 'block', fontSize: '0.82rem', fontWeight: 700, color: labelColor, marginBottom: '0.35rem' }}>
            Password
          </label>
          <input
            type="password"
            required
            autoComplete="new-password"
            placeholder="Password (min 6 characters)"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            style={{
              width: '100%',
              padding: '0.75rem 0.95rem',
              borderRadius: '8px',
              border: `1px solid ${inputBorder}`,
              background: inputBg,
              color: textColor,
              fontSize: '0.9rem',
              outline: 'none',
              boxSizing: 'border-box',
              transition: 'border-color 0.15s ease'
            }}
            onFocus={(e) => e.target.style.borderColor = inputFocusBorder}
            onBlur={(e) => e.target.style.borderColor = inputBorder}
          />
        </div>

        <div>
          <label style={{ display: 'block', fontSize: '0.82rem', fontWeight: 700, color: labelColor, marginBottom: '0.35rem' }}>
            Confirm Password
          </label>
          <input
            type="password"
            required
            autoComplete="new-password"
            placeholder="Confirm password"
            value={confirmPassword}
            onChange={(e) => setConfirmPassword(e.target.value)}
            style={{
              width: '100%',
              padding: '0.75rem 0.95rem',
              borderRadius: '8px',
              border: `1px solid ${inputBorder}`,
              background: inputBg,
              color: textColor,
              fontSize: '0.9rem',
              outline: 'none',
              boxSizing: 'border-box',
              transition: 'border-color 0.15s ease'
            }}
            onFocus={(e) => e.target.style.borderColor = inputFocusBorder}
            onBlur={(e) => e.target.style.borderColor = inputBorder}
          />
        </div>

        <div style={{ display: 'flex', alignItems: 'flex-start', gap: '0.65rem', marginTop: '0.25rem' }}>
          <input
            type="checkbox"
            id="monitoring-consent"
            checked={consentAccepted}
            onChange={(e) => setConsentAccepted(e.target.checked)}
            style={{
              marginTop: '0.2rem',
              cursor: 'pointer',
              accentColor: isDark ? '#3b82f6' : '#2563eb',
              width: '16px',
              height: '16px'
            }}
          />
          <label htmlFor="monitoring-consent" style={{ fontSize: '0.8rem', color: mutedTextColor, lineHeight: 1.4, cursor: 'pointer' }}>
            I agree to the <span style={{ color: textColor, textDecoration: 'underline' }}>Privacy Notice</span> and consent to local system telemetry collection for cybersecurity defense.
          </label>
        </div>

        <button
          type="submit"
          disabled={isLoading}
          style={{
            marginTop: '0.5rem',
            padding: '0.85rem',
            borderRadius: '8px',
            border: 'none',
            background: buttonBg,
            color: buttonTextColor,
            fontSize: '0.95rem',
            fontWeight: 800,
            cursor: isLoading ? 'not-allowed' : 'pointer',
            opacity: isLoading ? 0.7 : 1,
            boxShadow: isDark ? '0 4px 15px rgba(0, 0, 0, 0.6)' : '0 4px 15px rgba(15, 23, 42, 0.15)',
            transition: 'all 0.15s ease'
          }}
        >
          {isLoading ? 'Creating Account...' : 'Create Account'}
        </button>
      </form>

      <div style={{ textAlign: 'center', marginTop: '0.75rem' }}>
        <button
          type="button"
          onClick={onSwitchToLogin}
          style={{
            background: 'none',
            border: 'none',
            color: mutedTextColor,
            fontSize: '0.85rem',
            fontWeight: 500,
            cursor: 'pointer'
          }}
        >
          Already have an account? <span style={{ color: textColor, fontWeight: 700, textDecoration: 'underline' }}>Sign In</span>
        </button>
      </div>
    </div>
  );
}
