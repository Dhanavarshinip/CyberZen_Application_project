import React from 'react';
import { ShieldCheck, X } from 'lucide-react';
import { useTheme } from '../../context/ThemeContext';

export default function PrivacyTermsModal({ isOpen, onClose }) {
  const { isDark } = useTheme();

  if (!isOpen) return null;

  const bgModal = isDark ? '#09090b' : '#ffffff';
  const textPrimary = isDark ? '#ffffff' : '#0f172a';
  const textMuted = isDark ? '#a1a1aa' : '#64748b';
  const borderCol = isDark ? '#27272a' : '#e2e8f0';

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
        maxWidth: '600px',
        padding: '1.75rem',
        display: 'flex',
        flexDirection: 'column',
        gap: '1.25rem',
        maxHeight: '80vh',
        background: bgModal,
        border: `1px solid ${borderCol}`,
        borderRadius: '12px',
        boxShadow: isDark ? '0 20px 40px rgba(0,0,0,0.8)' : '0 20px 40px rgba(0,0,0,0.15)'
      }}>
        
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
            <ShieldCheck size={22} style={{ color: '#10b981' }} />
            <h3 style={{ fontSize: '1.1rem', fontWeight: 700, color: textPrimary, margin: 0 }}>Terms of Service & Privacy Policy</h3>
          </div>
          <button onClick={onClose} style={{ background: 'none', border: 'none', color: textMuted, cursor: 'pointer' }}>
            <X size={20} />
          </button>
        </div>

        <div style={{
          overflowY: 'auto',
          fontSize: '0.85rem',
          color: textMuted,
          lineHeight: '1.6',
          paddingRight: '0.5rem',
          display: 'flex',
          flexDirection: 'column',
          gap: '1rem'
        }}>
          <div>
            <h4 style={{ color: textPrimary, fontWeight: 600, marginBottom: '0.3rem' }}>1. Zero-Trust Local Security & Privacy</h4>
            <p style={{ margin: 0 }}>CyberZen processes local security telemetry, file hashes, and active network sockets directly on your local device. Telemetry is evaluated locally by your Behavioral Digital Twin without harvesting or transmitting personal documents.</p>
          </div>

          <div>
            <h4 style={{ color: textPrimary, fontWeight: 600, marginBottom: '0.3rem' }}>2. Continuous Host Telemetry Monitoring</h4>
            <p style={{ margin: 0 }}>By using CyberZen, you authorize background threat correlation, Machine Learning behavioral anomaly detection, and automated containment actions against malicious processes and suspicious network sockets.</p>
          </div>

          <div>
            <h4 style={{ color: textPrimary, fontWeight: 600, marginBottom: '0.3rem' }}>3. Enterprise Compliance</h4>
            <p style={{ margin: 0 }}>Complies with SOC 2 Type II, ISO 27001, and GDPR enterprise data protection principles for intelligent endpoint cyber threat detection and prevention systems.</p>
          </div>
        </div>

        <div style={{ display: 'flex', justifyContent: 'flex-end', paddingTop: '0.5rem', borderTop: `1px solid ${borderCol}` }}>
          <button
            onClick={onClose}
            style={{
              padding: '0.55rem 1.4rem',
              fontSize: '0.85rem',
              fontWeight: 700,
              borderRadius: '8px',
              border: 'none',
              background: isDark ? '#ffffff' : '#0f172a',
              color: isDark ? '#000000' : '#ffffff',
              cursor: 'pointer'
            }}
          >
            I Understand & Agree
          </button>
        </div>

      </div>
    </div>
  );
}
