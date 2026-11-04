import React, { useState } from 'react';
import { Shield, Cpu, Activity, Database, GitBranch, ArrowRight, Download, CheckCircle2, Lock, Terminal, Eye, Layers } from 'lucide-react';

export default function PublicHomeView({ onNavigate, onOpenDownload, onOpenRegister, onOpenLogin }) {
  const [hasDownloaded] = useState(() => localStorage.getItem('cyberthreat_app_downloaded') === 'true');
  return (
    <div style={{ maxWidth: '1200px', margin: '0 auto', padding: '2rem 1.5rem', color: '#f8fafc' }}>
      
      {/* Hero Section */}
      <div style={{
        textAlign: 'center',
        padding: '3.5rem 1rem 4rem 1rem',
        position: 'relative'
      }}>
        <div style={{
          display: 'inline-flex',
          alignItems: 'center',
          gap: '0.5rem',
          background: 'rgba(0, 240, 255, 0.08)',
          border: '1px solid rgba(0, 240, 255, 0.25)',
          padding: '0.35rem 0.85rem',
          borderRadius: '20px',
          fontSize: '0.8rem',
          color: '#00f0ff',
          fontWeight: 600,
          marginBottom: '1.5rem'
        }}>
          <Shield size={14} />
          <span>CyberZen AI Defense Platform</span>
        </div>

        <h1 style={{
          fontSize: 'clamp(1.9rem, 4.5vw, 3.2rem)',
          fontWeight: 800,
          lineHeight: 1.2,
          letterSpacing: '-0.03em',
          margin: '0 auto 1.5rem auto',
          maxWidth: '960px',
          background: 'linear-gradient(135deg, #ffffff 30%, #94a3b8 100%)',
          WebkitBackgroundClip: 'text',
          WebkitTextFillColor: 'transparent'
        }}>
          Intelligent Real-Time Digital Threat Detection, Prevention and Incident Reconstruction
        </h1>

        <p style={{
          fontSize: '1.1rem',
          lineHeight: 1.6,
          color: '#94a3b8',
          maxWidth: '720px',
          margin: '0 auto 2.5rem auto'
        }}>
          CyberZen continuously monitors genuine online and offline device activities, calculates real-time behavioral drift, isolates zero-day anomalies with Isolation Forest, and reconstructs security incidents using a Temporal Knowledge Graph.
        </p>

        <div style={{ display: 'flex', justifyContent: 'center', gap: '1rem', flexWrap: 'wrap' }}>
          {!hasDownloaded ? (
            <button
              onClick={onOpenDownload}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '0.6rem',
                padding: '0.85rem 1.75rem',
                borderRadius: '8px',
                border: 'none',
                background: '#00f0ff',
                color: '#090d16',
                fontSize: '1rem',
                fontWeight: 700,
                cursor: 'pointer',
                boxShadow: '0 0 25px rgba(0, 240, 255, 0.3)',
                transition: 'transform 0.15s ease'
              }}
            >
              <Download size={18} />
              <span>Download for Windows</span>
            </button>
          ) : (
            <button
              onClick={onOpenRegister}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '0.6rem',
                padding: '0.85rem 1.75rem',
                borderRadius: '8px',
                border: 'none',
                background: '#10b981',
                color: '#090d16',
                fontSize: '1rem',
                fontWeight: 700,
                cursor: 'pointer',
                boxShadow: '0 0 25px rgba(16, 185, 129, 0.3)',
                transition: 'transform 0.15s ease'
              }}
            >
              <CheckCircle2 size={18} />
              <span>Downloaded • Open App & Create Account</span>
            </button>
          )}

          <button
            onClick={onOpenRegister}
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '0.6rem',
              padding: '0.85rem 1.75rem',
              borderRadius: '8px',
              border: '1px solid #334155',
              background: '#0f172a',
              color: '#f8fafc',
              fontSize: '1rem',
              fontWeight: 600,
              cursor: 'pointer',
              transition: 'border-color 0.15s ease'
            }}
          >
            <span>{hasDownloaded ? 'Sign In / Register' : 'Create Free Account'}</span>
            <ArrowRight size={16} />
          </button>
        </div>

        <div style={{
          display: 'flex',
          justifyContent: 'center',
          alignItems: 'center',
          gap: '2rem',
          marginTop: '2.5rem',
          fontSize: '0.8rem',
          color: '#64748b'
        }}>
          <span style={{ display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
            <CheckCircle2 size={14} style={{ color: '#4ade80' }} /> Windows 10 & 11 Verified
          </span>
          <span style={{ display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
            <CheckCircle2 size={14} style={{ color: '#4ade80' }} /> Local SQLite Offline Cache
          </span>
          <span style={{ display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
            <CheckCircle2 size={14} style={{ color: '#4ade80' }} /> Zero Private Data Snooping
          </span>
        </div>
      </div>

      {/* Core Architectural Pillars */}
      <div style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))',
        gap: '1.5rem',
        margin: '2rem 0 4rem 0'
      }}>
        <div style={{
          background: '#0f172a',
          border: '1px solid #1e293b',
          borderRadius: '12px',
          padding: '1.75rem',
          display: 'flex',
          flexDirection: 'column',
          gap: '1rem'
        }}>
          <div style={{
            width: '42px',
            height: '42px',
            borderRadius: '10px',
            background: 'rgba(0, 240, 255, 0.1)',
            color: '#00f0ff',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center'
          }}>
            <Cpu size={22} />
          </div>
          <h3 style={{ fontSize: '1.15rem', fontWeight: 700, margin: 0, color: '#f8fafc' }}>
            Isolation Forest Anomaly Detection
          </h3>
          <p style={{ fontSize: '0.88rem', color: '#94a3b8', lineHeight: 1.6, margin: 0 }}>
            Trained ensemble isolation estimators evaluate 14-dimensional feature vectors in real time, detecting unknown threats and abnormal execution patterns before signatures exist.
          </p>
        </div>

        <div style={{
          background: '#0f172a',
          border: '1px solid #1e293b',
          borderRadius: '12px',
          padding: '1.75rem',
          display: 'flex',
          flexDirection: 'column',
          gap: '1rem'
        }}>
          <div style={{
            width: '42px',
            height: '42px',
            borderRadius: '10px',
            background: 'rgba(56, 189, 248, 0.1)',
            color: '#38bdf8',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center'
          }}>
            <Activity size={22} />
          </div>
          <h3 style={{ fontSize: '1.15rem', fontWeight: 700, margin: 0, color: '#f8fafc' }}>
            Behavioral Digital Twin
          </h3>
          <p style={{ fontSize: '0.88rem', color: '#94a3b8', lineHeight: 1.6, margin: 0 }}>
            Builds a baseline profile of known applications, typical operating hours, and network habits. Dynamically computes drift score $B(t)$ whenever behavior deviates from normal patterns.
          </p>
        </div>

        <div style={{
          background: '#0f172a',
          border: '1px solid #1e293b',
          borderRadius: '12px',
          padding: '1.75rem',
          display: 'flex',
          flexDirection: 'column',
          gap: '1rem'
        }}>
          <div style={{
            width: '42px',
            height: '42px',
            borderRadius: '10px',
            background: 'rgba(168, 85, 247, 0.1)',
            color: '#a855f7',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center'
          }}>
            <GitBranch size={22} />
          </div>
          <h3 style={{ fontSize: '1.15rem', fontWeight: 700, margin: 0, color: '#f8fafc' }}>
            Temporal Knowledge Graph
          </h3>
          <p style={{ fontSize: '0.88rem', color: '#94a3b8', lineHeight: 1.6, margin: 0 }}>
            Maps cause-and-effect relationships across processes, downloaded files, network sockets, and browser navigations. Enables deterministic step-by-step incident reconstruction.
          </p>
        </div>
      </div>

      {/* CTA Banner */}
      <div style={{
        background: 'linear-gradient(135deg, rgba(0, 240, 255, 0.1) 0%, rgba(15, 23, 42, 0.8) 100%)',
        border: '1px solid rgba(0, 240, 255, 0.3)',
        borderRadius: '16px',
        padding: '3rem 2rem',
        textAlign: 'center',
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        gap: '1.25rem'
      }}>
        <h2 style={{ fontSize: '1.8rem', fontWeight: 800, margin: 0, color: '#f8fafc' }}>
          Protect Your Windows Laptop Today
        </h2>
        <p style={{ fontSize: '0.95rem', color: '#94a3b8', maxWidth: '600px', margin: 0, lineHeight: 1.6 }}>
          Experience transparent, genuine host monitoring with zero telemetry mocking. Download the installer, enroll your device, and verify protection on real Windows hardware.
        </p>
        <div style={{ display: 'flex', gap: '1rem', flexWrap: 'wrap', marginTop: '0.5rem' }}>
          <button
            onClick={onOpenDownload}
            style={{
              padding: '0.8rem 1.6rem',
              borderRadius: '8px',
              border: 'none',
              background: '#00f0ff',
              color: '#090d16',
              fontWeight: 700,
              fontSize: '0.95rem',
              cursor: 'pointer'
            }}
          >
            Go to Download Page
          </button>
          <button
            onClick={() => onNavigate('features')}
            style={{
              padding: '0.8rem 1.6rem',
              borderRadius: '8px',
              border: '1px solid #334155',
              background: '#0f172a',
              color: '#cbd5e1',
              fontWeight: 600,
              fontSize: '0.95rem',
              cursor: 'pointer'
            }}
          >
            Explore All Features
          </button>
        </div>
      </div>

    </div>
  );
}
