import React from 'react';
import { Cpu, Activity, GitBranch, Shield, Eye, Database, Terminal, Globe, HardDrive, Wifi, Lock, AlertTriangle, CheckCircle2 } from 'lucide-react';

export default function FeaturesView({ onOpenDownload, onOpenRegister }) {
  return (
    <div style={{ maxWidth: '1200px', margin: '0 auto', padding: '2rem 1.5rem', color: '#f8fafc' }}>
      
      {/* Title Header */}
      <div style={{ textAlign: 'center', marginBottom: '3.5rem' }}>
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
          marginBottom: '1rem'
        }}>
          <Shield size={14} />
          <span>Comprehensive Technical Capabilities</span>
        </div>
        <h1 style={{ fontSize: '2.5rem', fontWeight: 800, margin: '0 0 1rem 0', letterSpacing: '-0.02em' }}>
          Real Defense Modules & Validated Models
        </h1>
        <p style={{ fontSize: '1.05rem', color: '#94a3b8', maxWidth: '750px', margin: '0 auto', lineHeight: 1.6 }}>
          Every feature described below is backed by running code, concrete collectors, persistent database records, or trained machine learning pipelines.
        </p>
      </div>

      {/* 4 Host Collectors Section */}
      <div style={{ marginBottom: '4rem' }}>
        <h2 style={{ fontSize: '1.5rem', fontWeight: 800, margin: '0 0 1.5rem 0', color: '#f8fafc' }}>
          1. Supported Host Telemetry Collectors
        </h2>
        
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '1.5rem' }}>
          
          {/* Process Monitor */}
          <div style={{ background: '#0f172a', border: '1px solid #1e293b', borderRadius: '12px', padding: '1.75rem', display: 'flex', flexDirection: 'column', gap: '1rem' }}>
            <div style={{ width: '40px', height: '40px', borderRadius: '8px', background: 'rgba(0, 240, 255, 0.1)', color: '#00f0ff', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
              <Terminal size={20} />
            </div>
            <h3 style={{ fontSize: '1.1rem', fontWeight: 700, margin: 0, color: '#f8fafc' }}>
              Host Process Monitor
            </h3>
            <p style={{ fontSize: '0.85rem', color: '#94a3b8', lineHeight: 1.5, margin: 0 }}>
              Inspects live process spawns via system APIs. Detects executions from temp or roaming directories, double-extension files, and unsolicited promotional scareware/adware popups.
            </p>
            <div style={{ fontSize: '0.78rem', color: '#64748b', background: '#090d16', padding: '0.65rem', borderRadius: '6px', border: '1px solid #1e293b' }}>
              <strong>Evidence Recorded:</strong> PID, process name, command line arguments, parent process, execution path.
            </div>
          </div>

          {/* File Watcher */}
          <div style={{ background: '#0f172a', border: '1px solid #1e293b', borderRadius: '12px', padding: '1.75rem', display: 'flex', flexDirection: 'column', gap: '1rem' }}>
            <div style={{ width: '40px', height: '40px', borderRadius: '8px', background: 'rgba(56, 189, 248, 0.1)', color: '#38bdf8', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
              <HardDrive size={20} />
            </div>
            <h3 style={{ fontSize: '1.1rem', fontWeight: 700, margin: 0, color: '#f8fafc' }}>
              File & Download Watcher
            </h3>
            <p style={{ fontSize: '0.85rem', color: '#94a3b8', lineHeight: 1.5, margin: 0 }}>
              Monitors User Downloads and Desktop for newly created or modified executables, archives, and scripts. Computes cryptographic SHA-256 hashes and scans for the standard EICAR test signature.
            </p>
            <div style={{ fontSize: '0.78rem', color: '#64748b', background: '#090d16', padding: '0.65rem', borderRadius: '6px', border: '1px solid #1e293b' }}>
              <strong>Evidence Recorded:</strong> File path, size in bytes, SHA-256 hash, creation timestamp, signature verdict.
            </div>
          </div>

          {/* Network Socket Monitor */}
          <div style={{ background: '#0f172a', border: '1px solid #1e293b', borderRadius: '12px', padding: '1.75rem', display: 'flex', flexDirection: 'column', gap: '1rem' }}>
            <div style={{ width: '40px', height: '40px', borderRadius: '8px', background: 'rgba(168, 85, 247, 0.1)', color: '#a855f7', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
              <Wifi size={20} />
            </div>
            <h3 style={{ fontSize: '1.1rem', fontWeight: 700, margin: 0, color: '#f8fafc' }}>
              Network Socket Inspector
            </h3>
            <p style={{ fontSize: '0.85rem', color: '#94a3b8', lineHeight: 1.5, margin: 0 }}>
              Enumerates active TCP and UDP internet connections. Maps sockets to owning local processes, differentiates RFC 1918 private subnets from external IPs, and flags non-standard egress ports.
            </p>
            <div style={{ fontSize: '0.78rem', color: '#64748b', background: '#090d16', padding: '0.65rem', borderRadius: '6px', border: '1px solid #1e293b' }}>
              <strong>Evidence Recorded:</strong> Local/Remote IP and port, connection state, owning PID, protocol type.
            </div>
          </div>

          {/* Browser Integration */}
          <div style={{ background: '#0f172a', border: '1px solid #1e293b', borderRadius: '12px', padding: '1.75rem', display: 'flex', flexDirection: 'column', gap: '1rem' }}>
            <div style={{ width: '40px', height: '40px', borderRadius: '8px', background: 'rgba(34, 197, 94, 0.1)', color: '#4ade80', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
              <Globe size={20} />
            </div>
            <h3 style={{ fontSize: '1.1rem', fontWeight: 700, margin: 0, color: '#f8fafc' }}>
              Browser Extension Integration
            </h3>
            <p style={{ fontSize: '0.85rem', color: '#94a3b8', lineHeight: 1.5, margin: 0 }}>
              Integrates with Google Chrome and Edge via Manifest V3 extension. Evaluates URLs for known threats, separates piracy policy advisories from malware, and captures rich video contexts on YouTube.
            </p>
            <div style={{ fontSize: '0.78rem', color: '#64748b', background: '#090d16', padding: '0.65rem', borderRadius: '6px', border: '1px solid #1e293b' }}>
              <strong>Evidence Recorded:</strong> Navigated URL, domain reputation, page/video title, classification badge.
            </div>
          </div>

        </div>
      </div>

      {/* AI Threat Detection & Incident Reconstruction */}
      <div style={{ marginBottom: '4rem' }}>
        <h2 style={{ fontSize: '1.5rem', fontWeight: 800, margin: '0 0 1.5rem 0', color: '#f8fafc' }}>
          2. Machine Learning, Drift, & Temporal Reconstruction
        </h2>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(340px, 1fr))', gap: '1.5rem' }}>
          
          <div style={{ background: '#0f172a', border: '1px solid #1e293b', borderRadius: '12px', padding: '2rem', display: 'flex', flexDirection: 'column', gap: '1rem' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem' }}>
              <Cpu size={22} style={{ color: '#00f0ff' }} />
              <h3 style={{ fontSize: '1.2rem', fontWeight: 700, margin: 0, color: '#f8fafc' }}>
                Isolation Forest Ensemble Model
              </h3>
            </div>
            <p style={{ fontSize: '0.88rem', color: '#94a3b8', lineHeight: 1.6, margin: 0 }}>
              Uses a trained 100-tree scikit-learn Isolation Forest model (`models/isolation_forest.joblib`). Extracts 14 standardized features per event (process duration, port risk, file entropy, time of day) and computes anomaly score $A(t) \in [0, 100]$.
            </p>
            <div style={{ background: '#090d16', border: '1px solid #1e293b', borderRadius: '8px', padding: '1rem', fontSize: '0.82rem', color: '#cbd5e1' }}>
              <strong>No Hardcoded Verdicts:</strong> Events with high tree partition depth are flagged as anomalous, while common typical actions remain safely within normal variance.
            </div>
          </div>

          <div style={{ background: '#0f172a', border: '1px solid #1e293b', borderRadius: '12px', padding: '2rem', display: 'flex', flexDirection: 'column', gap: '1rem' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem' }}>
              <Activity size={22} style={{ color: '#38bdf8' }} />
              <h3 style={{ fontSize: '1.2rem', fontWeight: 700, margin: 0, color: '#f8fafc' }}>
                Behavioral Digital Twin
              </h3>
            </div>
            <p style={{ fontSize: '0.88rem', color: '#94a3b8', lineHeight: 1.6, margin: 0 }}>
              Maintains an evolving statistical profile of the user's authentic activities. Profiles common login hours, regular applications, average session lengths, and trusted network destinations. Calculates drift score $B(t) \in [0, 100]$.
            </p>
            <div style={{ background: '#090d16', border: '1px solid #1e293b', borderRadius: '8px', padding: '1rem', fontSize: '0.82rem', color: '#cbd5e1' }}>
              <strong>Adaptive Learning:</strong> Continues learning legitimately without discarding past security incidents or resetting without user consent.
            </div>
          </div>

          <div style={{ background: '#0f172a', border: '1px solid #1e293b', borderRadius: '12px', padding: '2rem', display: 'flex', flexDirection: 'column', gap: '1rem' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem' }}>
              <GitBranch size={22} style={{ color: '#a855f7' }} />
              <h3 style={{ fontSize: '1.2rem', fontWeight: 700, margin: 0, color: '#f8fafc' }}>
                Temporal Knowledge Graph
              </h3>
            </div>
            <p style={{ fontSize: '0.88rem', color: '#94a3b8', lineHeight: 1.6, margin: 0 }}>
              Built with NetworkX, the temporal graph tracks entities (User, Device, Process, File, Network Socket, Domain) and temporal relations (SPAWNED, CONNECTED_TO, DOWNLOADED, MODIFIED).
            </p>
            <div style={{ background: '#090d16', border: '1px solid #1e293b', borderRadius: '8px', padding: '1rem', fontSize: '0.82rem', color: '#cbd5e1' }}>
              <strong>Interactive Causal Chain:</strong> Links an alert step-by-step from browser navigation $\rightarrow$ downloaded payload $\rightarrow$ executed process $\rightarrow$ suspicious network connection.
            </div>
          </div>

        </div>
      </div>

      {/* Offline Architecture & Persistence */}
      <div style={{
        background: '#0f172a',
        border: '1px solid #1e293b',
        borderRadius: '12px',
        padding: '2.5rem 2rem',
        display: 'flex',
        flexDirection: 'column',
        gap: '1.25rem',
        marginBottom: '4rem'
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem' }}>
          <Database size={22} style={{ color: '#00f0ff' }} />
          <h2 style={{ fontSize: '1.35rem', fontWeight: 800, margin: 0, color: '#f8fafc' }}>
            Local-First Persistence & Duplicate-Free Cloud Sync
          </h2>
        </div>
        <p style={{ fontSize: '0.92rem', color: '#94a3b8', lineHeight: 1.6, margin: 0 }}>
          Security cannot depend on an internet connection. CyberZen is designed with an offline-first architecture:
        </p>
        <ul style={{ color: '#cbd5e1', fontSize: '0.88rem', lineHeight: 1.7, margin: 0, paddingLeft: '1.25rem' }}>
          <li>All monitoring threads write immediately to the local SQLite database in WAL (Write-Ahead Logging) mode.</li>
          <li>When offline, the host agent queues pending sync items without dropping events or crashing.</li>
          <li>Upon network restoration, events are synced to the cloud service idempotently, guaranteeing zero duplicates.</li>
          <li>Historical activities can be browsed date-by-date across any calendar day using your exact local timezone.</li>
        </ul>
      </div>

      {/* Action Footer */}
      <div style={{ textAlign: 'center', padding: '2rem 1rem' }}>
        <h2 style={{ fontSize: '1.5rem', fontWeight: 800, color: '#f8fafc', margin: '0 0 1rem 0' }}>
          Ready to Test CyberZen?
        </h2>
        <div style={{ display: 'flex', justifyContent: 'center', gap: '1rem' }}>
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
            Download Windows Installer
          </button>
          <button
            onClick={onOpenRegister}
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
            Create Account
          </button>
        </div>
      </div>

    </div>
  );
}
