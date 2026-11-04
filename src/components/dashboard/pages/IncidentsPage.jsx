import React from 'react';
import { ShieldAlert, Clock, CheckCircle2, AlertOctagon } from 'lucide-react';

export default function IncidentsPage() {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
      <div className="glass-panel" style={{ padding: '1.25rem' }}>
        <h2 style={{ fontSize: '1.15rem', fontWeight: 700, display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <ShieldAlert size={20} style={{ color: '#f43f5e' }} /> Incident Response & Reconstruction Portal
        </h2>
        <p style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>Correlated attack chains, Patient Zero identification, and remediation controls</p>
      </div>

      <div className="glass-panel" style={{ padding: '1.5rem', background: 'rgba(244,63,94,0.08)', border: '1px solid rgba(244,63,94,0.3)' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
          <div>
            <span className="badge badge-critical" style={{ marginBottom: '0.5rem' }}>CRITICAL INCIDENT #INC-8891</span>
            <h3 style={{ fontSize: '1.2rem', fontWeight: 800 }}>Account Takeover & Tor Exit Node Exploitation Sequence</h3>
          </div>
          <span className="font-mono" style={{ fontSize: '0.85rem', color: '#f43f5e', fontWeight: 700 }}>Blast Radius: 42%</span>
        </div>

        <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', marginBottom: '1rem' }}>
          Attacker utilized compromised SSO credentials from IP 185.220.101.45 (Tor Exit Node) to access HashiCorp Vault secrets. Automated RL defense invalidated session tokens at 11:20 AM.
        </p>

        <div style={{ display: 'flex', gap: '0.75rem' }}>
          <button className="btn-cyan" style={{ fontSize: '0.8rem', padding: '0.5rem 1rem' }}>
            View Reconstructed Attack Timeline
          </button>
          <button className="btn-social" style={{ fontSize: '0.8rem', padding: '0.5rem 1rem' }}>
            Export Forensics Log
          </button>
        </div>
      </div>
    </div>
  );
}
