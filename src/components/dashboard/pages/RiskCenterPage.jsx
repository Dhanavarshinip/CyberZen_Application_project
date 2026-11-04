import React from 'react';
import { TrendingUp, ShieldCheck, AlertTriangle } from 'lucide-react';
import { DASHBOARD_METRICS } from '../../../data/digitalGuardData';

export default function RiskCenterPage() {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
      <div className="glass-panel" style={{ padding: '1.25rem' }}>
        <h2 style={{ fontSize: '1.15rem', fontWeight: 700, display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <TrendingUp size={20} style={{ color: 'var(--accent-cyan)' }} /> Risk Center & Threat Velocity Scoring
        </h2>
        <p style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>Evolving threat risk score profiles and asset vulnerability analysis</p>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '1.25rem' }}>
        <div className="glass-panel" style={{ padding: '1.5rem', textAlign: 'center' }}>
          <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', uppercase: true }}>Current Evolving Risk</div>
          <div className="font-mono" style={{ fontSize: '3rem', fontWeight: 800, color: 'var(--accent-cyan)', margin: '0.5rem 0' }}>
            24 / 100
          </div>
          <span className="badge badge-low">LOW RISK BASELINE</span>
        </div>

        <div className="glass-panel" style={{ padding: '1.5rem', textAlign: 'center' }}>
          <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>Threat Risk Velocity</div>
          <div className="font-mono" style={{ fontSize: '3rem', fontWeight: 800, color: '#10b981', margin: '0.5rem 0' }}>
            -18 pts/hr
          </div>
          <span className="badge badge-low">RISK RECOVERING</span>
        </div>
      </div>
    </div>
  );
}
