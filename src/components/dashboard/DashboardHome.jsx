import React from 'react';
import { 
  ShieldCheck, 
  AlertTriangle, 
  ShieldAlert, 
  Laptop, 
  Bot, 
  TrendingUp, 
  Clock, 
  CheckCircle2, 
  AlertOctagon, 
  ExternalLink,
  ChevronRight
} from 'lucide-react';

import { 
  DASHBOARD_METRICS, 
  AI_SECURITY_SUMMARY, 
  THREAT_TREND_DATA, 
  REALTIME_ACTIVITIES, 
  RECENT_ALERTS 
} from '../../data/digitalGuardData';

export default function DashboardHome({ onNavigate }) {
  const { securityScore, activeAnomalies, criticalIncidents, connectedDevices, riskLevel } = DASHBOARD_METRICS;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
      
      {/* 4 Primary Security Overview Stat Cards */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: '1.25rem' }}>
        
        {/* Card 1: Security Score */}
        <div className="glass-panel" style={{ padding: '1.25rem', position: 'relative', overflow: 'hidden' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', color: 'var(--text-secondary)' }}>
            <span style={{ fontSize: '0.8rem', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.05em' }}>Security Score</span>
            <ShieldCheck size={20} style={{ color: 'var(--accent-cyan)' }} />
          </div>
          <div style={{ display: 'flex', alignItems: 'baseline', gap: '0.5rem', marginTop: '0.75rem' }}>
            <span className="font-mono" style={{ fontSize: '2.4rem', fontWeight: 800, color: 'var(--accent-cyan)' }}>
              {securityScore}
            </span>
            <span style={{ fontSize: '0.9rem', color: 'var(--text-muted)' }}>/ 100</span>
          </div>
          <div style={{ fontSize: '0.75rem', color: '#10b981', display: 'flex', alignItems: 'center', gap: '0.3rem', marginTop: '0.35rem' }}>
            <CheckCircle2 size={13} /> {DASHBOARD_METRICS.securityScoreStatus}
          </div>
        </div>

        {/* Card 2: Active Anomalies */}
        <div className="glass-panel" style={{ padding: '1.25rem' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', color: 'var(--text-secondary)' }}>
            <span style={{ fontSize: '0.8rem', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.05em' }}>Active Anomalies</span>
            <AlertTriangle size={20} style={{ color: '#f59e0b' }} />
          </div>
          <div style={{ display: 'flex', alignItems: 'baseline', gap: '0.5rem', marginTop: '0.75rem' }}>
            <span className="font-mono" style={{ fontSize: '2.4rem', fontWeight: 800, color: '#f59e0b' }}>
              {activeAnomalies}
            </span>
            <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>Flagged Events</span>
          </div>
          <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', marginTop: '0.35rem' }}>
            Last 24 Hours Detection
          </div>
        </div>

        {/* Card 3: Critical Incidents */}
        <div className="glass-panel" style={{ padding: '1.25rem' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', color: 'var(--text-secondary)' }}>
            <span style={{ fontSize: '0.8rem', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.05em' }}>Critical Incidents</span>
            <ShieldAlert size={20} style={{ color: '#f43f5e' }} />
          </div>
          <div style={{ display: 'flex', alignItems: 'baseline', gap: '0.5rem', marginTop: '0.75rem' }}>
            <span className="font-mono" style={{ fontSize: '2.4rem', fontWeight: 800, color: '#f43f5e' }}>
              {criticalIncidents}
            </span>
            <span style={{ fontSize: '0.8rem', color: '#f43f5e', fontWeight: 600 }}>Action Required</span>
          </div>
          <div style={{ fontSize: '0.75rem', color: '#f43f5e', marginTop: '0.35rem' }}>
            Tor Exit Anomaly Blocked
          </div>
        </div>

        {/* Card 4: Connected Devices */}
        <div className="glass-panel" style={{ padding: '1.25rem' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', color: 'var(--text-secondary)' }}>
            <span style={{ fontSize: '0.8rem', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.05em' }}>Connected Devices</span>
            <Laptop size={20} style={{ color: 'var(--accent-blue)' }} />
          </div>
          <div style={{ display: 'flex', alignItems: 'baseline', gap: '0.5rem', marginTop: '0.75rem' }}>
            <span className="font-mono" style={{ fontSize: '2.4rem', fontWeight: 800, color: 'var(--text-primary)' }}>
              {connectedDevices}
            </span>
            <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>Endpoints</span>
          </div>
          <div style={{ fontSize: '0.75rem', color: '#10b981', marginTop: '0.35rem' }}>
            13 Protected • 1 Flagged
          </div>
        </div>

      </div>

      {/* AI Security Summary Card */}
      <div className="glass-panel" style={{ padding: '1.5rem', background: 'linear-gradient(135deg, rgba(15, 20, 32, 0.9) 0%, rgba(7, 9, 14, 0.95) 100%)', border: '1px solid var(--border-glow)' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.85rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
            <div style={{ padding: '0.4rem', borderRadius: '8px', background: 'rgba(0, 240, 255, 0.15)', color: 'var(--accent-cyan)' }}>
              <Bot size={20} />
            </div>
            <div>
              <h3 style={{ fontSize: '1.05rem', fontWeight: 700, color: 'var(--text-primary)' }}>
                AI Security Summary
              </h3>
              <span style={{ fontSize: '0.75rem', color: 'var(--accent-cyan)', fontWeight: 600 }}>
                {AI_SECURITY_SUMMARY.status}
              </span>
            </div>
          </div>

          <button onClick={() => onNavigate('ai-analyst')} className="btn-social" style={{ fontSize: '0.8rem', padding: '0.4rem 0.85rem' }}>
            Ask AI Analyst <ChevronRight size={14} />
          </button>
        </div>

        <p style={{ fontSize: '0.875rem', color: 'var(--text-secondary)', lineHeight: '1.6', marginBottom: '1rem' }}>
          {AI_SECURITY_SUMMARY.summaryText}
        </p>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))', gap: '0.6rem' }}>
          {AI_SECURITY_SUMMARY.keyInsights.map((insight, idx) => (
            <div key={idx} style={{ background: 'rgba(0,0,0,0.25)', padding: '0.6rem 0.85rem', borderRadius: '8px', border: '1px solid var(--border-subtle)', fontSize: '0.8rem', display: 'flex', alignItems: 'center', gap: '0.5rem', color: 'var(--text-primary)' }}>
              <span style={{ width: '6px', height: '6px', borderRadius: '50%', background: 'var(--accent-cyan)' }}></span>
              {insight}
            </div>
          ))}
        </div>
      </div>

      {/* Main Split: Threat Trend Chart & Recent Alerts */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(360px, 1fr))', gap: '1.5rem' }}>
        
        {/* Threat Trend Chart */}
        <div className="glass-panel" style={{ padding: '1.5rem', display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
            <div>
              <h3 style={{ fontSize: '1rem', fontWeight: 700, display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                <TrendingUp size={18} style={{ color: 'var(--accent-cyan)' }} /> Threat Trend (Risk Over Time)
              </h3>
              <p style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>24-hour threat velocity surge monitoring</p>
            </div>
            <span className="font-mono" style={{ fontSize: '0.75rem', color: 'var(--accent-cyan)', background: 'rgba(0,240,255,0.1)', padding: '0.2rem 0.6rem', borderRadius: '6px' }}>
              Peak Risk: 78%
            </span>
          </div>

          {/* Simple Visual SVG Sparkline Chart */}
          <div style={{ width: '100%', height: '180px', position: 'relative', marginTop: '1rem' }}>
            <svg style={{ width: '100%', height: '100%', overflow: 'visible' }}>
              <defs>
                <linearGradient id="riskGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="#00f0ff" stopOpacity="0.35" />
                  <stop offset="100%" stopColor="#00f0ff" stopOpacity="0" />
                </linearGradient>
              </defs>
              
              {/* Area path */}
              <path
                d="M 10 140 Q 80 145 150 135 T 290 30 T 420 80 T 550 120 L 550 170 L 10 170 Z"
                fill="url(#riskGrad)"
              />
              
              {/* Line path */}
              <path
                d="M 10 140 Q 80 145 150 135 T 290 30 T 420 80 T 550 120"
                fill="none"
                stroke="var(--accent-cyan)"
                strokeWidth="3"
              />

              {/* Peak Point Alert Marker */}
              <circle cx="290" cy="30" r="6" fill="#f43f5e" />
              <text x="290" y="15" textAnchor="middle" fill="#f43f5e" fontSize="10" fontWeight="700">Tor Anomaly (78%)</text>
            </svg>

            {/* Time X-Axis */}
            <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.7rem', color: 'var(--text-muted)', marginTop: '0.5rem' }} className="font-mono">
              {THREAT_TREND_DATA.map((d, i) => (
                <span key={i}>{d.time}</span>
              ))}
            </div>
          </div>
        </div>

        {/* Recent Alerts Section */}
        <div className="glass-panel" style={{ padding: '1.5rem', display: 'flex', flexDirection: 'column', gap: '1rem' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <h3 style={{ fontSize: '1rem', fontWeight: 700, display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <AlertTriangle size={18} style={{ color: '#f59e0b' }} /> Recent Security Alerts
            </h3>
            <button onClick={() => onNavigate('anomalies')} style={{ background: 'none', border: 'none', color: 'var(--accent-cyan)', fontSize: '0.8rem', fontWeight: 600, cursor: 'pointer' }}>
              View All
            </button>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.65rem' }}>
            {RECENT_ALERTS.map((alert) => (
              <div 
                key={alert.id}
                style={{
                  background: 'rgba(0,0,0,0.25)',
                  padding: '0.85rem',
                  borderRadius: '10px',
                  borderLeft: `4px solid ${alert.severity === 'critical' ? '#f43f5e' : alert.severity === 'high' ? '#f97316' : alert.severity === 'medium' ? '#f59e0b' : '#10b981'}`,
                  display: 'flex',
                  justify: 'space-between',
                  alignItems: 'flex-start',
                  gap: '0.75rem'
                }}
              >
                <div>
                  <div style={{ fontSize: '0.85rem', fontWeight: 700, color: 'var(--text-primary)' }}>
                    {alert.title}
                  </div>
                  <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', marginTop: '0.2rem' }}>
                    {alert.description}
                  </div>
                </div>
                <div style={{ textAlign: 'right', whiteSpace: 'nowrap' }}>
                  <span className={`badge badge-${alert.severity}`}>{alert.severity}</span>
                  <div className="font-mono" style={{ fontSize: '0.7rem', color: 'var(--text-muted)', marginTop: '0.3rem' }}>
                    {alert.timestamp}
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>

      </div>

      {/* Real-Time Activity Section Table */}
      <div className="glass-panel" style={{ padding: '1.5rem' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
          <div>
            <h3 style={{ fontSize: '1rem', fontWeight: 700, display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <Clock size={18} style={{ color: 'var(--accent-cyan)' }} /> Real-Time Activity Log
            </h3>
            <p style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>Continuous stream across connected endpoints & network services</p>
          </div>
          <button onClick={() => onNavigate('activities')} className="btn-social" style={{ fontSize: '0.8rem', padding: '0.4rem 0.85rem' }}>
            Full Logs Stream <ChevronRight size={14} />
          </button>
        </div>

        <div style={{ overflowX: 'auto' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '0.85rem' }}>
            <thead>
              <tr style={{ background: 'rgba(0,0,0,0.3)', borderBottom: '1px solid var(--border-subtle)', color: 'var(--text-muted)', fontSize: '0.75rem', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                <th style={{ padding: '0.85rem 1rem' }}>Timestamp</th>
                <th style={{ padding: '0.85rem 1rem' }}>Activity</th>
                <th style={{ padding: '0.85rem 1rem' }}>Device</th>
                <th style={{ padding: '0.85rem 1rem' }}>Source</th>
                <th style={{ padding: '0.85rem 1rem' }}>Risk Score</th>
                <th style={{ padding: '0.85rem 1rem' }}>Status</th>
              </tr>
            </thead>
            <tbody>
              {REALTIME_ACTIVITIES.map((act) => (
                <tr key={act.id} style={{ borderBottom: '1px solid rgba(255,255,255,0.05)' }}>
                  <td className="font-mono" style={{ padding: '0.85rem 1rem', color: 'var(--text-muted)' }}>{act.timestamp}</td>
                  <td style={{ padding: '0.85rem 1rem', fontWeight: 600, color: 'var(--text-primary)' }}>{act.activity}</td>
                  <td style={{ padding: '0.85rem 1rem', color: 'var(--text-secondary)' }}>{act.device}</td>
                  <td className="font-mono" style={{ padding: '0.85rem 1rem', color: act.source.includes('Tor') ? '#f43f5e' : 'var(--text-secondary)' }}>{act.source}</td>
                  <td className="font-mono" style={{ padding: '0.85rem 1rem', fontWeight: 700, color: parseInt(act.risk) > 60 ? '#f43f5e' : parseInt(act.risk) > 20 ? '#f59e0b' : '#10b981' }}>
                    {act.risk}
                  </td>
                  <td style={{ padding: '0.85rem 1rem' }}>
                    <span className={`badge ${act.status === 'Blocked' ? 'badge-critical' : act.status === 'Flagged' ? 'badge-high' : 'badge-low'}`}>
                      {act.status}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

    </div>
  );
}
