import React from 'react';
import { 
  ShieldAlert, 
  Activity, 
  Share2, 
  Clock, 
  Zap, 
  Bot, 
  TrendingUp, 
  AlertOctagon, 
  Users, 
  Laptop, 
  Server, 
  Lock, 
  ArrowRight,
  CheckCircle2,
  FileSpreadsheet
} from 'lucide-react';

export default function DashboardOverview({ 
  riskScore, 
  threatSeverity, 
  threatVelocity, 
  evalResult, 
  telemetryLogs, 
  incidentData, 
  onNavigate,
  onOpenScenarioModal
}) {
  const getScoreColor = (score) => {
    if (score >= 75) return '#f43f5e';
    if (score >= 50) return '#f97316';
    if (score >= 25) return '#f59e0b';
    return '#10b981';
  };

  const scoreColor = getScoreColor(riskScore);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
      
      {/* Top Banner Alert if Critical */}
      {riskScore >= 60 && (
        <div style={{
          background: 'linear-gradient(90deg, rgba(244, 63, 94, 0.25) 0%, rgba(249, 115, 22, 0.15) 100%)',
          border: '1px solid rgba(244, 63, 94, 0.5)',
          borderRadius: '12px',
          padding: '1rem 1.5rem',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          boxShadow: '0 0 20px rgba(244, 63, 94, 0.2)'
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
            <AlertOctagon size={28} style={{ color: '#f43f5e' }} className="animate-pulse-glow" />
            <div>
              <h3 style={{ fontSize: '1rem', fontWeight: 700, color: '#f8fafc' }}>
                CRITICAL SECURITY INCIDENT IN PROGRESS
              </h3>
              <p style={{ fontSize: '0.85rem', color: '#cbd5e1' }}>
                Behavioral Anomaly Engine flagged multi-vector attack sequence. Blast Radius: {incidentData.blastRadiusScore}%
              </p>
            </div>
          </div>
          <div style={{ display: 'flex', gap: '0.5rem' }}>
            <button onClick={() => onNavigate('reconstruction')} className="btn-danger" style={{ fontSize: '0.8rem' }}>
              <Clock size={14} /> Reconstruct Incident
            </button>
            <button onClick={() => onNavigate('response')} className="btn-primary" style={{ fontSize: '0.8rem' }}>
              <Zap size={14} /> Execute RL Defense
            </button>
          </div>
        </div>
      )}

      {/* Main Grid: Left Risk Meter & Factors | Right Metrics & Stream */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(360px, 1fr))', gap: '1.5rem' }}>
        
        {/* Card 1: Dynamic Threat Risk Gauge */}
        <div className="glass-panel" style={{ padding: '1.5rem', display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
          <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
              <h2 style={{ fontSize: '1.1rem', fontWeight: 600, display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                <Activity size={18} style={{ color: 'var(--accent-cyan)' }} /> Evolving Threat Risk Score
              </h2>
              <span className="font-mono" style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>LIVE DL EVAL</span>
            </div>

            {/* Circular / Semi-gauge Display */}
            <div style={{ textAlign: 'center', padding: '1.5rem 0', position: 'relative' }}>
              <div style={{
                width: '180px',
                height: '180px',
                borderRadius: '50%',
                background: `radial-gradient(closest-side, var(--bg-primary) 79%, transparent 80% 100%), conic-gradient(${scoreColor} ${riskScore}%, rgba(255,255,255,0.06) 0)`,
                margin: '0 auto',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                boxShadow: `0 0 30px ${scoreColor}40`
              }}>
                <div style={{ textAlign: 'center' }}>
                  <div className="font-mono" style={{ fontSize: '2.75rem', fontWeight: 800, color: scoreColor }}>
                    {riskScore}
                  </div>
                  <div style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-secondary)', textTransform: 'uppercase' }}>
                    {threatSeverity} RISK
                  </div>
                </div>
              </div>

              {/* Threat Velocity Badge */}
              <div style={{ marginTop: '1rem', display: 'inline-flex', alignItems: 'center', gap: '0.4rem', background: 'rgba(0,0,0,0.3)', padding: '0.3rem 0.8rem', borderRadius: '20px', border: '1px solid var(--border-subtle)' }}>
                <TrendingUp size={14} style={{ color: threatVelocity > 0 ? '#f43f5e' : '#10b981' }} />
                <span style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
                  Velocity Surge: <strong style={{ color: threatVelocity > 0 ? '#f43f5e' : '#10b981' }}>{threatVelocity > 0 ? `+${threatVelocity}` : threatVelocity} pts/event</strong>
                </span>
              </div>
            </div>
          </div>

          {/* Anomaly Contributing Factors Breakdown */}
          <div style={{ borderTop: '1px solid var(--border-subtle)', paddingTop: '1rem', marginTop: '1rem' }}>
            <h4 style={{ fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-secondary)', textTransform: 'uppercase', marginBottom: '0.75rem' }}>
              ML Behavioral Anomaly Weights
            </h4>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
              {evalResult.contributingFactors.map((item, idx) => (
                <div key={idx} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: '0.8rem' }}>
                  <span style={{ color: 'var(--text-primary)', display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                    <span style={{ width: '6px', height: '6px', borderRadius: '50%', background: scoreColor }}></span>
                    {item.factor}
                  </span>
                  <span className="font-mono" style={{ color: 'var(--accent-cyan)', fontWeight: 600 }}>{item.weight}</span>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Card 2: Security Metrics Overview */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
          
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem' }}>
            <div className="glass-panel" style={{ padding: '1.2rem' }}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', color: 'var(--text-secondary)' }}>
                <span style={{ fontSize: '0.8rem' }}>Monitored Users</span>
                <Users size={18} style={{ color: 'var(--accent-blue)' }} />
              </div>
              <div className="font-mono" style={{ fontSize: '1.75rem', fontWeight: 700, marginTop: '0.5rem' }}>
                4 Active
              </div>
              <span style={{ fontSize: '0.75rem', color: '#34d399', display: 'flex', alignItems: 'center', gap: '0.2rem', marginTop: '0.25rem' }}>
                <CheckCircle2 size={12} /> 1 Compromised Account
              </span>
            </div>

            <div className="glass-panel" style={{ padding: '1.2rem' }}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', color: 'var(--text-secondary)' }}>
                <span style={{ fontSize: '0.8rem' }}>Device Fingerprints</span>
                <Laptop size={18} style={{ color: 'var(--accent-purple)' }} />
              </div>
              <div className="font-mono" style={{ fontSize: '1.75rem', fontWeight: 700, marginTop: '0.5rem' }}>
                5 Devices
              </div>
              <span style={{ fontSize: '0.75rem', color: '#f43f5e', display: 'flex', alignItems: 'center', gap: '0.2rem', marginTop: '0.25rem' }}>
                <AlertOctagon size={12} /> 1 Rogue Host Endpoint
              </span>
            </div>

            <div className="glass-panel" style={{ padding: '1.2rem' }}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', color: 'var(--text-secondary)' }}>
                <span style={{ fontSize: '0.8rem' }}>Critical Apps Monitored</span>
                <Server size={18} style={{ color: 'var(--accent-cyan)' }} />
              </div>
              <div className="font-mono" style={{ fontSize: '1.75rem', fontWeight: 700, marginTop: '0.5rem' }}>
                4 Services
              </div>
              <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '0.25rem', display: 'block' }}>
                K8s Gateway & Vault Active
              </span>
            </div>

            <div className="glass-panel" style={{ padding: '1.2rem' }}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', color: 'var(--text-secondary)' }}>
                <span style={{ fontSize: '0.8rem' }}>Blast Radius Index</span>
                <Lock size={18} style={{ color: 'var(--accent-amber)' }} />
              </div>
              <div className="font-mono" style={{ fontSize: '1.75rem', fontWeight: 700, marginTop: '0.5rem', color: incidentData.blastRadiusScore > 40 ? '#f43f5e' : 'var(--text-primary)' }}>
                {incidentData.blastRadiusScore || 0}%
              </div>
              <span style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', marginTop: '0.25rem', display: 'block' }}>
                {incidentData.affectedEntitiesCount || 0} entities correlated
              </span>
            </div>
          </div>

          {/* Incident Workbench Quick Launcher */}
          <div className="glass-panel" style={{ padding: '1.2rem', background: 'linear-gradient(135deg, rgba(24, 32, 53, 0.8) 0%, rgba(17, 22, 37, 0.9) 100%)' }}>
            <h3 style={{ fontSize: '0.95rem', fontWeight: 600, marginBottom: '0.5rem' }}>
              AI Incident Reconstruction Workbench
            </h3>
            <p style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', marginBottom: '1rem' }}>
              Correlate graph connections between users, devices, sessions, applications, and network IPs to identify Patient Zero root cause.
            </p>
            <div style={{ display: 'flex', gap: '0.75rem', flexWrap: 'wrap' }}>
              <button onClick={() => onNavigate('graph')} className="btn-primary" style={{ fontSize: '0.8rem' }}>
                <Share2 size={14} /> Knowledge Graph Visualizer
              </button>
              <button onClick={() => onNavigate('genai')} className="btn-secondary" style={{ fontSize: '0.8rem' }}>
                <Bot size={14} /> GenAI Incident Report
              </button>
            </div>
          </div>

        </div>
      </div>

      {/* Bottom Row: Telemetry Feed Preview & Attack Scenario Launcher */}
      <div className="glass-panel" style={{ padding: '1.5rem' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
          <div>
            <h3 style={{ fontSize: '1rem', fontWeight: 600 }}>Live Telemetry Activity Stream</h3>
            <p style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>Continuous real-time events ingested from authentication, devices, sessions, and network infrastructure</p>
          </div>
          <button onClick={() => onNavigate('telemetry')} className="btn-secondary" style={{ fontSize: '0.8rem' }}>
            View All Events Stream <ArrowRight size={14} />
          </button>
        </div>

        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.65rem' }}>
          {telemetryLogs.slice(0, 4).map((log) => (
            <div 
              key={log.id} 
              style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                padding: '0.75rem 1rem',
                background: 'rgba(0,0,0,0.25)',
                borderRadius: '8px',
                borderLeft: `4px solid ${log.severity === 'critical' ? '#f43f5e' : log.severity === 'high' ? '#f97316' : '#10b981'}`
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
                <span className="font-mono" style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>{log.timestamp}</span>
                <div>
                  <div style={{ fontSize: '0.85rem', fontWeight: 600, color: 'var(--text-primary)' }}>
                    [{log.type}] {log.user || 'Unknown'} - {log.details}
                  </div>
                  <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
                    IP: {log.ip} | App: {log.app} | Device: {log.device || 'N/A'}
                  </div>
                </div>
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
                <span className="font-mono" style={{ fontSize: '0.75rem', color: 'var(--accent-cyan)' }}>
                  Anomaly: {Math.round(log.anomalyScore * 100)}%
                </span>
                <span className={`badge badge-${log.severity}`}>{log.severity}</span>
              </div>
            </div>
          ))}
        </div>
      </div>

    </div>
  );
}
