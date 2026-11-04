import React from 'react';
import { 
  Zap, 
  ShieldAlert, 
  CheckCircle2, 
  Sliders, 
  Laptop, 
  Globe, 
  UserX, 
  FileCode, 
  Clock, 
  TrendingDown 
} from 'lucide-react';

export default function AdaptiveResponseView({ 
  recommendations, 
  onExecuteAction, 
  executedHistory, 
  isAutoPilot, 
  setIsAutoPilot,
  riskScore 
}) {
  const getActionIcon = (id) => {
    switch (id) {
      case 'act_kill_session': return <UserX size={18} />;
      case 'act_block_ip': return <Globe size={18} />;
      case 'act_isolate_device': return <Laptop size={18} />;
      case 'act_quarantine_process': return <FileCode size={18} />;
      default: return <ShieldAlert size={18} />;
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
      
      {/* Header Info */}
      <div className="glass-panel" style={{ padding: '1.25rem', display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '1rem' }}>
        <div>
          <h2 style={{ fontSize: '1.1rem', fontWeight: 600, display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <Zap size={20} style={{ color: 'var(--accent-cyan)' }} /> Reinforcement Learning Adaptive Security Response
          </h2>
          <p style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
            Q-Learning policy matrix evaluates optimal defense mitigations balancing risk reduction vs operational user friction.
          </p>
        </div>

        {/* Auto Pilot Toggle */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
          <span style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>RL Auto-Mitigation Engine:</span>
          <button 
            onClick={() => setIsAutoPilot(!isAutoPilot)}
            className={isAutoPilot ? 'btn-primary' : 'btn-secondary'}
            style={{ fontSize: '0.8rem' }}
          >
            <Sliders size={14} /> AUTO-PILOT: {isAutoPilot ? 'ENABLED' : 'MANUAL MODE'}
          </button>
        </div>
      </div>

      {/* Main Grid: Policy Recommendations | Action History */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(360px, 1fr))', gap: '1.5rem' }}>
        
        {/* Left Column: Optimal RL Recommendations */}
        <div className="glass-panel" style={{ padding: '1.5rem', display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <h3 style={{ fontSize: '1rem', fontWeight: 600, display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <ShieldAlert size={18} style={{ color: 'var(--accent-cyan)' }} /> Active Policy Recommendations
            </h3>
            <span className="font-mono" style={{ fontSize: '0.75rem', color: 'var(--accent-cyan)' }}>
              Current Threat: {riskScore}/100
            </span>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
            {recommendations.map((action) => (
              <div 
                key={action.id}
                style={{
                  background: 'rgba(0,0,0,0.3)',
                  borderRadius: '10px',
                  padding: '1.1rem',
                  border: action.status.includes('CRITICAL') ? '1px solid rgba(244, 63, 94, 0.5)' : '1px solid var(--border-subtle)',
                  display: 'flex',
                  flexDirection: 'column',
                  gap: '0.75rem'
                }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
                    <div style={{
                      padding: '0.4rem',
                      borderRadius: '6px',
                      background: 'rgba(0, 240, 255, 0.1)',
                      color: 'var(--accent-cyan)'
                    }}>
                      {getActionIcon(action.id)}
                    </div>
                    <span style={{ fontSize: '0.95rem', fontWeight: 700, color: 'var(--text-primary)' }}>
                      {action.name}
                    </span>
                  </div>
                  <span className="font-mono" style={{ fontSize: '0.75rem', color: '#10b981', fontWeight: 700 }}>
                    Q-Value: {action.qValue}
                  </span>
                </div>

                <p style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
                  {action.description}
                </p>

                {/* Reasoning & Metrics */}
                <div style={{ background: 'rgba(255,255,255,0.02)', padding: '0.65rem', borderRadius: '6px', fontSize: '0.75rem', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <span style={{ color: 'var(--text-muted)' }}>RL Strategy Reasoning:</span>
                  <span style={{ color: 'var(--accent-cyan)', fontWeight: 500 }}>{action.reasoning}</span>
                </div>

                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: '0.75rem' }}>
                  <div style={{ display: 'flex', gap: '1rem' }}>
                    <span style={{ color: '#10b981', display: 'flex', alignItems: 'center', gap: '0.2rem' }}>
                      <TrendingDown size={12} /> Risk Drop: -{action.riskReduction} pts
                    </span>
                    <span style={{ color: 'var(--text-muted)' }}>
                      User Friction Cost: {action.userFriction}/100
                    </span>
                  </div>

                  <button 
                    onClick={() => onExecuteAction(action)}
                    className={action.status.includes('CRITICAL') ? 'btn-danger' : 'btn-primary'}
                    style={{ fontSize: '0.75rem', padding: '0.35rem 0.85rem' }}
                  >
                    Execute Defense Action
                  </button>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Right Column: Execution Audit Log */}
        <div className="glass-panel" style={{ padding: '1.5rem', display: 'flex', flexDirection: 'column', gap: '1rem' }}>
          <h3 style={{ fontSize: '1rem', fontWeight: 600, display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <Clock size={18} style={{ color: 'var(--accent-cyan)' }} /> Defense Execution Audit Trail
          </h3>

          {executedHistory.length === 0 ? (
            <div style={{ padding: '2rem', textAlign: 'center', color: 'var(--text-muted)', fontSize: '0.85rem' }}>
              No automated or manual actions executed yet. Select a recommended action above to deploy defense mitigations.
            </div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
              {executedHistory.map((rec) => (
                <div key={rec.id} style={{ background: 'rgba(0,0,0,0.25)', padding: '0.85rem', borderRadius: '8px', borderLeft: '4px solid #10b981', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <div>
                    <div style={{ fontSize: '0.85rem', fontWeight: 600, color: 'var(--text-primary)', display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                      <CheckCircle2 size={14} style={{ color: '#10b981' }} /> {rec.actionName}
                    </div>
                    <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', marginTop: '0.2rem' }}>
                      Target: {rec.targetEntity} | Executor: <strong>{rec.executor}</strong>
                    </div>
                  </div>
                  <div style={{ textAlign: 'right' }}>
                    <div className="font-mono" style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>{rec.timestamp}</div>
                    <span className="badge badge-low" style={{ fontSize: '0.65rem', marginTop: '0.2rem' }}>-{rec.riskReduction} PTS RISK</span>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

      </div>

    </div>
  );
}
