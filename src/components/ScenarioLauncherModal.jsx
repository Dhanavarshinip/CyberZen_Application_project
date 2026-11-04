import React from 'react';
import { 
  ShieldAlert, 
  Play, 
  X, 
  AlertTriangle, 
  Zap, 
  Server, 
  UserCheck 
} from 'lucide-react';
import { ATTACK_SCENARIOS } from '../data/mockData';

export default function ScenarioLauncherModal({ isOpen, onClose, onLaunchScenario }) {
  if (!isOpen) return null;

  return (
    <div style={{
      position: 'fixed',
      top: 0, left: 0, right: 0, bottom: 0,
      background: 'rgba(5, 11, 20, 0.85)',
      backdropFilter: 'blur(10px)',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      zIndex: 2000,
      padding: '1rem'
    }}>
      <div className="glass-panel" style={{ width: '100%', maxWidth: '640px', padding: '1.75rem', display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
        
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
            <ShieldAlert size={22} style={{ color: '#f43f5e' }} className="animate-pulse-glow" />
            <div>
              <h3 style={{ fontSize: '1.15rem', fontWeight: 700 }}>Attack Vector Scenario Launcher</h3>
              <p style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>Inject multi-stage real-world threat sequences to test real-time ML detection and RL defense</p>
            </div>
          </div>
          <button onClick={onClose} style={{ background: 'none', border: 'none', color: 'var(--text-muted)', cursor: 'pointer', fontSize: '1.5rem' }}>
            <X size={20} />
          </button>
        </div>

        <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
          {ATTACK_SCENARIOS.map((scenario) => (
            <div 
              key={scenario.id}
              style={{
                background: 'rgba(0,0,0,0.3)',
                borderRadius: '10px',
                padding: '1.2rem',
                border: '1px solid var(--border-subtle)',
                display: 'flex',
                justify: 'space-between',
                alignItems: 'center',
                gap: '1rem',
                transition: 'border 0.2s ease'
              }}
            >
              <div style={{ flex: 1 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.25rem' }}>
                  <span style={{ fontSize: '0.95rem', fontWeight: 700, color: 'var(--text-primary)' }}>
                    {scenario.title}
                  </span>
                  <span className="badge badge-critical" style={{ fontSize: '0.65rem' }}>{scenario.difficulty}</span>
                </div>
                <p style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
                  {scenario.description}
                </p>
                <div style={{ fontSize: '0.75rem', color: 'var(--accent-cyan)', marginTop: '0.4rem', fontWeight: 600 }}>
                  Payload Events: {scenario.events.length} multi-stage steps
                </div>
              </div>

              <button 
                onClick={() => {
                  onLaunchScenario(scenario);
                  onClose();
                }}
                className="btn-danger"
                style={{ fontSize: '0.8rem', whiteSpace: 'nowrap' }}
              >
                <Play size={14} /> Inject Scenario
              </button>
            </div>
          ))}
        </div>

        <div style={{ marginTop: '0.5rem', display: 'flex', justifyContent: 'flex-end' }}>
          <button onClick={onClose} className="btn-secondary" style={{ fontSize: '0.85rem' }}>
            Cancel
          </button>
        </div>

      </div>
    </div>
  );
}
