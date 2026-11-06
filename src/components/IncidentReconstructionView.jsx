import React, { useState } from 'react';
import { 
  Clock, 
  AlertOctagon, 
  Share2, 
  ChevronRight, 
  Play, 
  RotateCcw, 
  ShieldAlert, 
  Layers, 
  Server, 
  User, 
  Globe 
} from 'lucide-react';

export default function IncidentReconstructionView({ incidentData, telemetryLogs }) {
  const [timelineIndex, setTimelineIndex] = useState(telemetryLogs.length - 1);
  const patientZero = incidentData.patientZero;

  const currentStep = telemetryLogs[timelineIndex] || telemetryLogs[0];

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
      
      {/* Header Info */}
      <div className="glass-panel" style={{ padding: '1.25rem', display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '1rem' }}>
        <div>
          <h2 style={{ fontSize: '1.1rem', fontWeight: 600, display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <Clock size={20} style={{ color: 'var(--accent-cyan)' }} /> Incident Reconstruction & Timeline Playback
          </h2>
          <p style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
            Trace security evidence back to Patient Zero, reconstruct incident sequence, and map blast radius across assets.
          </p>
        </div>

        <div style={{ display: 'flex', gap: '0.5rem' }}>
          <button 
            onClick={() => setTimelineIndex(0)} 
            className="btn-secondary" 
            style={{ fontSize: '0.8rem' }}
          >
            <RotateCcw size={14} /> Reset to Patient Zero
          </button>
          <button 
            onClick={() => setTimelineIndex(Math.min(telemetryLogs.length - 1, timelineIndex + 1))} 
            className="btn-primary" 
            style={{ fontSize: '0.8rem' }}
          >
            <ChevronRight size={14} /> Step Forward
          </button>
        </div>
      </div>

      {/* Patient Zero Root Cause Spotlight Banner */}
      {patientZero && (
        <div style={{
          background: 'linear-gradient(135deg, rgba(244, 63, 94, 0.15) 0%, rgba(249, 115, 22, 0.1) 100%)',
          border: '1px solid rgba(244, 63, 94, 0.4)',
          borderRadius: '12px',
          padding: '1.25rem',
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))',
          gap: '1rem'
        }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', color: '#f43f5e', fontSize: '0.8rem', fontWeight: 700, textTransform: 'uppercase', marginBottom: '0.25rem' }}>
              <AlertOctagon size={16} /> PATIENT ZERO (Earliest Anomaly)
            </div>
            <div style={{ fontSize: '1.1rem', fontWeight: 700, color: 'var(--text-primary)' }}>
              {patientZero.details}
            </div>
            <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', marginTop: '0.25rem' }}>
              First Flagged Timestamp: <span className="font-mono" style={{ color: 'var(--accent-cyan)' }}>{patientZero.timestamp}</span>
            </div>
          </div>

          <div>
            <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Target Account:</div>
            <div style={{ fontSize: '0.9rem', fontWeight: 600 }}>{patientZero.user || 'usr_1 (Sarah Connor)'}</div>
            <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '0.5rem' }}>Attack Vector:</div>
            <div style={{ fontSize: '0.85rem', color: 'var(--accent-amber)', fontWeight: 600 }}>{patientZero.type}</div>
          </div>

          <div>
            <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Origin IP Address:</div>
            <div className="font-mono" style={{ fontSize: '0.9rem', color: '#f43f5e', fontWeight: 700 }}>{patientZero.ip}</div>
            <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>Location: {patientZero.location}</div>
          </div>

          <div>
            <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Anomaly Confidence:</div>
            <div className="font-mono" style={{ fontSize: '1.4rem', fontWeight: 800, color: '#f43f5e' }}>
              {Math.round(patientZero.anomalyScore * 100)}%
            </div>
            <span className="badge badge-critical">HIGH CONFIDENCE</span>
          </div>
        </div>
      )}

      {/* Interactive Timeline Scrubber Slider */}
      <div className="glass-panel" style={{ padding: '1.5rem' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
          <h3 style={{ fontSize: '0.95rem', fontWeight: 600 }}>Incident Timeline Playback Control</h3>
          <span className="font-mono" style={{ fontSize: '0.85rem', color: 'var(--accent-cyan)' }}>
            Step {timelineIndex + 1} of {telemetryLogs.length}
          </span>
        </div>

        <input
          type="range"
          min={0}
          max={telemetryLogs.length - 1}
          value={timelineIndex}
          onChange={(e) => setTimelineIndex(parseInt(e.target.value))}
          style={{
            width: '100%',
            height: '8px',
            borderRadius: '4px',
            background: 'linear-gradient(90deg, #10b981 0%, #f59e0b 50%, #f43f5e 100%)',
            outline: 'none',
            cursor: 'pointer'
          }}
        />

        {/* Selected Timeline Step Card */}
        {currentStep && (
          <div style={{ marginTop: '1.25rem', background: 'rgba(0,0,0,0.3)', padding: '1rem', borderRadius: '8px', border: '1px solid var(--border-glow)' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.5rem' }}>
              <span className="font-mono" style={{ fontSize: '0.85rem', color: 'var(--accent-cyan)', fontWeight: 700 }}>
                [{currentStep.timestamp}] {currentStep.type}
              </span>
              <span className={`badge badge-${currentStep.severity}`}>{currentStep.severity}</span>
            </div>
            <p style={{ fontSize: '0.9rem', color: 'var(--text-primary)', marginBottom: '0.5rem' }}>
              {currentStep.details}
            </p>
            <div style={{ display: 'flex', gap: '1.5rem', fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
              <span>User: <strong style={{ color: 'var(--text-primary)' }}>{currentStep.user || 'N/A'}</strong></span>
              <span>IP: <strong className="font-mono" style={{ color: 'var(--text-primary)' }}>{currentStep.ip}</strong></span>
              <span>App: <strong style={{ color: 'var(--text-primary)' }}>{currentStep.app || 'N/A'}</strong></span>
            </div>
          </div>
        )}
      </div>

      {/* Sequential Attack Propagation Chain */}
      <div className="glass-panel" style={{ padding: '1.5rem' }}>
        <h3 style={{ fontSize: '1rem', fontWeight: 600, marginBottom: '1rem' }}>
          Reconstructed Sequential Attack Vector Chain
        </h3>

        <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
          {telemetryLogs.map((evt, idx) => (
            <div 
              key={evt.id} 
              onClick={() => setTimelineIndex(idx)}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '1rem',
                padding: '1rem',
                borderRadius: '8px',
                background: idx === timelineIndex ? 'rgba(0, 240, 255, 0.1)' : 'rgba(255,255,255,0.02)',
                border: idx === timelineIndex ? '1px solid var(--accent-cyan)' : '1px solid var(--border-subtle)',
                cursor: 'pointer',
                transition: 'all 0.2s ease'
              }}
            >
              <div className="font-mono" style={{
                width: '32px',
                height: '32px',
                borderRadius: '50%',
                background: evt.severity === 'critical' ? 'rgba(244, 63, 94, 0.2)' : 'rgba(0, 240, 255, 0.1)',
                border: `1px solid ${evt.severity === 'critical' ? '#f43f5e' : 'var(--accent-cyan)'}`,
                color: evt.severity === 'critical' ? '#f43f5e' : 'var(--accent-cyan)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                fontWeight: 700,
                fontSize: '0.85rem'
              }}>
                {idx + 1}
              </div>

              <div style={{ flex: 1 }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <div style={{ fontSize: '0.9rem', fontWeight: 600, color: 'var(--text-primary)' }}>
                    {evt.details}
                  </div>
                  <span className="font-mono" style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>{evt.timestamp}</span>
                </div>
                <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', marginTop: '0.25rem' }}>
                  Event Type: <strong className="font-mono">{evt.type}</strong> | IP: <span className="font-mono">{evt.ip}</span> | User: {evt.user || 'N/A'}
                </div>
              </div>

              <span className={`badge badge-${evt.severity}`}>{evt.severity}</span>
            </div>
          ))}
        </div>
      </div>

    </div>
  );
}
