import React, { useState } from 'react';
import { 
  Radio, 
  Play, 
  Pause, 
  Search, 
  Filter, 
  ShieldAlert, 
  Download, 
  Eye, 
  Server, 
  User, 
  Laptop, 
  Globe 
} from 'lucide-react';

export default function LiveTelemetryView({ 
  telemetryLogs, 
  isStreaming, 
  setIsStreaming, 
  onInjectSimulatedEvent,
  onOpenScenarioModal 
}) {
  const [filterType, setFilterType] = useState('ALL');
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedEvent, setSelectedEvent] = useState(null);

  const filteredLogs = telemetryLogs.filter(log => {
    const matchesFilter = filterType === 'ALL' || 
      (filterType === 'CRITICAL' && (log.severity === 'critical' || log.severity === 'high')) ||
      (filterType === 'LOGIN' && log.type.includes('LOGIN')) ||
      (filterType === 'NETWORK' && log.type.includes('NETWORK')) ||
      (filterType === 'API' && (log.type.includes('API') || log.type.includes('EXFIL')));
    
    const queryLower = searchQuery.toLowerCase();
    const matchesSearch = !searchQuery || 
      log.details.toLowerCase().includes(queryLower) ||
      (log.user && log.user.toLowerCase().includes(queryLower)) ||
      log.ip.toLowerCase().includes(queryLower) ||
      log.type.toLowerCase().includes(queryLower);

    return matchesFilter && matchesSearch;
  });

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
      
      {/* Stream Controls Header */}
      <div className="glass-panel" style={{ padding: '1.25rem', display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '1rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
          <div style={{
            width: '12px',
            height: '12px',
            borderRadius: '50%',
            background: isStreaming ? '#10b981' : '#f43f5e',
            boxShadow: isStreaming ? '0 0 10px #10b981' : 'none'
          }}></div>
          <div>
            <h2 style={{ fontSize: '1.1rem', fontWeight: 600, display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <Radio size={20} style={{ color: 'var(--accent-cyan)' }} /> Real-Time Telemetry Stream
            </h2>
            <p style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
              Monitoring logins, devices, active sessions, API invocations, and network transactions ({telemetryLogs.length} total events captured)
            </p>
          </div>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
          <button 
            onClick={() => setIsStreaming(!isStreaming)} 
            className="btn-secondary"
            style={{ fontSize: '0.85rem' }}
          >
            {isStreaming ? <><Pause size={14} /> Pause Stream</> : <><Play size={14} /> Resume Stream</>}
          </button>

          <button onClick={onInjectSimulatedEvent} className="btn-secondary" style={{ fontSize: '0.85rem' }}>
            + Inject Single Event
          </button>

          <button onClick={onOpenScenarioModal} className="btn-danger" style={{ fontSize: '0.85rem' }}>
            <ShieldAlert size={14} /> Attack Scenarios
          </button>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '1rem' }}>
        <div style={{ display: 'flex', gap: '0.4rem', background: 'rgba(0,0,0,0.25)', padding: '0.3rem', borderRadius: '8px', border: '1px solid var(--border-subtle)' }}>
          {['ALL', 'CRITICAL', 'LOGIN', 'NETWORK', 'API'].map(type => (
            <button
              key={type}
              onClick={() => setFilterType(type)}
              style={{
                padding: '0.35rem 0.8rem',
                fontSize: '0.8rem',
                borderRadius: '6px',
                border: 'none',
                cursor: 'pointer',
                background: filterType === type ? 'var(--accent-cyan)' : 'transparent',
                color: filterType === type ? '#050b14' : 'var(--text-secondary)',
                fontWeight: filterType === type ? 700 : 500
              }}
            >
              {type}
            </button>
          ))}
        </div>

        {/* Search Input */}
        <div style={{ position: 'relative', minWidth: '280px' }}>
          <Search size={16} style={{ position: 'absolute', left: '12px', top: '50%', transform: 'translateY(-50%)', color: 'var(--text-muted)' }} />
          <input
            type="text"
            placeholder="Search by IP, User, Event Type, Payload..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            style={{
              width: '100%',
              padding: '0.5rem 0.75rem 0.5rem 2.2rem',
              borderRadius: '8px',
              border: '1px solid var(--border-subtle)',
              background: 'rgba(17, 22, 37, 0.8)',
              color: 'var(--text-primary)',
              fontSize: '0.85rem',
              outline: 'none'
            }}
          />
        </div>
      </div>

      {/* Main Telemetry Table */}
      <div className="glass-panel" style={{ padding: '0', overflow: 'hidden' }}>
        <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '0.85rem' }}>
          <thead>
            <tr style={{ background: 'rgba(0,0,0,0.3)', borderBottom: '1px solid var(--border-subtle)', color: 'var(--text-secondary)' }}>
              <th style={{ padding: '0.85rem 1rem' }}>Timestamp</th>
              <th style={{ padding: '0.85rem 1rem' }}>Type</th>
              <th style={{ padding: '0.85rem 1rem' }}>User / Device</th>
              <th style={{ padding: '0.85rem 1rem' }}>IP & Location</th>
              <th style={{ padding: '0.85rem 1rem' }}>Details & Payload</th>
              <th style={{ padding: '0.85rem 1rem' }}>ML Anomaly</th>
              <th style={{ padding: '0.85rem 1rem' }}>Severity</th>
              <th style={{ padding: '0.85rem 1rem', textAlign: 'center' }}>Inspect</th>
            </tr>
          </thead>
          <tbody>
            {filteredLogs.map(log => (
              <tr key={log.id} style={{ borderBottom: '1px solid rgba(255,255,255,0.05)', transition: 'background 0.2s ease' }} className="table-row-hover">
                <td className="font-mono" style={{ padding: '0.85rem 1rem', color: 'var(--text-muted)' }}>{log.timestamp}</td>
                <td style={{ padding: '0.85rem 1rem', fontWeight: 600 }}>{log.type}</td>
                <td style={{ padding: '0.85rem 1rem' }}>
                  <div style={{ color: 'var(--text-primary)', fontWeight: 500 }}>{log.user || 'N/A'}</div>
                  <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>{log.device || 'N/A'}</div>
                </td>
                <td style={{ padding: '0.85rem 1rem' }}>
                  <div className="font-mono" style={{ color: log.ip.includes('Tor') || log.ip.includes('185.') ? '#f43f5e' : 'var(--text-primary)' }}>{log.ip}</div>
                  <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>{log.location || 'Internal'}</div>
                </td>
                <td style={{ padding: '0.85rem 1rem', maxWidth: '280px', textOverflow: 'ellipsis', overflow: 'hidden', whiteSpace: 'nowrap' }}>
                  {log.details}
                </td>
                <td style={{ padding: '0.85rem 1rem' }}>
                  <span className="font-mono" style={{ color: log.anomalyScore > 0.7 ? '#f43f5e' : log.anomalyScore > 0.4 ? '#f59e0b' : '#10b981', fontWeight: 700 }}>
                    {Math.round(log.anomalyScore * 100)}%
                  </span>
                </td>
                <td style={{ padding: '0.85rem 1rem' }}>
                  <span className={`badge badge-${log.severity}`}>{log.severity}</span>
                </td>
                <td style={{ padding: '0.85rem 1rem', textAlign: 'center' }}>
                  <button onClick={() => setSelectedEvent(log)} className="btn-secondary" style={{ padding: '0.25rem 0.5rem', fontSize: '0.75rem' }}>
                    <Eye size={12} /> View
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Detail Modal Inspector */}
      {selectedEvent && (
        <div style={{
          position: 'fixed',
          top: 0, left: 0, right: 0, bottom: 0,
          background: 'rgba(0,0,0,0.75)',
          backdropFilter: 'blur(8px)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          zIndex: 1000,
          padding: '1rem'
        }}>
          <div className="glass-panel" style={{ width: '100%', maxWidth: '580px', padding: '1.5rem' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
              <h3 style={{ fontSize: '1.1rem', fontWeight: 700, display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                <ShieldAlert size={18} style={{ color: 'var(--accent-cyan)' }} /> Telemetry Event Detail Inspector
              </h3>
              <span className={`badge badge-${selectedEvent.severity}`}>{selectedEvent.severity}</span>
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem', fontSize: '0.85rem' }}>
              <div style={{ display: 'grid', gridTemplateColumns: '120px 1fr', gap: '0.5rem', background: 'rgba(0,0,0,0.25)', padding: '0.75rem', borderRadius: '8px' }}>
                <span style={{ color: 'var(--text-muted)' }}>Event ID:</span>
                <span className="font-mono">{selectedEvent.id}</span>

                <span style={{ color: 'var(--text-muted)' }}>Event Type:</span>
                <span style={{ fontWeight: 600 }}>{selectedEvent.type}</span>

                <span style={{ color: 'var(--text-muted)' }}>Timestamp:</span>
                <span className="font-mono">{selectedEvent.timestamp}</span>

                <span style={{ color: 'var(--text-muted)' }}>Target User:</span>
                <span>{selectedEvent.user || 'None'}</span>

                <span style={{ color: 'var(--text-muted)' }}>Source IP:</span>
                <span className="font-mono">{selectedEvent.ip} ({selectedEvent.location})</span>

                <span style={{ color: 'var(--text-muted)' }}>Target App:</span>
                <span>{selectedEvent.app || 'N/A'}</span>

                <span style={{ color: 'var(--text-muted)' }}>ML Anomaly Score:</span>
                <span className="font-mono" style={{ color: '#f43f5e', fontWeight: 700 }}>{Math.round(selectedEvent.anomalyScore * 100)}% Confidence</span>
              </div>

              <div>
                <h4 style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', marginBottom: '0.25rem' }}>Telemetry Payload & Details:</h4>
                <div className="font-mono" style={{ background: 'var(--bg-primary)', padding: '0.75rem', borderRadius: '6px', border: '1px solid var(--border-subtle)', color: 'var(--accent-cyan)' }}>
                  {selectedEvent.details}
                </div>
              </div>
            </div>

            <div style={{ marginTop: '1.5rem', display: 'flex', justifyContent: 'flex-end' }}>
              <button onClick={() => setSelectedEvent(null)} className="btn-secondary" style={{ fontSize: '0.85rem' }}>
                Close Inspector
              </button>
            </div>
          </div>
        </div>
      )}

    </div>
  );
}
