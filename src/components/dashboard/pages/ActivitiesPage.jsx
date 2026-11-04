import React, { useState } from 'react';
import { Activity, Search, Filter, Download } from 'lucide-react';
import { REALTIME_ACTIVITIES } from '../../../data/digitalGuardData';

export default function ActivitiesPage() {
  const [searchTerm, setSearchTerm] = useState('');
  const [filterLevel, setFilterLevel] = useState('ALL');

  const filtered = REALTIME_ACTIVITIES.filter(act => {
    const matchesFilter = filterLevel === 'ALL' || act.riskLevel.toUpperCase() === filterLevel;
    const matchesSearch = !searchTerm || act.activity.toLowerCase().includes(searchTerm.toLowerCase()) || act.source.toLowerCase().includes(searchTerm.toLowerCase());
    return matchesFilter && matchesSearch;
  });

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
      <div className="glass-panel" style={{ padding: '1.25rem', display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '1rem' }}>
        <div>
          <h2 style={{ fontSize: '1.15rem', fontWeight: 700, display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <Activity size={20} style={{ color: 'var(--accent-cyan)' }} /> Telemetry Activities Log
          </h2>
          <p style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>Full real-time stream of monitored security, API, and network activities</p>
        </div>

        <div style={{ display: 'flex', gap: '0.75rem' }}>
          <div style={{ position: 'relative' }}>
            <Search size={15} style={{ position: 'absolute', left: '12px', top: '50%', transform: 'translateY(-50%)', color: 'var(--text-muted)' }} />
            <input
              type="text"
              placeholder="Search logs..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="input-field"
              style={{ width: '220px', padding: '0.45rem 0.85rem 0.45rem 2.2rem' }}
            />
          </div>

          <div style={{ display: 'flex', gap: '0.3rem', background: 'rgba(0,0,0,0.3)', padding: '0.2rem', borderRadius: '8px' }}>
            {['ALL', 'LOW', 'HIGH', 'CRITICAL'].map(lvl => (
              <button
                key={lvl}
                onClick={() => setFilterLevel(lvl)}
                style={{
                  padding: '0.3rem 0.65rem',
                  fontSize: '0.75rem',
                  borderRadius: '6px',
                  border: 'none',
                  cursor: 'pointer',
                  background: filterLevel === lvl ? 'var(--accent-cyan)' : 'transparent',
                  color: filterLevel === lvl ? '#050b14' : 'var(--text-secondary)',
                  fontWeight: filterLevel === lvl ? 700 : 500
                }}
              >
                {lvl}
              </button>
            ))}
          </div>
        </div>
      </div>

      <div className="glass-panel" style={{ padding: '0', overflow: 'hidden' }}>
        <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '0.85rem' }}>
          <thead>
            <tr style={{ background: 'rgba(0,0,0,0.3)', borderBottom: '1px solid var(--border-subtle)', color: 'var(--text-muted)', fontSize: '0.75rem', textTransform: 'uppercase' }}>
              <th style={{ padding: '0.85rem 1rem' }}>Timestamp</th>
              <th style={{ padding: '0.85rem 1rem' }}>Activity Name</th>
              <th style={{ padding: '0.85rem 1rem' }}>Device Endpoint</th>
              <th style={{ padding: '0.85rem 1rem' }}>Source Location</th>
              <th style={{ padding: '0.85rem 1rem' }}>Risk Score</th>
              <th style={{ padding: '0.85rem 1rem' }}>Verification Status</th>
            </tr>
          </thead>
          <tbody>
            {filtered.map(act => (
              <tr key={act.id} style={{ borderBottom: '1px solid rgba(255,255,255,0.05)' }}>
                <td className="font-mono" style={{ padding: '0.85rem 1rem', color: 'var(--text-muted)' }}>{act.timestamp}</td>
                <td style={{ padding: '0.85rem 1rem', fontWeight: 600 }}>{act.activity}</td>
                <td style={{ padding: '0.85rem 1rem', color: 'var(--text-secondary)' }}>{act.device}</td>
                <td className="font-mono" style={{ padding: '0.85rem 1rem' }}>{act.source}</td>
                <td className="font-mono" style={{ padding: '0.85rem 1rem', fontWeight: 700, color: parseInt(act.risk) > 60 ? '#f43f5e' : '#10b981' }}>{act.risk}</td>
                <td style={{ padding: '0.85rem 1rem' }}>
                  <span className={`badge ${act.status === 'Blocked' ? 'badge-critical' : 'badge-low'}`}>{act.status}</span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
