import React from 'react';
import { Server, CheckCircle2, Laptop } from 'lucide-react';
import { CONNECTED_DEVICES_LIST } from '../../../data/digitalGuardData';

export default function ConnectedServicesPage() {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
      <div className="glass-panel" style={{ padding: '1.25rem' }}>
        <h2 style={{ fontSize: '1.15rem', fontWeight: 700, display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <Server size={20} style={{ color: 'var(--accent-cyan)' }} /> Connected Services & Endpoints
        </h2>
        <p style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>Monitored workstation endpoints, cloud gateways, and database integrations</p>
      </div>

      <div className="glass-panel" style={{ padding: '0', overflow: 'hidden' }}>
        <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '0.85rem' }}>
          <thead>
            <tr style={{ background: 'rgba(0,0,0,0.3)', borderBottom: '1px solid var(--border-subtle)', color: 'var(--text-muted)', fontSize: '0.75rem', textTransform: 'uppercase' }}>
              <th style={{ padding: '0.85rem 1rem' }}>Device Name</th>
              <th style={{ padding: '0.85rem 1rem' }}>Owner / Service</th>
              <th style={{ padding: '0.85rem 1rem' }}>IP Address</th>
              <th style={{ padding: '0.85rem 1rem' }}>OS Platform</th>
              <th style={{ padding: '0.85rem 1rem' }}>Protection Status</th>
            </tr>
          </thead>
          <tbody>
            {CONNECTED_DEVICES_LIST.map(dev => (
              <tr key={dev.id} style={{ borderBottom: '1px solid rgba(255,255,255,0.05)' }}>
                <td style={{ padding: '0.85rem 1rem', fontWeight: 600 }}>{dev.name}</td>
                <td style={{ padding: '0.85rem 1rem', color: 'var(--text-secondary)' }}>{dev.owner}</td>
                <td className="font-mono" style={{ padding: '0.85rem 1rem' }}>{dev.ip}</td>
                <td style={{ padding: '0.85rem 1rem', color: 'var(--text-secondary)' }}>{dev.os}</td>
                <td style={{ padding: '0.85rem 1rem' }}>
                  <span className={`badge ${dev.status === 'Protected' ? 'badge-low' : 'badge-high'}`}>{dev.status}</span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
