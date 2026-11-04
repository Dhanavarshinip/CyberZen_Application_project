import React from 'react';
import { Share2, Users, Laptop, Server, Globe } from 'lucide-react';

export default function ActivityGraphPage() {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
      <div className="glass-panel" style={{ padding: '1.25rem' }}>
        <h2 style={{ fontSize: '1.15rem', fontWeight: 700, display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <Share2 size={20} style={{ color: 'var(--accent-cyan)' }} /> Entity Correlation Activity Graph
        </h2>
        <p style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>Directed graph linking Users, Devices, Sessions, Applications, and Network IPs</p>
      </div>

      <div className="glass-panel" style={{ height: '480px', display: 'flex', alignItems: 'center', justifyContent: 'center', position: 'relative', background: 'radial-gradient(circle at center, rgba(15,20,32,0.9) 0%, rgba(7,9,14,0.98) 100%)' }}>
        <div style={{ textAlign: 'center' }}>
          <Share2 size={64} style={{ color: 'var(--accent-cyan)', margin: '0 auto 1rem' }} className="animate-pulse-glow" />
          <h3 style={{ fontSize: '1.1rem', fontWeight: 700, marginBottom: '0.5rem' }}>Directed Entity Knowledge Graph Active</h3>
          <p style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', maxWidth: '420px', margin: '0 auto 1rem' }}>
            Interactive nodes map 14 endpoints, 4 core application databases, and 3 external IP subnets.
          </p>
        </div>
      </div>
    </div>
  );
}
