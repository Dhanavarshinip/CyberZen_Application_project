import React from 'react';
import { FileText, Download, FileSpreadsheet } from 'lucide-react';

export default function ReportsPage() {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
      <div className="glass-panel" style={{ padding: '1.25rem' }}>
        <h2 style={{ fontSize: '1.15rem', fontWeight: 700, display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <FileText size={20} style={{ color: 'var(--accent-cyan)' }} /> Executive & Technical Reports
        </h2>
        <p style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>Generated incident summaries and compliance documentation</p>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: '1.25rem' }}>
        <div className="glass-panel" style={{ padding: '1.25rem', display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
          <h3 style={{ fontSize: '1rem', fontWeight: 700 }}>Weekly Executive Summary</h3>
          <p style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>High-level overview of security posture, incident counts, and risk trends.</p>
          <button className="btn-social" style={{ fontSize: '0.8rem' }}><Download size={14} /> Download PDF</button>
        </div>

        <div className="glass-panel" style={{ padding: '1.25rem', display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
          <h3 style={{ fontSize: '1rem', fontWeight: 700 }}>Technical Forensics Audit</h3>
          <p style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>Full raw telemetry logs and anomaly feature weights for compliance.</p>
          <button className="btn-social" style={{ fontSize: '0.8rem' }}><Download size={14} /> Download JSON</button>
        </div>
      </div>
    </div>
  );
}
