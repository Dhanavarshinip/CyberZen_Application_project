import React from 'react';
import { AlertTriangle, RefreshCw } from 'lucide-react';

export class ErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = { hasError: false, error: null };
  }

  static getDerivedStateFromError(error) {
    return { hasError: true, error };
  }

  componentDidCatch(error, errorInfo) {
    console.error('[ErrorBoundary caught error]:', error, errorInfo);
  }

  handleReset = () => {
    this.setState({ hasError: false, error: null });
    if (this.props.onReset) this.props.onReset();
  };

  render() {
    if (this.state.hasError) {
      const isDark = typeof document !== 'undefined' ? (document.documentElement.getAttribute('data-theme') !== 'light') : true;

      return (
        <div style={{
          padding: '3rem 1.5rem',
          maxWidth: '650px',
          margin: '3rem auto',
          background: isDark ? '#0a0a0a' : '#ffffff',
          borderRadius: '12px',
          border: isDark ? '1px solid rgba(220, 38, 38, 0.4)' : '1px solid #fecaca',
          boxShadow: isDark ? '0 10px 30px rgba(0, 0, 0, 0.7)' : '0 4px 6px -1px rgba(0, 0, 0, 0.05)',
          textAlign: 'center',
          color: isDark ? '#ffffff' : '#0f172a'
        }}>
          <div style={{
            width: '48px',
            height: '48px',
            borderRadius: '50%',
            background: isDark ? 'rgba(220, 38, 38, 0.15)' : '#fef2f2',
            color: '#dc2626',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            margin: '0 auto 1rem auto'
          }}>
            <AlertTriangle size={24} />
          </div>
          <h2 style={{ fontSize: '1.25rem', fontWeight: 800, margin: '0 0 0.5rem 0', color: isDark ? '#ffffff' : '#0f172a' }}>
            View Encountered an Error
          </h2>
          <p style={{ fontSize: '0.85rem', color: isDark ? '#94a3b8' : '#64748b', margin: '0 0 1.25rem 0', lineHeight: 1.5 }}>
            {this.state.error?.message || 'An unexpected error occurred while rendering this view.'}
          </p>
          <button
            onClick={this.handleReset}
            style={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: '0.45rem',
              padding: '0.6rem 1.2rem',
              borderRadius: '8px',
              border: 'none',
              background: '#0284c7',
              color: '#ffffff',
              fontSize: '0.85rem',
              fontWeight: 700,
              cursor: 'pointer'
            }}
          >
            <RefreshCw size={14} />
            <span>Reload View</span>
          </button>
        </div>
      );
    }
    return this.props.children;
  }
}
