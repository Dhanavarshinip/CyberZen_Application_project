import React from 'react';
import { 
  ShieldCheck, 
  LayoutDashboard, 
  Activity, 
  AlertTriangle, 
  ShieldAlert, 
  Share2, 
  TrendingUp, 
  Bot, 
  FileText, 
  Server, 
  Settings,
  ChevronRight
} from 'lucide-react';

export default function Sidebar({ activeTab, setActiveTab }) {
  const navItems = [
    { id: 'dashboard', label: 'Dashboard', icon: LayoutDashboard },
    { id: 'activities', label: 'Activities', icon: Activity },
    { id: 'anomalies', label: 'Anomaly Alerts', icon: AlertTriangle, badge: '3' },
    { id: 'incidents', label: 'Incidents', icon: ShieldAlert, badge: '1', badgeColor: '#f43f5e' },
    { id: 'graph', label: 'Activity Graph', icon: Share2 },
    { id: 'risk', label: 'Risk Center', icon: TrendingUp },
    { id: 'ai-analyst', label: 'AI Security Analyst', icon: Bot, highlight: true },
    { id: 'reports', label: 'Reports', icon: FileText },
    { id: 'services', label: 'Connected Services', icon: Server },
    { id: 'settings', label: 'Settings', icon: Settings }
  ];

  return (
    <aside style={{
      width: '260px',
      minWidth: '260px',
      background: 'rgba(12, 16, 26, 0.95)',
      backdropFilter: 'blur(16px)',
      borderRight: '1px solid var(--border-subtle)',
      display: 'flex',
      flexDirection: 'column',
      height: '100vh',
      position: 'sticky',
      top: 0,
      zIndex: 100
    }}>
      
      {/* Brand Logo Header */}
      <div style={{ padding: '1.5rem 1.25rem', borderBottom: '1px solid var(--border-subtle)', display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
        <div style={{
          width: '38px',
          height: '38px',
          borderRadius: '10px',
          background: 'linear-gradient(135deg, rgba(0, 240, 255, 0.2) 0%, rgba(59, 130, 246, 0.2) 100%)',
          border: '1px solid var(--border-glow)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          color: 'var(--accent-cyan)'
        }}>
          <ShieldCheck size={22} />
        </div>
        <div>
          <div style={{ fontSize: '1.1rem', fontWeight: 800, letterSpacing: '-0.02em', color: 'var(--text-primary)', display: 'flex', alignItems: 'center', gap: '0.3rem' }}>
            Digital<span style={{ color: 'var(--accent-cyan)' }}>Guard</span>
          </div>
          <div style={{ fontSize: '0.65rem', color: 'var(--accent-cyan)', fontWeight: 700, letterSpacing: '0.1em', textTransform: 'uppercase' }}>
            AI SECURITY PLATFORM
          </div>
        </div>
      </div>

      {/* Navigation List */}
      <nav style={{ flex: 1, padding: '1rem 0.75rem', overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: '0.25rem' }}>
        {navItems.map((item) => {
          const Icon = item.icon;
          const isActive = activeTab === item.id;

          return (
            <button
              key={item.id}
              onClick={() => setActiveTab(item.id)}
              style={{
                width: '100%',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                padding: '0.65rem 0.85rem',
                borderRadius: '8px',
                border: isActive ? '1px solid var(--border-glow)' : '1px solid transparent',
                background: isActive ? 'rgba(0, 240, 255, 0.12)' : item.highlight ? 'rgba(59, 130, 246, 0.08)' : 'transparent',
                color: isActive ? 'var(--accent-cyan)' : 'var(--text-secondary)',
                fontWeight: isActive ? 700 : 500,
                fontSize: '0.85rem',
                cursor: 'pointer',
                transition: 'all 0.2s ease',
                fontFamily: 'var(--font-main)'
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
                <Icon size={18} style={{ color: isActive ? 'var(--accent-cyan)' : item.highlight ? 'var(--accent-blue)' : 'var(--text-muted)' }} />
                <span>{item.label}</span>
              </div>

              {item.badge && (
                <span style={{
                  background: item.badgeColor || 'rgba(0, 240, 255, 0.2)',
                  color: item.badgeColor ? '#ffffff' : 'var(--accent-cyan)',
                  fontSize: '0.65rem',
                  fontWeight: 700,
                  padding: '0.15rem 0.45rem',
                  borderRadius: '10px'
                }}>
                  {item.badge}
                </span>
              )}
            </button>
          );
        })}
      </nav>

      {/* Footer System Health Tag */}
      <div style={{ padding: '1rem 1.25rem', borderTop: '1px solid var(--border-subtle)', background: 'rgba(7, 9, 14, 0.5)' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.75rem', color: 'var(--text-muted)' }}>
          <span style={{ width: '8px', height: '8px', borderRadius: '50%', background: '#10b981', display: 'inline-block' }}></span>
          <span>Engine v3.8 Active</span>
        </div>
      </div>

    </aside>
  );
}
