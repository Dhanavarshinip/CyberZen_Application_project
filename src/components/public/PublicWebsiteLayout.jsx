import React, { useState } from 'react';
import { Shield, Download, ArrowRight, Menu, X, ExternalLink } from 'lucide-react';
import PublicHomeView from './PublicHomeView';
import FeaturesView from './FeaturesView';
import DownloadView from './DownloadView';
import LoginForm from '../auth/LoginForm';
import SignupForm from '../auth/SignupForm';

export default function PublicWebsiteLayout({ initialPage = 'home' }) {
  const [currentPage, setCurrentPage] = useState(initialPage); // 'home' | 'features' | 'download' | 'login' | 'register'
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  const navigateTo = (page) => {
    setCurrentPage(page);
    setMobileMenuOpen(false);
    window.scrollTo({ top: 0, behavior: 'smooth' });
  };

  return (
    <div style={{
      minHeight: '100vh',
      display: 'flex',
      flexDirection: 'column',
      background: '#090d16',
      color: '#f8fafc',
      fontFamily: 'Inter, system-ui, -apple-system, sans-serif'
    }}>
      {/* Public Header / Navbar */}
      <header style={{
        background: 'rgba(9, 13, 22, 0.85)',
        backdropFilter: 'blur(8px)',
        borderBottom: '1px solid #1e293b',
        padding: '0.85rem 2rem',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        position: 'sticky',
        top: 0,
        zIndex: 50
      }}>
        {/* Brand */}
        <div
          onClick={() => navigateTo('home')}
          style={{ display: 'flex', alignItems: 'center', gap: '0.65rem', cursor: 'pointer' }}
        >
          <div style={{
            width: '36px',
            height: '36px',
            borderRadius: '8px',
            background: 'linear-gradient(135deg, rgba(0, 240, 255, 0.2) 0%, rgba(59, 130, 246, 0.3) 100%)',
            border: '1px solid rgba(0, 240, 255, 0.4)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            color: '#00f0ff'
          }}>
            <Shield size={20} strokeWidth={2.5} />
          </div>
          <div>
            <div style={{ fontSize: '1.15rem', fontWeight: 800, color: '#f8fafc', letterSpacing: '-0.02em', lineHeight: 1.1 }}>
              Cyber<span style={{ color: '#00f0ff' }}>Zen</span>
            </div>
            <div style={{ fontSize: '0.68rem', color: '#94a3b8', fontWeight: 500, maxWidth: '420px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title="Intelligent Real-Time Digital Threat Detection, Prevention and Incident Reconstruction">
              Intelligent Real-Time Digital Threat Detection, Prevention and Incident Reconstruction
            </div>
          </div>
        </div>

        {/* Desktop Nav Links */}
        <nav style={{ display: 'flex', alignItems: 'center', gap: '1.75rem' }}>
          <button
            onClick={() => navigateTo('home')}
            style={{
              background: 'none',
              border: 'none',
              color: currentPage === 'home' ? '#00f0ff' : '#94a3b8',
              fontWeight: currentPage === 'home' ? 700 : 500,
              fontSize: '0.9rem',
              cursor: 'pointer',
              transition: 'color 0.15s ease'
            }}
          >
            Home
          </button>

          <button
            onClick={() => navigateTo('features')}
            style={{
              background: 'none',
              border: 'none',
              color: currentPage === 'features' ? '#00f0ff' : '#94a3b8',
              fontWeight: currentPage === 'features' ? 700 : 500,
              fontSize: '0.9rem',
              cursor: 'pointer',
              transition: 'color 0.15s ease'
            }}
          >
            Features & Models
          </button>

          <button
            onClick={() => navigateTo('download')}
            style={{
              background: 'none',
              border: 'none',
              color: currentPage === 'download' ? '#00f0ff' : '#94a3b8',
              fontWeight: currentPage === 'download' ? 700 : 500,
              fontSize: '0.9rem',
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              gap: '0.35rem',
              transition: 'color 0.15s ease'
            }}
          >
            <Download size={15} />
            <span>Download</span>
          </button>
        </nav>

        {/* Auth Action Buttons */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
          <button
            onClick={() => navigateTo('login')}
            style={{
              background: 'none',
              border: '1px solid #334155',
              borderRadius: '8px',
              padding: '0.5rem 1rem',
              color: currentPage === 'login' ? '#00f0ff' : '#f8fafc',
              fontSize: '0.85rem',
              fontWeight: 600,
              cursor: 'pointer'
            }}
          >
            Sign In
          </button>

          <button
            onClick={() => navigateTo('register')}
            style={{
              background: '#00f0ff',
              border: 'none',
              borderRadius: '8px',
              padding: '0.5rem 1.15rem',
              color: '#090d16',
              fontSize: '0.85rem',
              fontWeight: 700,
              cursor: 'pointer',
              boxShadow: '0 0 15px rgba(0, 240, 255, 0.25)'
            }}
          >
            Register
          </button>
        </div>
      </header>

      {/* Page Body */}
      <main style={{ flex: 1 }}>
        {currentPage === 'home' && (
          <PublicHomeView
            onNavigate={navigateTo}
            onOpenDownload={() => navigateTo('download')}
            onOpenRegister={() => navigateTo('register')}
            onOpenLogin={() => navigateTo('login')}
          />
        )}

        {currentPage === 'features' && (
          <FeaturesView
            onOpenDownload={() => navigateTo('download')}
            onOpenRegister={() => navigateTo('register')}
          />
        )}

        {currentPage === 'download' && (
          <DownloadView />
        )}

        {(currentPage === 'login' || currentPage === 'register') && (
          <div style={{
            minHeight: 'calc(100vh - 180px)',
            display: 'flex',
            flexDirection: 'column',
            alignItems: 'center',
            justifyContent: 'center',
            padding: '3rem 1.5rem'
          }}>
            <div style={{ width: '100%', maxWidth: '380px' }}>
              {currentPage === 'login' ? (
                <LoginForm onSwitchToSignup={() => setCurrentPage('register')} />
              ) : (
                <SignupForm onSwitchToLogin={() => setCurrentPage('login')} />
              )}
            </div>
          </div>
        )}
      </main>

      {/* Public Footer */}
      <footer style={{
        borderTop: '1px solid #1e293b',
        padding: '2.5rem 2rem',
        background: '#070a12',
        color: '#64748b',
        fontSize: '0.82rem'
      }}>
        <div style={{
          maxWidth: '1200px',
          margin: '0 auto',
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          flexWrap: 'wrap',
          gap: '1.5rem'
        }}>
          <div>
            <div style={{ fontWeight: 700, color: '#f8fafc', marginBottom: '0.25rem' }}>
              Intelligent Real-Time Digital Threat Detection, Prevention and Incident Reconstruction
            </div>
            <div>Autonomous anomaly detection, behavioral drift modeling, and temporal graph reconstruction.</div>
          </div>

          <div style={{ display: 'flex', gap: '1.5rem' }}>
            <button
              onClick={() => navigateTo('home')}
              style={{ background: 'none', border: 'none', color: '#94a3b8', cursor: 'pointer', fontSize: '0.82rem' }}
            >
              Home
            </button>
            <button
              onClick={() => navigateTo('features')}
              style={{ background: 'none', border: 'none', color: '#94a3b8', cursor: 'pointer', fontSize: '0.82rem' }}
            >
              Features
            </button>
            <button
              onClick={() => navigateTo('download')}
              style={{ background: 'none', border: 'none', color: '#94a3b8', cursor: 'pointer', fontSize: '0.82rem' }}
            >
              Download (.exe)
            </button>
          </div>

          <div>
            © 2026 CyberZen. Verified Windows 10 & 11 Host Distribution.
          </div>
        </div>
      </footer>
    </div>
  );
}
