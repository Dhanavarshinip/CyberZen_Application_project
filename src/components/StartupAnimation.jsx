import React, { useEffect, useState } from 'react';
import { Shield } from 'lucide-react';
import { apiClient } from '../services/apiClient';

export default function StartupAnimation({ onComplete }) {
  const [fading, setFading] = useState(false);
  const [imgLoaded, setImgLoaded] = useState(false);

  const apiBase = apiClient?.getApiBase ? apiClient.getApiBase() : 'https://cyberzen.13.211.114.156.sslip.io/api';
  const cleanBase = apiBase.endsWith('/') ? apiBase.slice(0, -1) : apiBase;
  const [imgSrc, setImgSrc] = useState('/cyberzen-3d-shield.jpg');

  const handleSkip = () => {
    setFading(true);
    setTimeout(() => {
      if (onComplete) onComplete();
    }, 200);
  };

  useEffect(() => {
    // 2.3s display, then 0.5s fade out
    const fadeTimer = setTimeout(() => {
      setFading(true);
    }, 1200);

    const completeTimer = setTimeout(() => {
      if (onComplete) onComplete();
    }, 1500);

    return () => {
      clearTimeout(fadeTimer);
      clearTimeout(completeTimer);
    };
  }, [onComplete]);

  return (
    <div 
      onClick={handleSkip}
      title="Click anywhere to enter Operations Center"
      style={{
        position: 'fixed',
        inset: 0,
        background: '#000000',
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        justifyContent: 'center',
        zIndex: 9999,
        opacity: fading ? 0 : 1,
        transition: 'opacity 0.4s ease-out',
        fontFamily: 'Inter, system-ui, -apple-system, sans-serif',
        overflow: 'hidden',
        cursor: 'pointer'
      }}
    >
      {/* Full Animative Cybersecurity Image Background */}
      <div style={{
        position: 'absolute',
        inset: -20,
        zIndex: 0,
        overflow: 'hidden',
        pointerEvents: 'none'
      }}>
        <img
          src="/cyberzen-cyber-bg.jpg"
          alt="Cyber Defense Matrix"
          onError={(e) => { e.currentTarget.style.display = 'none'; }}
          style={{
            width: '100%',
            height: '100%',
            objectFit: 'cover',
            filter: 'brightness(0.68) contrast(1.2) saturate(1.15)',
            animation: 'cyberBgMotion 20s ease-in-out infinite alternate',
            transformOrigin: 'center center'
          }}
        />
        {/* Cinematic Vignette & Radial Cyan Aura Overlay */}
        <div style={{
          position: 'absolute',
          inset: 0,
          background: 'radial-gradient(circle at 50% 45%, rgba(0, 240, 255, 0.12) 0%, rgba(3, 7, 18, 0.65) 55%, rgba(0, 0, 0, 0.92) 100%)'
        }} />
      </div>

      {/* 3D Cyber Grid Lines Overlay */}
      <div style={{
        position: 'absolute',
        inset: 0,
        backgroundImage: `
          linear-gradient(rgba(0, 240, 255, 0.04) 1px, transparent 1px),
          linear-gradient(90deg, rgba(0, 240, 255, 0.04) 1px, transparent 1px)
        `,
        backgroundSize: '36px 36px, 36px 36px',
        pointerEvents: 'none',
        zIndex: 1
      }} />

      {/* Prominent 3D Cybersecurity Shield Emblem */}
      <div style={{
        position: 'relative',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        marginBottom: '1.75rem',
        perspective: '1000px'
      }}>
        {/* Pulsing Cyan Radial Aura */}
        <div style={{
          position: 'absolute',
          width: '260px',
          height: '260px',
          borderRadius: '50%',
          background: 'radial-gradient(circle, rgba(0, 240, 255, 0.35) 0%, rgba(59, 130, 246, 0.12) 50%, transparent 75%)',
          filter: 'blur(24px)',
          animation: 'cyberPulse 2.4s ease-in-out infinite'
        }} />

        {/* Outer Rotating Cyber Tech Ring */}
        <div style={{
          position: 'absolute',
          width: '210px',
          height: '210px',
          borderRadius: '50%',
          border: '1px dashed rgba(0, 240, 255, 0.35)',
          animation: 'rotateSlow 18s linear infinite',
          boxShadow: '0 0 25px rgba(0, 240, 255, 0.15)'
        }} />

        {/* 3D Floating Container */}
        <div style={{
          width: '180px',
          height: '180px',
          position: 'relative',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          animation: 'float3D 3s ease-in-out infinite',
          transformStyle: 'preserve-3d',
          zIndex: 2
        }}>
          {/* Real 3D Cybersecurity Shield Image */}
          <img
            src={imgSrc}
            alt="CyberZen 3D Shield"
            onLoad={() => setImgLoaded(true)}
            onError={() => {
              if (imgSrc !== `${cleanBase}/assets/cyberzen-3d-shield.jpg`) {
                setImgSrc(`${cleanBase}/assets/cyberzen-3d-shield.jpg`);
              }
            }}
            style={{
              width: '100%',
              height: '100%',
              objectFit: 'contain',
              borderRadius: '24px',
              filter: 'drop-shadow(0 0 35px rgba(0, 240, 255, 0.55)) drop-shadow(0 15px 30px rgba(0, 0, 0, 0.9))',
              display: imgLoaded ? 'block' : 'none',
              transform: 'scale(1.08)'
            }}
          />

          {/* Holographic 3D Shield Fallback while image streams */}
          {!imgLoaded && (
            <div style={{
              width: '100px',
              height: '100px',
              borderRadius: '24px',
              background: 'linear-gradient(135deg, rgba(0, 240, 255, 0.25) 0%, rgba(59, 130, 246, 0.35) 100%)',
              border: '2px solid rgba(0, 240, 255, 0.6)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              color: '#00f0ff',
              boxShadow: '0 0 45px rgba(0, 240, 255, 0.45)',
              transform: 'rotateY(-12deg) rotateX(10deg)'
            }}>
              <Shield size={56} strokeWidth={2.4} />
            </div>
          )}
        </div>
      </div>

      {/* Brand: CyberZen & Subtitle: Project Title */}
      <div style={{ textAlign: 'center', position: 'relative', zIndex: 2, padding: '0 1.5rem', maxWidth: '780px' }}>
        <h1 style={{
          fontSize: '2.5rem',
          fontWeight: 900,
          color: '#ffffff',
          letterSpacing: '-0.03em',
          margin: '0 0 0.5rem 0',
          textShadow: '0 0 30px rgba(0, 240, 255, 0.35)'
        }}>
          Cyber<span style={{ color: '#00f0ff' }}>Zen</span>
        </h1>

        <p style={{
          fontSize: '0.92rem',
          fontWeight: 600,
          color: '#94a3b8',
          letterSpacing: '0.04em',
          textTransform: 'uppercase',
          margin: '0 auto',
          lineHeight: 1.5,
          maxWidth: '680px'
        }}>
          Intelligent Real-Time Digital Threat Detection, Prevention and Incident Reconstruction
        </p>
      </div>

      {/* Futuristic Scan Bar */}
      <div style={{
        marginTop: '2rem',
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        gap: '0.6rem',
        position: 'relative',
        zIndex: 2
      }}>
        <div style={{
          width: '200px',
          height: '3px',
          background: 'rgba(255, 255, 255, 0.1)',
          borderRadius: '3px',
          overflow: 'hidden',
          position: 'relative',
          boxShadow: '0 0 10px rgba(0, 240, 255, 0.2)'
        }}>
          <div style={{
            width: '100%',
            height: '100%',
            background: 'linear-gradient(90deg, transparent, #00f0ff, #38bdf8, transparent)',
            animation: 'scanLine 1.6s ease-in-out infinite'
          }} />
        </div>
        <span style={{
          fontSize: '0.68rem',
          color: '#00f0ff',
          letterSpacing: '0.12em',
          fontWeight: 700,
          textTransform: 'uppercase',
          opacity: 0.9
        }}>
          INITIALIZING CYBER DEFENSE CORES
        </span>
      </div>

      <style>{`
        @keyframes cyberBgMotion {
          0% { transform: scale(1) translate(0px, 0px); }
          50% { transform: scale(1.08) translate(-1.2%, -0.8%); }
          100% { transform: scale(1.04) translate(1%, 0.6%); }
        }
        @keyframes float3D {
          0%, 100% {
            transform: translateY(0px) rotateY(-8deg) rotateX(6deg);
          }
          50% {
            transform: translateY(-12px) rotateY(8deg) rotateX(-4deg);
          }
        }
        @keyframes cyberPulse {
          0%, 100% { transform: scale(1); opacity: 0.5; }
          50% { transform: scale(1.18); opacity: 0.85; }
        }
        @keyframes rotateSlow {
          from { transform: rotate(0deg); }
          to { transform: rotate(360deg); }
        }
        @keyframes scanLine {
          0% { transform: translateX(-100%); }
          100% { transform: translateX(100%); }
        }
      `}</style>
    </div>
  );
}
