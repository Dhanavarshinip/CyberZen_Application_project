import React from 'react';
import { Download, Shield, Laptop, Chrome, CheckCircle2, AlertTriangle, ExternalLink } from 'lucide-react';

export default function DownloadView() {
  const windowsZipUrl = "https://cyberzen.13.211.114.156.sslip.io/CyberZen-Windows-App-v1.0.0.zip";
  const windowsExeUrl = "https://github.com/Dhanavarshinip/CyberZen_Application_project/releases/download/v1.0.0/CyberZen-Operations-Center-Setup-1.0.0.exe";
  const extensionZipUrl = "https://cyberzen.13.211.114.156.sslip.io/cyberzen-chrome-extension.zip";

  return (
    <div style={{
      backgroundColor: '#f8fafc',
      color: '#0f172a',
      fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif',
      minHeight: '100vh',
      padding: '48px 20px 80px 20px',
      display: 'flex',
      flexDirection: 'column',
      alignItems: 'center'
    }}>
      <div style={{ maxWidth: '960px', width: '100%' }}>
        {/* Header */}
        <header style={{ textAlign: 'center', marginBottom: '44px' }}>
          <div style={{
            display: 'inline-flex',
            alignItems: 'center',
            padding: '4px 14px',
            background: '#f1f5f9',
            border: '1px solid #e2e8f0',
            borderRadius: '9999px',
            color: '#475569',
            fontSize: '12px',
            fontWeight: 700,
            letterSpacing: '0.5px',
            textTransform: 'uppercase',
            marginBottom: '18px'
          }}>
            Official Release · Version 1.0
          </div>
          <h1 style={{
            fontSize: '36px',
            fontWeight: 700,
            letterSpacing: '-0.8px',
            color: '#0f172a',
            marginBottom: '14px',
            lineHeight: 1.2
          }}>
            Install CyberZen on your computer
          </h1>
          <p style={{
            fontSize: '16.5px',
            color: '#475569',
            maxWidth: '640px',
            margin: '0 auto',
            lineHeight: 1.6
          }}>
            A quiet, continuous security companion that monitors background system activity and browser sessions to prevent real-world threats before they cause harm.
          </p>
        </header>

        {/* Cards Grid */}
        <div style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))',
          gap: '24px',
          marginBottom: '36px'
        }}>
          {/* Windows Desktop Application Card */}
          <div style={{
            background: '#ffffff',
            border: '1px solid #e2e8f0',
            borderTop: '3px solid #2563eb',
            borderRadius: '14px',
            padding: '32px',
            display: 'flex',
            flexDirection: 'column',
            boxShadow: '0 4px 6px -1px rgba(15, 23, 42, 0.06), 0 2px 4px -2px rgba(15, 23, 42, 0.04)'
          }}>
            <div style={{
              fontSize: '12px',
              fontWeight: 700,
              letterSpacing: '0.5px',
              textTransform: 'uppercase',
              color: '#2563eb',
              marginBottom: '8px'
            }}>
              Windows Desktop Application
            </div>
            <h2 style={{
              fontSize: '22px',
              fontWeight: 700,
              color: '#0f172a',
              marginBottom: '10px',
              letterSpacing: '-0.3px'
            }}>
              CyberZen Operations Center
            </h2>
            <p style={{
              fontSize: '14px',
              color: '#475569',
              lineHeight: 1.6,
              marginBottom: '24px',
              flexGrow: 1
            }}>
              Monitors process behavior, inspects unexpected background tasks, and verifies system integrity in real time. Designed to operate silently with minimal memory usage.
            </p>

            <a
              href={windowsZipUrl}
              download
              style={{
                display: 'inline-flex',
                alignItems: 'center',
                justifyContent: 'center',
                gap: '8px',
                padding: '13px 20px',
                fontSize: '14px',
                fontWeight: 600,
                borderRadius: '8px',
                textDecoration: 'none',
                cursor: 'pointer',
                textAlign: 'center',
                backgroundColor: '#059669',
                color: '#ffffff',
                border: '1px solid #059669',
                transition: 'background-color 0.15s ease'
              }}
            >
              <Download size={17} />
              Download Windows App Package (.zip) — Safe & Unblocked (98 MB)
            </a>

            <div style={{ marginTop: '10px', textAlign: 'center', fontSize: '13px' }}>
              <a
                href={windowsExeUrl}
                download
                style={{ color: '#2563eb', textDecoration: 'none' }}
              >
                Or download direct Windows installer (.exe, 99 MB)
              </a>
            </div>

            <div style={{
              marginTop: '12px',
              padding: '10px 14px',
              background: '#f8fafc',
              border: '1px solid #e2e8f0',
              borderRadius: '8px',
              fontSize: '11.5px',
              color: '#475569',
              lineHeight: 1.4
            }}>
              <strong>Browser Notice:</strong> If Chrome shows "Download blocked" or "Keep / Discard", click the three dots next to the download item and choose <strong>Keep</strong> &rarr; <strong>Keep anyway</strong>. If Windows displays "Protected your PC", click <strong>More info</strong> &rarr; <strong>Run anyway</strong>.
            </div>

            <div style={{
              marginTop: '24px',
              paddingTop: '18px',
              borderTop: '1px solid #e2e8f0',
              display: 'flex',
              flexDirection: 'column',
              gap: '8px',
              fontSize: '12px',
              color: '#64748b'
            }}>
              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span>Operating System</span>
                <span style={{ fontWeight: 500, color: '#475569' }}>Windows 10, Windows 11 (64-bit)</span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span>Build Release</span>
                <span style={{ fontWeight: 500, color: '#475569' }}>Version 1.0.0 Stable</span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span>Integrity Check</span>
                <span style={{ fontFamily: 'monospace', fontWeight: 500, color: '#475569' }}>SHA-256 Verified</span>
              </div>
            </div>
          </div>

          {/* Chrome Security Companion Card */}
          <div style={{
            background: '#ffffff',
            border: '1px solid #e2e8f0',
            borderRadius: '14px',
            padding: '32px',
            display: 'flex',
            flexDirection: 'column',
            boxShadow: '0 4px 6px -1px rgba(15, 23, 42, 0.06), 0 2px 4px -2px rgba(15, 23, 42, 0.04)'
          }}>
            <div style={{
              fontSize: '12px',
              fontWeight: 700,
              letterSpacing: '0.5px',
              textTransform: 'uppercase',
              color: '#64748b',
              marginBottom: '8px'
            }}>
              Browser Companion
            </div>
            <h2 style={{
              fontSize: '22px',
              fontWeight: 700,
              color: '#0f172a',
              marginBottom: '10px',
              letterSpacing: '-0.3px'
            }}>
              Chrome Security Companion
            </h2>
            <p style={{
              fontSize: '14px',
              color: '#475569',
              lineHeight: 1.6,
              marginBottom: '24px',
              flexGrow: 1
            }}>
              Inspects website reputations as you browse, alerts you to deceptive URLs, and checks for phishing patterns in real time without tracking your private data.
            </p>

            <a
              href={extensionZipUrl}
              download
              style={{
                display: 'inline-flex',
                alignItems: 'center',
                justifyContent: 'center',
                gap: '8px',
                padding: '13px 20px',
                fontSize: '14px',
                fontWeight: 600,
                borderRadius: '8px',
                textDecoration: 'none',
                cursor: 'pointer',
                textAlign: 'center',
                backgroundColor: '#ffffff',
                color: '#0f172a',
                border: '1px solid #cbd5e1',
                transition: 'background-color 0.15s ease'
              }}
            >
              <Chrome size={17} />
              Download Extension Package (.zip)
            </a>

            <div style={{ marginTop: '10px', height: '17px' }}>&nbsp;</div>

            <div style={{
              marginTop: 'auto',
              paddingTop: '18px',
              borderTop: '1px solid #e2e8f0',
              display: 'flex',
              flexDirection: 'column',
              gap: '8px',
              fontSize: '12px',
              color: '#64748b'
            }}>
              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span>Supported Browsers</span>
                <span style={{ fontWeight: 500, color: '#475569' }}>Chrome, Edge, Brave, Opera</span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span>Specification</span>
                <span style={{ fontWeight: 500, color: '#475569' }}>Manifest V3 Architecture</span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span>Privacy Standard</span>
                <span style={{ fontWeight: 500, color: '#475569' }}>Zero Remote Telemetry Stored</span>
              </div>
            </div>
          </div>
        </div>

        {/* Walkthrough Section */}
        <div style={{
          background: '#ffffff',
          border: '1px solid #e2e8f0',
          borderRadius: '14px',
          padding: '36px 32px',
          boxShadow: '0 1px 2px 0 rgba(0, 0, 0, 0.05)',
          marginBottom: '36px'
        }}>
          <h3 style={{
            fontSize: '18px',
            fontWeight: 700,
            color: '#0f172a',
            marginBottom: '24px',
            letterSpacing: '-0.2px'
          }}>
            Simple installation guide
          </h3>

          <div style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))',
            gap: '24px'
          }}>
            <div style={{ display: 'flex', flexDirection: 'column' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '8px' }}>
                <div style={{
                  width: '24px',
                  height: '24px',
                  borderRadius: '50%',
                  background: '#e2e8f0',
                  color: '#0f172a',
                  fontSize: '12px',
                  fontWeight: 700,
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center'
                }}>
                  1
                </div>
                <div style={{ fontSize: '15px', fontWeight: 600, color: '#0f172a' }}>
                  Run the installer
                </div>
              </div>
              <div style={{ fontSize: '13px', color: '#475569', lineHeight: 1.6, paddingLeft: '34px' }}>
                Open <code style={{ background: '#f1f5f9', padding: '2px 5px', borderRadius: '4px', fontSize: '12px', color: '#0f172a', border: '1px solid #e2e8f0' }}>CyberZen-Operations-Center-Setup-1.0.0.exe</code> from your Downloads folder. If Windows SmartScreen appears, click <em>More info</em> and then <em>Run anyway</em>.
              </div>
            </div>

            <div style={{ display: 'flex', flexDirection: 'column' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '8px' }}>
                <div style={{
                  width: '24px',
                  height: '24px',
                  borderRadius: '50%',
                  background: '#e2e8f0',
                  color: '#0f172a',
                  fontSize: '12px',
                  fontWeight: 700,
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center'
                }}>
                  2
                </div>
                <div style={{ fontSize: '15px', fontWeight: 600, color: '#0f172a' }}>
                  Add to Chrome
                </div>
              </div>
              <div style={{ fontSize: '13px', color: '#475569', lineHeight: 1.6, paddingLeft: '34px' }}>
                Extract <code style={{ background: '#f1f5f9', padding: '2px 5px', borderRadius: '4px', fontSize: '12px', color: '#0f172a', border: '1px solid #e2e8f0' }}>cyberzen-chrome-extension.zip</code>. In Chrome, open <code>chrome://extensions</code>, turn on <strong>Developer mode</strong> at the top right, click <strong>Load unpacked</strong>, and select the folder.
              </div>
            </div>

            <div style={{ display: 'flex', flexDirection: 'column' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '8px' }}>
                <div style={{
                  width: '24px',
                  height: '24px',
                  borderRadius: '50%',
                  background: '#e2e8f0',
                  color: '#0f172a',
                  fontSize: '12px',
                  fontWeight: 700,
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center'
                }}>
                  3
                </div>
                <div style={{ fontSize: '15px', fontWeight: 600, color: '#0f172a' }}>
                  Ready to protect
                </div>
              </div>
              <div style={{ fontSize: '13px', color: '#475569', lineHeight: 1.6, paddingLeft: '34px' }}>
                CyberZen will start guarding your laptop immediately. When browsing, a subtle verification badge appears on visited websites to confirm they are safe.
              </div>
            </div>
          </div>
        </div>

        {/* Reassurance Banner */}
        <div style={{
          display: 'flex',
          alignItems: 'center',
          gap: '16px',
          background: '#f1f5f9',
          border: '1px solid #e2e8f0',
          borderRadius: '10px',
          padding: '16px 20px',
          fontSize: '13px',
          color: '#475569',
          marginBottom: '36px'
        }}>
          <Shield size={24} color="#059669" style={{ flexShrink: 0 }} />
          <div>
            <div style={{ fontWeight: 600, color: '#0f172a', marginBottom: '2px' }}>Private and lightweight by design</div>
            <div>CyberZen evaluates behavior on your local machine using lightweight machine learning models. Your files and personal history are never sent to external servers.</div>
          </div>
        </div>

        <footer style={{
          textAlign: 'center',
          fontSize: '13px',
          color: '#64748b',
          padding: '24px 0',
          borderTop: '1px solid #e2e8f0'
        }}>
          CyberZen Security Platform · Deployed on AWS EC2 Infrastructure · Open-Source Project
        </footer>
      </div>
    </div>
  );
}
