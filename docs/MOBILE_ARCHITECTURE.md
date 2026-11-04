# Mobile Threat Detection & Prevention Architecture

## Overview

CyberThreat AI's official project — **Intelligent Real-Time Digital Threat Detection, Prevention and Incident Reconstruction** — is engineered with a modular telemetry pipeline. This document details the technical strategy, OS-level collector boundaries, background execution constraints, and architectural scaffolding for extending endpoint monitoring to mobile platforms (Android & iOS).

---

## 1. Operating System Sandboxing & Technical Constraints

Unlike desktop operating systems (Windows, Linux, macOS) where agent services can inspect kernel events, raw process memory, and cross-process network sockets via APIs like ETW, eBPF, or `psutil`, mobile platforms enforce strict hardware and software sandbox boundaries:

### Android Sandbox & Permissions
- **Process Isolation**: Each Android application executes within its own Linux UID sandbox (`Zygote` fork). An app cannot read `/proc` files or observe process tables of other apps without root (`su`) or enterprise Device Policy Controller (`DPC`) privileges.
- **Network Telemetry**: Direct raw packet sniffing is prohibited. To observe network metadata and outbound connections, CyberThreat AI must deploy an Android **`VpnService`**. This intercepts IP packets locally, parses DNS queries, IP connections, and SNI headers without terminating user privacy or requiring device root.
- **Background Execution Limits**: Android's Doze Mode and App Standby Buckets restrict persistent background daemons. A persistent foreground service with a visible ongoing notification (`FOREGROUND_SERVICE_TYPE_SYSTEM_EXEMPTED` or `SPECIAL_USE`) is mandatory for real-time telemetry streaming.
- **Accessibility & Notification Telemetry**: Phishing, SMS fraud, and screen overlay attacks can be identified via `AccessibilityService` (requiring explicit user opt-in) and `NotificationListenerService`.

### iOS Sandbox & Security Model
- **Strict Isolation**: iOS applications run in a chroot-style sandbox container (`Data Protection` and `App Sandbox`). Reading running processes, system sockets, or file activity outside the app container is strictly prohibited by Apple App Store guidelines.
- **Network Telemetry**: iOS allows network monitoring via the **Network Extension framework (`NEPacketTunnelProvider` / `NEDNSProxyProvider`)**. This provides local loopback VPN interception to inspect malicious DNS requests and suspicious IP ranges.
- **Background Execution**: Persistent background execution is restricted. Real-time updates require **`BGAppRefreshTask`**, VoIP push notifications (for MDM-enrolled devices), or local PushKit triggers.

---

## 2. Target Mobile Architecture

```
                      ┌──────────────────────────────────────────────┐
                      │              Mobile Device                   │
                      │                                              │
                      │  ┌─────────────────┐   ┌──────────────────┐  │
                      │  │ Local VPN Svc   │   │ Foreground Agent │  │
                      │  │ (DNS/IP Meta)   │   │ (State & Battery)│  │
                      │  └────────┬────────┘   └────────┬─────────┘  │
                      │           │                     │            │
                      │           ▼                     ▼            │
                      │  ┌────────────────────────────────────────┐  │
                      │  │    Local Edge Buffer (Encrypted SQLite)│  │
                      │  └──────────────────┬─────────────────────┘  │
                      └─────────────────────┼────────────────────────┘
                                            │ HTTPS / WSS
                                            ▼
                      ┌──────────────────────────────────────────────┐
                      │       CyberThreat AI Cloud Backend           │
                      │                                              │
                      │  ┌─────────────────┐   ┌──────────────────┐  │
                      │  │ FastAPI Ingest  │──▶│ Isolation Forest │  │
                      │  └─────────────────┘   └────────┬─────────┘  │
                      │                                 ▼            │
                      │                        ┌──────────────────┐  │
                      │                        │ Digital Twin     │  │
                      │                        └──────────────────┘  │
                      └──────────────────────────────────────────────┘
```

---

## 3. Telemetry Event Mapping (Mobile to Core Engine)

Mobile events harmonize directly into the existing `telemetry_events` schema:

| Mobile Signal | Event Type | Target Data Captured | Risk Detection Scope |
| :--- | :--- | :--- | :--- |
| Local VPN DNS Resolution | `dns_request` | Domain name, resolved IP, query time, process name (Android) | C2 domain lookup, malicious phishing domains |
| Socket Outbound Connect | `network_connection` | Remote IP, remote port, protocol, data transferred | Rogue data exfiltration, port scanning |
| APK Sideload / Package Install | `package_installed` | Package name, SHA-256 digest, installer origin, requested permissions | Sideloaded malware, banking trojans |
| Screen Lock / Biometric Auth | `device_security` | Lock screen status, biometric failures, root/jailbreak detection flags | Unauthorized physical device access |
| WiFi Connection Change | `network_state` | SSID, BSSID, captive portal flag, encryption type | Rogue access points (Evil Twin attacks) |

---

## 4. Multi-Tenant Device Enrollment on Mobile

Device enrollment adheres strictly to the existing device isolation model:
1. Mobile user logs in using authenticated JWT token (`usr_...`).
2. Mobile client requests enrollment via `POST /api/devices/enroll`:
   - Generates hardware fingerprint: Hardware UUID + Secure Android ID / iOS IDFV.
   - Enrolls device type: `android` or `ios`.
3. Backend issues unique device identifier (`DEVICE_M_...`) and pre-shared secret key (`dk_...`).
4. Secret key is securely written to the device hardware keystore:
   - **Android**: `AndroidKeyStore` with AES-256 GCM encryption.
   - **iOS**: `Keychain Services` with `kSecAttrAccessibleAfterFirstUnlock`.
5. Device isolation prevents cross-account telemetry pollution or account takeover.

---

## 5. Implementation Roadmap & Phases

- **Phase A**: Flutter / React Native cross-platform scaffold with local encrypted SQLite event queue.
- **Phase B**: Native Android Kotlin `VpnService` module for domain threat categorization.
- **Phase C**: Native iOS Swift `NetworkExtension` tunnel provider module.
- **Phase D**: Offline queue synchronizer with back-off retry logic connecting to `/api/telemetry/events`.
