# CyberThreat AI System — Architecture Specification

## Project Title
**Threat Evolution Modeling for Online and Offline Cybersecurity Monitoring Using Behavioral Digital Twins and Temporal Knowledge Graphs**

---

## 1. System Architecture Overview

```
                      React 19 + Electron Frontend
                                   |
                                   | REST API (HTTP / JSON)
                                   ↓
                         FastAPI Python Backend
                                   |
      ┌────────────────────────────┼────────────────────────────┐
      ↓                            ↓                            ↓
  SQLite Database            ML Pipeline                   Sync Engine
  (Persistent Storage)             |                     (Online/Offline)
      |                            ↓                            |
      |                 Behavioral Digital Twin                 |
      |                            ↓                            |
      |                 Behavioral Drift Engine                 |
      |                            ↓                            |
      |                  Threat Risk Engine                     |
      |                 R(t)=0.4A+0.4B+0.2H                     |
      |                                                         |
      └────────────────────────────┬────────────────────────────┘
                                   ↓
                       Temporal Knowledge Graph
                             (NetworkX)
                                   ↓
                       Incident Reconstruction
                                   ↓
                           What Changed?
                                   ↓
                         Contribution Analysis
                                   ↓
                       Adaptive Response Engine
                                   ↓
                     Grounded AI Investigator
                                   ↓
                         React SOC Dashboard
```

---

## 2. Core Subsystems & Components

### 2.1 Telemetry Event Pipeline
- **Common Event Model**: Standardized schema across `event_id`, `device_id`, `user_id`, `timestamp`, `event_type`, `features`, `anomaly_score`, `behavioral_drift`, `risk_score`, `sync_status`.
- **Feature Extraction**: 8-dimensional numerical feature encoding (`login_hour_norm`, `is_known_device`, `is_known_app`, `session_duration_norm`, `is_known_dest`, `is_business_hours`, `bytes_sent_norm`, `event_type_encoded`).

### 2.2 ML Anomaly Detection (Isolation Forest)
- **Model**: `scikit-learn` Isolation Forest (`n_estimators=100`, `contamination=0.15`).
- **Score Normalization**: Uncalibrated decision function transformed into normalized $[0, 100]$ anomaly scale $A(t)$.
- **Research Honesty**: Output is transparently labeled as a statistical anomaly score rather than a calibrated posterior probability.

### 2.3 Behavioral Digital Twin
- **Baseline Profiling**: Continuously learns user and device normative operational footprints (login hours, known device IDs, common binaries/applications, typical session durations, network egress endpoints).
- **Behavioral Drift $B(t)$**: Quantifies deviation across 5 core dimensions, normalized $[0, 100]$.

### 2.4 Threat Risk Evolution Engine
- **Formula**:
  $$R(t) = 0.4 \cdot A(t) + 0.4 \cdot B(t) + 0.2 \cdot H(t)$$
  - $A(t)$: Isolation Forest anomaly component ($0-100$)
  - $B(t)$: Behavioral Digital Twin drift component ($0-100$)
  - $H(t)$: Historical risk baseline with exponential moving average decay ($0-100$)

### 2.5 Resilient Online/Offline Synchronization Engine
- **Local Queueing**: Seamlessly enqueues telemetry in local SQLite queue during network partitions.
- **Idempotent Synchronization**: Deduplicates incoming batches using primary `event_id`.
- **Timestamp Integrity**: Preserves original device generation timestamp alongside server synchronization timestamp.

### 2.6 Temporal Knowledge Graph
- **Graph Schema**: Directed multi-graph built with NetworkX containing entities (`User`, `Device`, `Session`, `Application`, `NetworkEntity`, `Event`, `Incident`) and temporal relationships (`USES`, `CREATES`, `LAUNCHES`, `CONNECTS_TO`, `GENERATES`, `FOLLOWS`, `CONTRIBUTES_TO`).

### 2.7 Incident Reconstruction & Differential Analysis
- **Temporal Correlation**: Groups related anomalies by entity co-occurrence and sliding temporal proximity windows rather than isolated static thresholds.
- **"What Changed?" Analysis**: Evaluates explicit delta between current attack indicators and learned digital twin baselines.
- **Estimated Event Contribution**: Ranks events as `Low`, `Medium`, or `High` contribution without claiming unproven physical causality.

### 2.8 Adaptive Response & Grounded AI Investigator
- **Adaptive Response**: Multi-tiered policy recommendations ($0-30$: Monitor, $31-60$: Elevate Monitoring, $61-80$: Require MFA, $81-100$: Isolate Session).
- **Grounded AI Investigator**: 100% deterministic local fallback that reasons exclusively over structured backend evidence to avoid hallucinations.
