# CyberThreat AI System

> **Threat Evolution Modeling for Online and Offline Cybersecurity Monitoring Using Behavioral Digital Twins and Temporal Knowledge Graphs**

An end-to-end cybersecurity research platform and Security Operations Center (SOC) dashboard. The system treats cybersecurity threats as evolving behavioral states across multi-stage lifecycles rather than isolated suspicious alerts.

---

## Architecture

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

## Key Capabilities

1. **Isolation Forest Anomaly Detection**: Unsupervised statistical anomaly detection on multi-dimensional telemetry feature vectors.
2. **Behavioral Digital Twin**: Continuous user/device baseline learning and transparent drift calculation $B(t) \in [0, 100]$.
3. **Threat Risk Evolution Engine**: Composite risk scoring formula:
   $$R(t) = 0.4 \cdot A(t) + 0.4 \cdot B(t) + 0.2 \cdot H(t)$$
4. **Online/Offline Resilient Sync Engine**: Local SQLite event queueing, idempotency checks, deduplication, and zero event loss during network interruptions.
5. **Temporal Knowledge Graph**: Dynamic NetworkX entity-relationship model linking Users, Devices, Sessions, Applications, Network Entities, Events, and Incidents with temporal sequencing.
6. **Incident Reconstruction & "What Changed?"**: Sliding window temporal correlation, structural baseline delta analysis, and estimated event contribution ranking.
7. **Adaptive Response Engine**: Multi-tiered mitigative recommendations ($0-30$: Monitor, $31-60$: Elevate Monitoring, $61-80$: Require MFA, $81-100$: Isolate Session).
8. **Grounded AI Investigator**: 100% deterministic local investigator fallback that reasons strictly over structured database evidence without hallucination.
9. **Research Experiment Framework**: 5 reproducible empirical experiments evaluating detection accuracy, drift anchoring, graph clustering, sync resilience, and threat trajectory.

---

## Quick Start Guide (Windows)

### 1. Prerequisites
- Python 3.10+ (Python 3.14 compatible)
- Node.js 18+ and npm

### 2. Backend Setup
```powershell
# In project root directory:
pip install -r requirements.txt
pip install pytest pytest-asyncio httpx

# Start FastAPI Backend:
python -m uvicorn backend.main:app --reload --host 127.0.0.1 --port 8000
```
Backend API will be live at `http://127.0.0.1:8000` with interactive Swagger docs at `http://127.0.0.1:8000/docs`.

### 3. Frontend Setup
```powershell
# In a new terminal:
npm install
npm run dev
```
React SOC Dashboard will be accessible at `http://localhost:5173`.

### 4. Running Desktop Electron App (Optional)
```powershell
npm run electron:dev
```

---

## Automated Testing & Research Experiments

### Run Backend & Integration Tests
```powershell
python -m pytest tests/ -v
```
*(Runs 22 comprehensive unit and end-to-end integration tests).*

### Execute Research Experiments
```powershell
python -m experiments.run_experiments
```
*(Executes all 5 research experiments and generates `experiments/results.json`).*

---

## Research Documentation

Comprehensive research documentation is located in the `docs/` folder:
- [docs/architecture.md](docs/architecture.md) — Detailed system architecture and subcomponent design.
- [docs/research_experiments.md](docs/research_experiments.md) — Empirical methodology and experiment benchmark results.
- [docs/limitations.md](docs/limitations.md) — Research boundaries, assumptions, and engineering disclosures.
- [docs/phase_1_report.md](docs/phase_1_report.md) — Phase 1 progress report.
- [docs/phase_2_report.md](docs/phase_2_report.md) — Phase 2 progress report.
- [docs/phase_3_report.md](docs/phase_3_report.md) — Phase 3 progress report.
- [docs/phase_4_report.md](docs/phase_4_report.md) — Phase 4 progress report.
