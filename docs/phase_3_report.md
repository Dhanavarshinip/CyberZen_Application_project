# Phase 3 Report — Online/Offline Sync, Graph & Incident Reconstruction

## Implementation Summary
- **Online/Offline Sync Engine**: `backend/sync/engine.py` with SQLite local queueing, idempotency checks, deduplication, and retry state machine.
- **Temporal Knowledge Graph**: `backend/knowledge_graph/graph.py` using NetworkX with nodes (`User`, `Device`, `Session`, `Application`, `NetworkEntity`, `Event`, `Incident`) and temporal edges (`FOLLOWS`, `GENERATES`, `CONTRIBUTES_TO`).
- **Incident Reconstruction**: `backend/incident_engine/reconstructor.py` correlates events via temporal sliding windows and entity co-occurrence.
- **Differential Analysis**: `backend/incident_engine/what_changed.py` and `backend/incident_engine/contribution.py` evaluate baseline divergence and relative event attribution.
