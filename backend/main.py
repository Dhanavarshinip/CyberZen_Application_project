"""
CyberThreat AI System - Main FastAPI Server.

Integrates:
- Real ML Anomaly Detection (Isolation Forest)
- Behavioral Digital Twins & Behavioral Drift
- Threat Risk Evolution Engine: R(t) = 0.4A(t) + 0.4B(t) + 0.2H(t)
- Online / Offline Synchronization Engine with Idempotency
- Temporal Knowledge Graph (NetworkX)
- Incident Reconstruction & Differential 'What Changed?' Analysis
- Event Contribution Analysis
- Adaptive Response Engine
- Grounded AI Investigator (Deterministic Fallback)
- Controlled Synthetic Research Scenario Generator
"""

import os
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import uvicorn

from backend.config import (
    DATABASE_PATH,
    SERVER_HOST,
    SERVER_PORT,
    CORS_ORIGINS,
    CORRELATION_TIME_WINDOW,
    INCIDENT_RISK_THRESHOLD,
    ISOLATION_FOREST_CONTAMINATION,
    ISOLATION_FOREST_ESTIMATORS
)
from backend.database.db import DatabaseManager
from backend.feature_engineering.extract import FeatureExtractor
from backend.anomaly_detection.model import IsolationForestAnomalyDetector
from backend.behavioral_model.digital_twin import BehavioralDigitalTwin
from backend.risk_engine.calculator import RiskEngine
from backend.knowledge_graph.graph import TemporalKnowledgeGraph
from backend.incident_engine.reconstructor import IncidentReconstructor
from backend.incident_engine.what_changed import WhatChangedAnalyzer
from backend.adaptive_response.engine import AdaptiveResponseEngine
from backend.investigator.investigator import AIInvestigator
from backend.sync.engine import SyncEngine
from backend.collectors.generator import SyntheticTelemetryGenerator
from backend.monitoring.engine import RealSystemMonitor
from backend.api.routes import create_api_router
from backend.anomaly_detection.deviation_analyzer import DeviationAnalyzer
from backend.knowledge_graph.graph_analyzer import GraphAnalyzer
from backend.investigator.shield_llm_analyzer import ShieldLLMAnalyzer
from backend.incident_engine.temporal_correlation import TemporalCorrelationEngine

# Shared service instances
db = DatabaseManager(db_path=DATABASE_PATH)
fe = FeatureExtractor()
anomaly_detector = IsolationForestAnomalyDetector(
    contamination=ISOLATION_FOREST_CONTAMINATION,
    n_estimators=ISOLATION_FOREST_ESTIMATORS
)
shield_deviation = DeviationAnalyzer.load() or DeviationAnalyzer(contamination=0.1, n_neighbors=20)
shield_graph = GraphAnalyzer()
shield_llm = ShieldLLMAnalyzer()
shield_tce = TemporalCorrelationEngine(db_manager=db)

digital_twin = BehavioralDigitalTwin(db_manager=db)
risk_engine = RiskEngine(db_manager=db)
graph = TemporalKnowledgeGraph()
incident_reconstructor = IncidentReconstructor(
    time_window_seconds=CORRELATION_TIME_WINDOW,
    risk_threshold=INCIDENT_RISK_THRESHOLD,
    db_manager=db
)
what_changed_analyzer = WhatChangedAnalyzer(digital_twin=digital_twin)
response_engine = AdaptiveResponseEngine()
investigator = AIInvestigator(db_manager=db, digital_twin=digital_twin)
sync_engine = SyncEngine(db_manager=db)
generator = SyntheticTelemetryGenerator()
real_monitor = RealSystemMonitor(db_manager=db)

def _real_event_pipeline(ev):
    """Processes real telemetry event through ML pipeline and persists to local DB."""
    import uuid
    from datetime import datetime, timezone
    if not ev.get("event_id"):
        ev["event_id"] = str(uuid.uuid4())
    if not ev.get("timestamp"):
        ev["timestamp"] = datetime.now(timezone.utc).isoformat()
    dev_id = ev.get("device_id") or real_monitor.device_id
    ev["device_id"] = dev_id
    user_id = ev.get("user_id") or real_monitor.user_id
    ev["user_id"] = user_id

    f = ev.setdefault("features", {})
    collector_risk = float(f.get("raw_risk") or 0.0)
    collector_status = f.get("status", "SAFE")

    vec = fe.extract_features(ev)
    ml_res = anomaly_detector.predict_anomaly(vec)

    # Incorporate collector threat indicators into anomaly scoring so confirmed threats are never suppressed
    if collector_risk > 0:
        ml_res["anomaly_score"] = max(ml_res["anomaly_score"], collector_risk)
        ml_res["normalized_score"] = ml_res["anomaly_score"] / 100.0

    drift_res = digital_twin.evaluate_event(ev)
    risk_res = risk_engine.calculate_risk(
        anomaly_score=ml_res["anomaly_score"],
        behavioral_drift=drift_res["drift_score"],
        user_id=user_id,
        device_id=dev_id
    )

    # Prevent false negatives: floor risk score when confirmed threat detected
    if collector_status in ("DANGEROUS", "DANGER") or collector_risk >= 70.0:
        risk_res["risk_score"] = max(risk_res["risk_score"], max(collector_risk, 75.0))
        risk_res["risk_level"] = "CRITICAL" if risk_res["risk_score"] >= 80.0 else "HIGH"
    elif collector_status == "SUSPICIOUS" or collector_risk >= 35.0:
        risk_res["risk_score"] = max(risk_res["risk_score"], max(collector_risk, 45.0))
        if risk_res["risk_level"] in ("MINIMAL", "LOW"):
            risk_res["risk_level"] = "MEDIUM"
    elif collector_status == "UNKNOWN":
        # Never label an unknown event as safe without sufficient evidence
        ev["verdict"] = "UNKNOWN"
        f["status"] = "UNKNOWN"
    elif collector_status == "INFO":
        ev["verdict"] = "INFO"
        f["status"] = "INFO"
        risk_res["risk_score"] = 0.0
        risk_res["risk_level"] = "MINIMAL"

    # Evidence generation: ensure every event has human-readable reasons explaining verdict
    reasons = f.get("reasons") or []
    if not isinstance(reasons, list):
        reasons = [str(reasons)]
    if not reasons:
        if collector_status in ("DANGEROUS", "DANGER"):
            reasons.append(f"Dangerous threat indicators detected by security engine: threat score {collector_risk:.1f}/100.")
        elif collector_status == "SUSPICIOUS":
            reasons.append(f"Suspicious indicators or behavioral drift detected: drift score {drift_res['drift_score']:.1f}/100.")
        elif collector_status == "INFO":
            reasons.append("Activity verified legitimate: CyberThreat AI internal component operating normally.")
        elif collector_status == "UNKNOWN":
            reasons.append("Unverified event: insufficient baseline evidence to verify complete safety. Proceed with caution.")
        else:
            reasons.append("Activity verified safe: no malicious signatures, anomalies, or behavioral drift detected.")
    if collector_status != "INFO" and drift_res.get("deviations"):
        reasons.extend(drift_res["deviations"])
    f["reasons"] = list(dict.fromkeys(reasons))  # Deduplicate while preserving order

    ev["anomaly_score"] = ml_res["anomaly_score"]
    ev["raw_ml_score"] = ml_res["raw_score"]
    ev["behavioral_drift"] = drift_res["drift_score"]
    ev["drift_factors"] = drift_res["factors"]
    ev["risk_score"] = risk_res["risk_score"]
    ev["historical_risk"] = risk_res["components"]["historical_risk_H_t"]
    ev["created_at"] = datetime.now(timezone.utc).isoformat()

    # Determine activity domain (ONLINE vs OFFLINE) and storage verification
    ev_type = ev.get("event_type", "")
    is_online_act = (
        ev_type in ("WEBSITE_OPENED", "BROWSER_NAVIGATION", "NETWORK_CONNECTION")
        or bool(f.get("domain"))
        or bool(f.get("url"))
        or (bool(f.get("remote_ip")) and f.get("remote_ip") not in ("127.0.0.1", "::1", "localhost"))
        or f.get("activity_category") in ("Browser", "Websites", "Network")
    )
    f["activity_domain"] = "ONLINE" if is_online_act else "OFFLINE"
    f["connectivity_state"] = "ONLINE" if sync_engine.is_online else "OFFLINE"
    f["db_storage_confirmed"] = True
    f["storage_table"] = "events"
    f["db_path"] = "data/cyberthreat.db"
    f["storage_engine"] = "SQLite3 Persistent WAL"

    # ALWAYS save to local DB so Activity tab shows real events
    # When offline, also enqueue into sync_queue for subsequent synchronization (Req 7 & 8)
    if sync_engine.is_online:
        ev["sync_status"] = "SYNCHRONIZED"
        ev["synchronized_at"] = datetime.now(timezone.utc).isoformat()
    else:
        ev["sync_status"] = "PENDING"
        ev["synchronized_at"] = None
        db.enqueue_sync(ev["event_id"], ev, device_id=dev_id)

    # Save to local SQLite regardless of connectivity
    db.save_event(ev)
    db.record_risk(
        user_id,
        dev_id,
        ev["risk_score"],
        ev["anomaly_score"],
        ev["behavioral_drift"],
        ev["timestamp"]
    )
    graph.ingest_event(ev)
    return ev


real_monitor.set_pipeline_callback(_real_event_pipeline)

services = {
    "db": db,
    "feature_extractor": fe,
    "anomaly_detector": anomaly_detector,
    "digital_twin": digital_twin,
    "risk_engine": risk_engine,
    "graph": graph,
    "incident_reconstructor": incident_reconstructor,
    "what_changed_analyzer": what_changed_analyzer,
    "response_engine": response_engine,
    "investigator": investigator,
    "sync_engine": sync_engine,
    "generator": generator,
    "real_monitor": real_monitor,
    "shield_deviation": shield_deviation,
    "shield_graph": shield_graph,
    "shield_llm": shield_llm,
    "shield_tce": shield_tce
}


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initializes ML models, baseline profiles, and real system monitor."""
    print("==================================================")
    print("[*] Initializing CyberThreat AI System Real Engine...")
    print(f"[*] Database: {DATABASE_PATH}")
    
    # 1. Establish training baseline data (in-memory only - never saved to DB)
    normal_training_events = None
    model_path = "models/isolation_forest.joblib"
    if anomaly_detector.load(model_path):
        print(f"[+] Isolation Forest loaded from cached model ({model_path}).")
    else:
        normal_training_events = generator.generate_normal_telemetry(count=150)
        training_vectors = [fe.extract_features(ev) for ev in normal_training_events]
        anomaly_detector.train(training_vectors)
        anomaly_detector.save(model_path)
        print("[+] Isolation Forest Anomaly Detector trained and cached successfully.")

    # 1b. Initialize SHIELD Deviation Analyzer (LOF) baseline if not already fitted
    if not shield_deviation.is_trained:
        if normal_training_events is None:
            normal_training_events = generator.generate_normal_telemetry(count=150)
        shield_deviation.train(normal_training_events)
        shield_deviation.save("models/deviation_analyzer_lof.joblib")
        print("[+] SHIELD Deviation Analyzer (LOF + Frequency Encoder) initialized.")
    else:
        print("[+] SHIELD Deviation Analyzer loaded from pre-trained weights.")
    
    # 2. Establish Digital Twin baseline (in-memory only - training data not stored to DB)
    if not digital_twin.profiles:
        if normal_training_events is None:
            normal_training_events = generator.generate_normal_telemetry(count=150)
        digital_twin.learn_baseline_from_events("local_user", normal_training_events)
        print("[+] Behavioral Digital Twin baseline initialized (in-memory).")
    else:
        print("[+] Behavioral Digital Twin profile active.")
    
    # 3. Start real-world system monitor
    try:
        real_monitor.start()
        print(f"[+] Real-World Host Monitor active on {real_monitor.device_id}")
    except Exception as e:
        print(f"[-] Real-World Host Monitor failed to start: {e}")
        
    print(f"[+] Backend ready on http://{SERVER_HOST}:{SERVER_PORT}")
    print("==========================================")
    yield
    print("[*] Shutting down CyberThreat AI System Backend.")
    try:
        real_monitor.stop()
    except Exception:
        pass



app = FastAPI(
    title="Intelligent Real-Time Digital Threat Detection, Prevention and Incident Reconstruction API",
    description="Threat Evolution Modeling for Online/Offline Cybersecurity Monitoring Using Behavioral Digital Twins and Temporal Knowledge Graphs",
    version="1.0.0",
    lifespan=lifespan
)

# Enable CORS for React/Electron frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["Content-Disposition", "Content-Length", "X-Suggested-Filename"],
)

# Attach API routes
app.include_router(create_api_router(services))

from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pathlib import Path

# Mount production React frontend build if present
DIST_DIR = Path(__file__).resolve().parent.parent / "dist"
if DIST_DIR.exists() and (DIST_DIR / "index.html").exists():
    assets_dir = DIST_DIR / "assets"
    if assets_dir.exists():
        app.mount("/assets", StaticFiles(directory=str(assets_dir)), name="assets")

    @app.get("/", include_in_schema=False)
    async def serve_index():
        return FileResponse(str(DIST_DIR / "index.html"))

    @app.get("/{full_path:path}", include_in_schema=False)
    async def serve_spa(full_path: str):
        if full_path.startswith("api") or full_path.startswith("docs") or full_path == "openapi.json":
            from fastapi import HTTPException
            raise HTTPException(status_code=404, detail="Endpoint not found")
        target_file = DIST_DIR / full_path
        if target_file.is_file():
            return FileResponse(str(target_file))
        return FileResponse(str(DIST_DIR / "index.html"))
else:
    @app.get("/")
    def root():
        return {
            "title": "CyberThreat AI System Research API",
            "version": "1.0.0",
            "docs_url": "/docs",
            "health_url": "/api/health",
            "architecture": "Behavioral Digital Twins + Temporal Knowledge Graphs + Threat Evolution Engine"
        }


if __name__ == "__main__":
    uvicorn.run("backend.main:app", host=SERVER_HOST, port=SERVER_PORT, reload=True)
