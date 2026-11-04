"""
Pydantic Schemas for CyberThreat AI System API.
"""

from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field
from datetime import datetime


class TelemetryEventCreate(BaseModel):
    event_id: Optional[str] = None
    device_id: str
    user_id: str
    timestamp: Optional[str] = None
    event_type: str
    features: Dict[str, Any] = Field(default_factory=dict)
    detection_source: str = "local_agent"


class TelemetryEventResponse(BaseModel):
    event_id: str
    device_id: str
    user_id: str
    timestamp: str
    event_type: str
    features: Dict[str, Any]
    anomaly_score: float
    raw_ml_score: float
    behavioral_drift: float
    drift_factors: Dict[str, Any]
    risk_score: float
    historical_risk: float
    detection_source: str
    sync_status: str
    created_at: str
    synchronized_at: Optional[str] = None


class BatchEventIngest(BaseModel):
    events: List[TelemetryEventCreate]


class SyncRequest(BaseModel):
    events: List[Dict[str, Any]]
    device_id: str


class SyncResponse(BaseModel):
    status: str
    received_count: int
    processed_count: int
    duplicate_count: int
    failed_count: int
    server_time: str


class RiskOverview(BaseModel):
    current_risk_score: float
    risk_level: str
    anomaly_component: float
    behavioral_drift_component: float
    historical_risk_component: float
    formula: str = "R(t) = 0.4*A(t) + 0.4*B(t) + 0.2*H(t)"
    total_events: int
    total_anomalies: int
    active_incidents: int
    online_status: bool
    last_updated: str


class GraphNode(BaseModel):
    id: str
    label: str
    type: str
    properties: Dict[str, Any] = Field(default_factory=dict)


class GraphEdge(BaseModel):
    id: str
    source: str
    target: str
    relationship: str
    timestamp: Optional[str] = None
    properties: Dict[str, Any] = Field(default_factory=dict)


class KnowledgeGraphResponse(BaseModel):
    nodes: List[GraphNode]
    edges: List[GraphEdge]
    stats: Dict[str, int]


class ContributingEvent(BaseModel):
    event_id: str
    event_type: str
    timestamp: str
    risk_score: float
    anomaly_score: float
    behavioral_drift: float
    estimated_contribution: str  # "Low", "Medium", "High"
    contribution_score: float
    reason: str


class IncidentResponse(BaseModel):
    incident_id: str
    title: str
    severity: str
    status: str
    affected_user: str
    affected_devices: List[str]
    start_time: str
    end_time: str
    event_count: int
    ordered_events: List[Dict[str, Any]]
    applications: List[str]
    network_entities: List[str]
    risk_evolution: List[Dict[str, Any]]
    major_contributing_events: List[ContributingEvent]
    confidence: float
    summary: str


class WhatChangedResponse(BaseModel):
    user_id: str
    baseline_established: bool
    deviations: List[Dict[str, Any]]
    summary: str
    analysis_time: str


class AdaptiveResponseRecommendation(BaseModel):
    risk_score: float
    recommended_action: str
    action_type: str  # "MONITOR", "ELEVATE_MONITORING", "REQUIRE_MFA", "RESTRICT_SESSION", "ISOLATE_HOST"
    policy_tier: str
    rationale: str
    confidence: float
    is_automated_executable: bool
    audit_notes: str


class InvestigatorQuery(BaseModel):
    query: str
    incident_id: Optional[str] = None
    user_id: Optional[str] = None


class InvestigatorResponse(BaseModel):
    query: str
    answer: str
    grounded_evidence: Dict[str, Any]
    confidence: str
    mode: str  # "deterministic_fallback" or "llm_enhanced"
