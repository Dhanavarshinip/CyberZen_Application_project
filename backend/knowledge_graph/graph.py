"""
Temporal Knowledge Graph for CyberThreat AI System.

Constructs and manages a temporal graph representation of cybersecurity entities:
- Entities: User, Device, Session, Application, NetworkEntity (IP/Domain), Event, Incident
- Relationships:
  - User USES Device
  - User CREATES Session
  - Session LAUNCHES Application
  - Application CONNECTS_TO NetworkEntity
  - Device GENERATES Event
  - Event FOLLOWS Event (Temporal sequencing)
  - Event CONTRIBUTES_TO Incident
  - Event ASSOCIATED_WITH User
  - Event ASSOCIATED_WITH Device

Uses NetworkX for in-memory graph operations and topological / temporal analysis.
"""

from typing import Dict, Any, List, Optional, Set, Tuple
import networkx as nx
from datetime import datetime


class TemporalKnowledgeGraph:
    """
    Manages a directed multi-entity temporal knowledge graph.
    """
    
    def __init__(self):
        self.graph = nx.MultiDiGraph()
        
    def clear(self):
        """Resets the graph."""
        self.graph.clear()
        
    def add_user_node(self, user_id: str, properties: Optional[Dict[str, Any]] = None):
        node_id = f"user:{user_id}"
        props = dict(properties or {})
        for k in ("node_type", "name", "label"):
            props.pop(k, None)
        self.graph.add_node(
            node_id,
            node_type="User",
            name=user_id,
            label=f"User: {user_id}",
            **props
        )
        return node_id
        
    def add_device_node(self, device_id: str, properties: Optional[Dict[str, Any]] = None):
        node_id = f"device:{device_id}"
        props = dict(properties or {})
        for k in ("node_type", "name", "label"):
            props.pop(k, None)
        self.graph.add_node(
            node_id,
            node_type="Device",
            name=device_id,
            label=f"Device: {device_id}",
            **props
        )
        return node_id

    def add_session_node(self, session_id: str, user_id: str, device_id: str, timestamp: str, properties: Optional[Dict[str, Any]] = None):
        node_id = f"session:{session_id}"
        props = dict(properties or {})
        for k in ("node_type", "name", "label", "timestamp"):
            props.pop(k, None)
        self.graph.add_node(
            node_id,
            node_type="Session",
            name=session_id,
            label=f"Session: {session_id[:8]}",
            timestamp=timestamp,
            **props
        )
        # Link user and device to session
        user_node = self.add_user_node(user_id)
        device_node = self.add_device_node(device_id)
        
        self.graph.add_edge(user_node, node_id, key="CREATES", relationship="CREATES", timestamp=timestamp)
        self.graph.add_edge(user_node, device_node, key="USES", relationship="USES", timestamp=timestamp)
        self.graph.add_edge(device_node, node_id, key="HOSTS", relationship="HOSTS", timestamp=timestamp)
        return node_id

    def add_app_node(self, app_name: str, properties: Optional[Dict[str, Any]] = None):
        node_id = f"app:{app_name}"
        props = dict(properties or {})
        for k in ("node_type", "name", "label"):
            props.pop(k, None)
        self.graph.add_node(
            node_id,
            node_type="Application",
            name=app_name,
            label=f"App: {app_name}",
            **props
        )
        return node_id

    def add_network_node(self, destination: str, properties: Optional[Dict[str, Any]] = None):
        node_id = f"net:{destination}"
        props = dict(properties or {})
        for k in ("node_type", "name", "label"):
            props.pop(k, None)
        self.graph.add_node(
            node_id,
            node_type="NetworkEntity",
            name=destination,
            label=f"Net: {destination}",
            **props
        )
        return node_id

    def add_incident_node(self, incident_id: str, severity: str, properties: Optional[Dict[str, Any]] = None):
        node_id = f"incident:{incident_id}"
        props = dict(properties or {})
        for k in ("node_type", "name", "label", "severity"):
            props.pop(k, None)
        self.graph.add_node(
            node_id,
            node_type="Incident",
            name=incident_id,
            label=f"Incident: {incident_id[:8]} ({severity})",
            severity=severity,
            **props
        )
        return node_id


    def ingest_event(self, event: Dict[str, Any], previous_event_id: Optional[str] = None):
        """
        Ingests a single telemetry event into the temporal knowledge graph,
        creating appropriate entities and relational temporal edges.
        """
        event_id = event.get("event_id")
        if not event_id:
            return
            
        event_node = f"event:{event_id}"
        from datetime import datetime, timezone
        ts = event.get("timestamp") or datetime.now(timezone.utc).isoformat()
        user_id = event.get("user_id", "unknown_user")
        device_id = event.get("device_id", "unknown_device")
        event_type = event.get("event_type", "generic")
        features = event.get("features", {})
        if isinstance(features, str):
            import json
            try:
                features = json.loads(features)
            except Exception:
                features = {}
                
        risk_score = float(event.get("risk_score", 0.0))
        anomaly_score = float(event.get("anomaly_score", 0.0))
        drift_score = float(event.get("behavioral_drift", 0.0))
        
        # Add event node
        self.graph.add_node(
            event_node,
            node_type="Event",
            event_id=event_id,
            name=event_type,
            label=f"Event: {event_type} (R:{risk_score:.0f})",
            timestamp=ts,
            risk_score=risk_score,
            anomaly_score=anomaly_score,
            behavioral_drift=drift_score,
            event_type=event_type,
            features=features
        )
        
        # User and Device nodes
        user_node = self.add_user_node(user_id)
        device_node = self.add_device_node(device_id)
        
        # Link Event to Device and User
        self.graph.add_edge(device_node, event_node, key="GENERATES", relationship="GENERATES", timestamp=ts)
        self.graph.add_edge(event_node, user_node, key="ASSOCIATED_WITH_USER", relationship="ASSOCIATED_WITH", timestamp=ts)
        self.graph.add_edge(event_node, device_node, key="ASSOCIATED_WITH_DEVICE", relationship="ASSOCIATED_WITH", timestamp=ts)
        
        # Link Session: guarantee Session node connects User -> Device -> Session
        session_id = features.get("session_id")
        if not session_id:
            session_id = f"sess_{user_id}_{device_id}_{ts[:10]}"
        sess_node = self.add_session_node(session_id, user_id, device_id, ts)
        self.graph.add_edge(sess_node, event_node, key="PRODUCES", relationship="PRODUCES", timestamp=ts)
            
        # Link Application if present
        app_name = features.get("app_name") or features.get("process_name") or features.get("display_name")
        if app_name:
            app_node = self.add_app_node(app_name)
            self.graph.add_edge(event_node, app_node, key="INVOKES", relationship="INVOKES", timestamp=ts)
            self.graph.add_edge(sess_node, app_node, key="LAUNCHES", relationship="LAUNCHES", timestamp=ts)
                
        # Link Network destination if present
        dest = features.get("destination_ip") or features.get("domain") or features.get("network_destination") or features.get("remote_ip")
        if dest:
            net_node = self.add_network_node(dest)
            self.graph.add_edge(event_node, net_node, key="TARGETS", relationship="TARGETS", timestamp=ts)
            if app_name:
                self.graph.add_edge(f"app:{app_name}", net_node, key="CONNECTS_TO", relationship="CONNECTS_TO", timestamp=ts)
                
        # Temporal sequencing edge: Event FOLLOWS Event
        if previous_event_id:
            prev_node = f"event:{previous_event_id}"
            if self.graph.has_node(prev_node):
                self.graph.add_edge(event_node, prev_node, key="FOLLOWS", relationship="FOLLOWS", timestamp=ts)

    def link_event_to_incident(self, event_id: str, incident_id: str, contribution: str = "Medium"):
        """Links an event node to an incident node with contribution weighting."""
        event_node = f"event:{event_id}"
        inc_node = f"incident:{incident_id}"
        if self.graph.has_node(event_node) and self.graph.has_node(inc_node):
            self.graph.add_edge(
                event_node,
                inc_node,
                key=f"CONTRIBUTES_TO_{incident_id}",
                relationship="CONTRIBUTES_TO",
                contribution=contribution
            )

    def get_incident_subgraph(self, incident_id: str) -> Dict[str, Any]:
        """
        Extracts the exact connected subgraph for an incident:
        User -> Device -> Application -> Session -> Network Entity -> Event -> Incident.
        """
        inc_node = f"incident:{incident_id}"
        if not self.graph.has_node(inc_node):
            return {"nodes": [], "edges": [], "incident_id": incident_id, "found": False}

        incident_nodes = {inc_node}
        # Find contributing events
        for u, v, data in self.graph.in_edges(inc_node, data=True):
            if data.get("relationship") == "CONTRIBUTES_TO" or "CONTRIBUTES_TO" in str(data.get("key", "")):
                incident_nodes.add(u)

        # Expand to connected entities (User, Device, Session, App, Network)
        expanded_nodes = set(incident_nodes)
        for ev_node in incident_nodes:
            if ev_node.startswith("event:"):
                # Outgoing and incoming neighbors for event
                for nbr in list(self.graph.successors(ev_node)) + list(self.graph.predecessors(ev_node)):
                    expanded_nodes.add(nbr)
                    # From session, add connected apps
                    if nbr.startswith("session:"):
                        for s_nbr in self.graph.successors(nbr):
                            expanded_nodes.add(s_nbr)
                    # From app, add connected network entities
                    if nbr.startswith("app:"):
                        for a_nbr in self.graph.successors(nbr):
                            expanded_nodes.add(a_nbr)

        sub = self.graph.subgraph(expanded_nodes)
        nodes = []
        for n, data in sub.nodes(data=True):
            nodes.append({
                "id": n,
                "label": data.get("label", n),
                "type": data.get("node_type", "Entity"),
                "name": data.get("name", n),
                "properties": {k: v for k, v in data.items() if k not in ("id", "label", "type", "name")}
            })

        edges = []
        edge_counter = 0
        for u, v, k, data in sub.edges(keys=True, data=True):
            edge_counter += 1
            edges.append({
                "id": f"sub_e_{edge_counter}",
                "source": u,
                "target": v,
                "relationship": data.get("relationship", str(k)),
                "timestamp": data.get("timestamp"),
                "properties": {pk: pv for pk, pv in data.items() if pk not in ("relationship", "timestamp")}
            })

        return {
            "incident_id": incident_id,
            "found": True,
            "nodes": nodes,
            "edges": edges,
            "total_nodes": len(nodes),
            "total_edges": len(edges)
        }

    def get_lateral_movement_analysis(self, incident_id: str) -> Dict[str, Any]:
        """
        Computes blast radius and lateral movement risk from the initial infection point.
        """
        sub_data = self.get_incident_subgraph(incident_id)
        if not sub_data.get("found"):
            return {
                "incident_id": incident_id,
                "lateral_movement_risk": "MINIMAL",
                "blast_radius_nodes": 0,
                "affected_instances": [],
                "clean_instances": [],
                "capabilities": [
                    "Map potential lateral movement from compromised nodes",
                    "Identify internal systems reachable after initial breach",
                    "Assess network segmentation effectiveness",
                    "Evaluate blast radius of public node compromise"
                ]
            }

        affected = []
        clean = []
        for n in sub_data["nodes"]:
            ntype = n["type"]
            props = n.get("properties", {})
            risk = float(props.get("risk_score", 0.0))
            if risk >= 35.0 or ntype in ("Incident", "Event") or "temp" in n["name"].lower():
                affected.append({"id": n["id"], "name": n["name"], "type": ntype, "status": "Affected", "risk_score": risk})
            else:
                clean.append({"id": n["id"], "name": n["name"], "type": ntype, "status": "Clean", "risk_score": risk})

        max_risk = max([a.get("risk_score", 0.0) for a in affected] or [0.0])
        risk_level = "CRITICAL" if max_risk >= 70 else ("HIGH" if max_risk >= 50 else "MEDIUM")

        return {
            "incident_id": incident_id,
            "lateral_movement_risk": risk_level,
            "blast_radius_nodes": len(sub_data["nodes"]),
            "affected_instances": affected,
            "clean_instances": clean,
            "current_cypher_query": self.generate_cypher_query(incident_id),
            "capabilities": [
                "Map potential lateral movement from compromised nodes",
                "Identify internal systems reachable after initial breach",
                "Assess network segmentation effectiveness",
                "Evaluate blast radius of public node compromise"
            ]
        }

    def generate_cypher_query(self, incident_id: str) -> str:
        """
        Generates executable Cypher query matching the reconstructed incident sequence.
        """
        return f"""-- Lateral Movement & Causal Attack Path for {incident_id}
-- Step 1: Trace initial ingress and compromised session
MATCH (u:User)-[:USES]->(d:Device)-[:RUNS]->(s:Session)-[:LAUNCHES]->(a:Application)
MATCH (e:Event)-[:CONTRIBUTES_TO]->(i:Incident {{id: "{incident_id}"}})
WHERE (s)-[:PRODUCES]->(e) OR (e)-[:INVOKES]->(a)
-- Step 2: Trace egress connections and blast radius
OPTIONAL MATCH (a)-[:CONNECTS_TO]->(net:NetworkEntity)
RETURN u.name AS user, d.name AS device, a.name AS application, net.name AS remote_endpoint, e.timestamp AS event_time, i.severity AS severity
ORDER BY e.timestamp ASC"""

    def explain_causal_sequence(self, incident_id: str) -> List[str]:
        """
        Reconstructs the chronological causal narrative explaining how events are connected.
        """
        sub_data = self.get_incident_subgraph(incident_id)
        if not sub_data.get("found"):
            return ["Incident node not found in temporal knowledge graph."]

        events = [n for n in sub_data["nodes"] if n["type"] == "Event"]
        events.sort(key=lambda x: x.get("properties", {}).get("timestamp", ""))

        explanations = []
        for idx, ev in enumerate(events, 1):
            ts = ev.get("properties", {}).get("timestamp", "Unknown time")
            etype = ev.get("name", "Event")
            risk = ev.get("properties", {}).get("risk_score", 0.0)
            features = ev.get("properties", {}).get("features", {})
            desc = features.get("description") or f"{etype} recorded"
            explanations.append(f"Step {idx} [{ts}]: {desc} (Risk: {risk:.0f}/100, Type: {etype})")

        return explanations

    def build_from_events(self, events: List[Dict[str, Any]], incidents: Optional[List[Dict[str, Any]]] = None):
        """
        Reconstructs the full graph from a list of chronologically sorted events and incidents.
        """
        self.clear()
        
        # Sort chronologically
        sorted_events = sorted(events, key=lambda x: x.get("timestamp", ""))
        
        prev_user_event: Dict[str, str] = {}
        for ev in sorted_events:
            user = ev.get("user_id", "default")
            prev_id = prev_user_event.get(user)
            self.ingest_event(ev, previous_event_id=prev_id)
            prev_user_event[user] = ev.get("event_id")
            
        if incidents:
            for inc in incidents:
                inc_id = inc.get("incident_id")
                sev = inc.get("severity", "MEDIUM")
                self.add_incident_node(inc_id, sev, properties=inc)
                
                for ev_id in inc.get("event_ids", []):
                    self.link_event_to_incident(ev_id, inc_id)

    def to_serializable_dict(self, max_nodes: int = 150) -> Dict[str, Any]:
        """
        Converts graph to frontend-friendly JSON structure with nodes and links.
        """
        nodes = []
        edges = []
        type_counts: Dict[str, int] = {}
        
        # Limit to most relevant / recent nodes if graph is very large
        all_nodes = list(self.graph.nodes(data=True))
        if len(all_nodes) > max_nodes:
            # Prioritize Incidents, high risk Events, and core entities
            def node_priority(n):
                data = n[1]
                ntype = data.get("node_type", "")
                if ntype == "Incident":
                    return 100
                if ntype == "Event":
                    return float(data.get("risk_score", 0))
                return 10
            all_nodes.sort(key=node_priority, reverse=True)
            selected_nodes = set([n[0] for n in all_nodes[:max_nodes]])
        else:
            selected_nodes = set(self.graph.nodes())
            
        for node_id, data in self.graph.nodes(data=True):
            if node_id not in selected_nodes:
                continue
            ntype = data.get("node_type", "Entity")
            type_counts[ntype] = type_counts.get(ntype, 0) + 1
            
            nodes.append({
                "id": node_id,
                "label": data.get("label", node_id),
                "type": ntype,
                "name": data.get("name", node_id),
                "properties": {k: v for k, v in data.items() if k not in ("id", "label", "type", "name")}
            })
            
        edge_id_counter = 0
        for u, v, k, data in self.graph.edges(keys=True, data=True):
            if u in selected_nodes and v in selected_nodes:
                edge_id_counter += 1
                edges.append({
                    "id": f"e_{edge_id_counter}_{k}",
                    "source": u,
                    "target": v,
                    "relationship": data.get("relationship", k),
                    "timestamp": data.get("timestamp"),
                    "properties": {pk: pv for pk, pv in data.items() if pk not in ("relationship", "timestamp")}
                })
                
        return {
            "nodes": nodes,
            "edges": edges,
            "stats": {
                "total_nodes": len(nodes),
                "total_edges": len(edges),
                **type_counts
            }
        }
