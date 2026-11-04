// Knowledge Graph & Incident Reconstruction Engine

export class KnowledgeGraphEngine {
  /**
   * Generates graph nodes and directed links based on active entities and telemetry stream events
   */
  static buildGraph(entities, events) {
    const nodesMap = new Map();
    const links = [];

    // Add User Nodes
    entities.users.forEach(u => {
      nodesMap.set(u.id, {
        id: u.id,
        label: u.name,
        type: "USER",
        subtext: u.role,
        status: "normal",
        risk: u.baselineRisk
      });
    });

    // Add Device Nodes
    entities.devices.forEach(d => {
      nodesMap.set(d.id, {
        id: d.id,
        label: d.type,
        type: "DEVICE",
        subtext: d.ip,
        status: "normal",
        risk: 10
      });

      // Link User -> Device
      if (nodesMap.has(d.owner)) {
        links.push({ source: d.owner, target: d.id, relation: "OWNS_DEVICE" });
      }
    });

    // Add Application Nodes
    entities.applications.forEach(a => {
      nodesMap.set(a.id, {
        id: a.id,
        label: a.name,
        type: "APPLICATION",
        subtext: `Port ${a.port}`,
        status: "normal",
        risk: a.tier === "Critical" ? 30 : 10
      });
    });

    // Process Events to inject dynamic Network/Unregistered nodes & dynamic links
    events.forEach(evt => {
      // Flag user node if critical
      if (evt.user && nodesMap.has(evt.user)) {
        const uNode = nodesMap.get(evt.user);
        if (evt.severity === "critical" || evt.anomalyScore > 0.8) {
          uNode.status = "compromised";
          uNode.risk = Math.max(uNode.risk, Math.round(evt.anomalyScore * 100));
        } else if (evt.severity === "high" && uNode.status !== "compromised") {
          uNode.status = "suspicious";
          uNode.risk = Math.max(uNode.risk, 60);
        }
      }

      // Dynamic Network IP node
      if (evt.ip && !nodesMap.has(evt.ip)) {
        nodesMap.set(evt.ip, {
          id: evt.ip,
          label: evt.ip,
          type: "NETWORK_IP",
          subtext: evt.location || "Remote IP",
          status: evt.ip.includes("Tor") || evt.ip.includes("C2") || evt.anomalyScore > 0.8 ? "compromised" : "suspicious",
          risk: Math.round(evt.anomalyScore * 100)
        });
      }

      // Link User/Device -> App / IP
      if (evt.user && evt.app && nodesMap.has(evt.user) && nodesMap.has(evt.app)) {
        links.push({
          source: evt.user,
          target: evt.app,
          relation: evt.type,
          severity: evt.severity,
          timestamp: evt.timestamp
        });
      }

      if (evt.device && evt.ip && nodesMap.has(evt.device) && nodesMap.has(evt.ip)) {
        links.push({
          source: evt.device,
          target: evt.ip,
          relation: "NETWORK_STREAM",
          severity: evt.severity,
          timestamp: evt.timestamp
        });
      }
    });

    return {
      nodes: Array.from(nodesMap.values()),
      links: links
    };
  }

  /**
   * Reconstructs chronological incident timeline and identifies Patient Zero
   */
  static reconstructIncident(events) {
    if (!events || events.length === 0) {
      return {
        patientZero: null,
        affectedEntities: [],
        timeline: [],
        blastRadiusScore: 0
      };
    }

    // Filter anomalous events
    const anomalousEvents = events.filter(e => e.anomalyScore > 0.4 || e.severity === "high" || e.severity === "critical");
    
    // Patient zero is earliest anomalous event
    const patientZero = anomalousEvents.length > 0 ? anomalousEvents[0] : events[0];

    // Collect affected entity IDs
    const affectedSet = new Set();
    anomalousEvents.forEach(e => {
      if (e.user) affectedSet.add(e.user);
      if (e.device) affectedSet.add(e.device);
      if (e.app) affectedSet.add(e.app);
      if (e.ip) affectedSet.add(e.ip);
    });

    // Calculate Blast Radius
    const totalCoreAssets = 12; // Standard asset count baseline
    const blastRadiusScore = Math.min(100, Math.round((affectedSet.size / totalCoreAssets) * 100));

    return {
      patientZero,
      affectedEntitiesCount: affectedSet.size,
      affectedEntityIds: Array.from(affectedSet),
      timeline: events,
      blastRadiusScore
    };
  }
}
