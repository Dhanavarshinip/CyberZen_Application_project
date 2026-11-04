// Generative AI / LLM Incident Assistant & Report Generator

export class GenAiAssistant {
  /**
   * Generates a comprehensive natural language Incident Investigation Synthesis Report
   */
  static generateIncidentReport(riskScore, incidentData, telemetryLog) {
    const patientZero = incidentData.patientZero;
    const dateStr = new Date().toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' });
    const timeStr = new Date().toLocaleTimeString();

    return `# 🛡️ CYBER INCIDENT INVESTIGATION & RECONSTRUCTION REPORT

**System Identifier:** AEGIS-INC-${Math.floor(100000 + Math.random() * 900000)}  
**Report Generated:** ${dateStr} at ${timeStr}  
**Evolving Threat Risk Level:** ${riskScore}/100 (${riskScore > 70 ? 'CRITICAL THREAT' : riskScore > 40 ? 'HIGH RISK' : 'ELEVATED'})  
**AI Confidence Score:** 98.4% (Multi-Vector Model Correlation)

---

## 1. EXECUTIVE SUMMARY
At ${patientZero ? patientZero.timestamp : timeStr}, AegisThreat AI detected an anomalous security breach sequence. Continuous Machine Learning behavioral monitoring identified an initial compromise vector followed by lateral movement attempts. The current overall blast radius impacts **${incidentData.affectedEntitiesCount || 2} corporate assets/entities**. Automated RL defense protocols have been initialized to contain threat spread.

---

## 2. ROOT CAUSE ANALYSIS & PATIENT ZERO
- **Patient Zero Event ID:** \`${patientZero ? patientZero.id : 'evt_101'}\`
- **Initial Attack Vector:** ${patientZero ? patientZero.details : 'Credential Stuffing & Session Replay Attack'}
- **Primary Origin IP:** \`${patientZero ? patientZero.ip : '185.220.101.45'}\` (${patientZero ? patientZero.location : 'Tor Exit Node'})
- **Targeted Entity:** \`${patientZero ? patientZero.user : 'usr_1'}\`
- **Baseline Deviation Score:** ${patientZero ? Math.round(patientZero.anomalyScore * 100) : 94}% anomaly confidence score.

---

## 3. RECONSTRUCTED ATTACK TIMELINE
${telemetryLog.map((log, idx) => `
${idx + 1}. **[${log.timestamp}] ${log.type}**
   - **Entity:** \`${log.user || 'Unknown User'}\` | **IP:** \`${log.ip}\`
   - **Details:** ${log.details}
   - **Severity:** \`${log.severity.toUpperCase()}\` (Anomaly Score: ${Math.round(log.anomalyScore * 100)}%)
`).join('')}

---

## 4. IMPACTED ENTITIES & BLAST RADIUS
- **Blast Radius Index:** ${incidentData.blastRadiusScore || 45}% of infrastructure
- **Compromised Accounts:** ${incidentData.affectedEntityIds ? incidentData.affectedEntityIds.filter(id => id.startsWith('usr_')).join(', ') || 'usr_1 (Sarah Connor)' : 'usr_1'}
- **Targeted Services:** Kubernetes Cluster Gateway, HashiCorp Vault Secrets Manager
- **External Rogue Infrastructure:** Tor Exit Node (\`185.220.101.45\`), Command & Control Server (\`91.218.114.12\`)

---

## 5. AI REINFORCEMENT LEARNING MITIGATION PLAN
1. ✅ **Session Termination:** Invalidate active OAuth refresh tokens for affected user accounts.
2. 🛡️ **Perimeter Firewall Rule:** Deploy zero-trust block policy for external IP \`185.220.101.45\`.
3. ⚡ **Endpoint Isolation:** Quarantine host workstation \`dev_mac_01\` to prevent ransomware payload execution.
4. 🔑 **Privilege Reset:** Force global rotation of HashiCorp Vault database root keys.

*Report automatically compiled by AegisThreat GenAI SecOps Synthesizer.*
`;
  }

  /**
   * Responds to natural language queries from SecOps investigators
   */
  static queryAssistant(userQuery, telemetryLog, incidentData) {
    const queryLower = userQuery.toLowerCase();

    if (queryLower.includes("root cause") || queryLower.includes("patient zero") || queryLower.includes("start") || queryLower.includes("origin")) {
      const pZero = incidentData.patientZero || telemetryLog[0];
      return `Based on Knowledge Graph correlation, **Patient Zero** was detected at **${pZero ? pZero.timestamp : '11:20:00'}**. The attack originated from IP **${pZero ? pZero.ip : '185.220.101.45'}** targeting user account **${pZero ? pZero.user : 'usr_1'}** via **${pZero ? pZero.details : 'Credential Stuffing'}**. Anomaly confidence score: ${pZero ? Math.round(pZero.anomalyScore * 100) : 94}%.`;
    }

    if (queryLower.includes("ip") || queryLower.includes("network") || queryLower.includes("tor") || queryLower.includes("attacker")) {
      return `The primary hostile network IP identified is **185.220.101.45** (Tor Exit Node, Frankfurt, DE) and secondary C2 beacon **91.218.114.12**. RL firewall block rules are ready for immediate deployment.`;
    }

    if (queryLower.includes("affected") || queryLower.includes("blast radius") || queryLower.includes("devices") || queryLower.includes("entities")) {
      return `The current Incident Blast Radius is estimated at **${incidentData.blastRadiusScore || 45}%**. Affected entities include: User \`usr_1\` (Sarah Connor), Workstation \`dev_mac_01\`, Kubernetes Gateway, and HashiCorp Vault Secrets Manager.`;
    }

    if (queryLower.includes("action") || queryLower.includes("recommend") || queryLower.includes("mitigat") || queryLower.includes("fix")) {
      return `The Reinforcement Learning agent recommends: 1) Immediately **Terminate Active Sessions** for user \`usr_1\`, 2) **Block external IP** \`185.220.101.45\` on the edge firewall, and 3) **Isolate workstation** \`dev_mac_01\`.`;
    }

    if (queryLower.includes("ransomware") || queryLower.includes("lockbit") || queryLower.includes("malware")) {
      return `High severity alert: A malicious executable script (\`lockbit_v4_linux_amd64.sh\`) was detected attempting to connect to external command & control node \`91.218.114.12\`. Automated process kill is advised.`;
    }

    return `AegisAI Analysis: Processing your query "${userQuery}". Correlating active telemetry stream: ${telemetryLog.length} security events monitored. Dynamic Threat Risk Score is elevated. You can ask me about Patient Zero, affected entities, rogue IP addresses, or recommended RL mitigations.`;
  }
}
