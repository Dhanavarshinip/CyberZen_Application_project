// Reinforcement Learning (RL) Adaptive Security Response Engine

export class RlResponseEngine {
  constructor() {
    this.actionCatalog = [
      {
        id: "act_mfa_challenge",
        name: "Require MFA Step-Up Challenge",
        type: "AUTHENTICATION",
        riskReduction: 45,
        userFriction: 15,
        qValue: 0.88,
        description: "Enforce webauthn biometric MFA prompt on active session",
        icon: "ShieldAlert"
      },
      {
        id: "act_kill_session",
        name: "Terminate Active Session Token",
        type: "SESSION",
        riskReduction: 75,
        userFriction: 30,
        qValue: 0.94,
        description: "Invalidate session key across Okta & OAuth gateway",
        icon: "UserX"
      },
      {
        id: "act_block_ip",
        name: "Perimeter Firewall IP Blocklist",
        type: "NETWORK",
        riskReduction: 85,
        userFriction: 20,
        qValue: 0.96,
        description: "Deploy automated drop rule to perimeter egress/ingress firewall",
        icon: "Globe"
      },
      {
        id: "act_isolate_device",
        name: "Isolate Host Device (EDR VLAN)",
        type: "ENDPOINT",
        riskReduction: 95,
        userFriction: 60,
        qValue: 0.92,
        description: "Restrict host network interface to security quarantine VLAN",
        icon: "Laptop"
      },
      {
        id: "act_quarantine_process",
        name: "Quarantine & Kill Malicious Process",
        type: "ENDPOINT",
        riskReduction: 98,
        userFriction: 40,
        qValue: 0.99,
        description: "SIGKILL process hierarchy & send binary to malware sandbox",
        icon: "FileCode"
      }
    ];

    this.executedActionsHistory = [];
  }

  /**
   * Recommends optimal adaptive security actions given current threat risk state
   * @param {number} riskScore - Current evolving risk score (0 - 100)
   * @param {Object} latestEvent - Latest anomalous telemetry event
   */
  getRecommendations(riskScore, latestEvent) {
    if (riskScore < 25) {
      return [
        {
          ...this.actionCatalog[0],
          status: "RECOMMENDED",
          matchScore: 92,
          reasoning: "Low risk baseline: Passive step-up authentication advised."
        }
      ];
    }

    if (riskScore >= 25 && riskScore < 60) {
      return [
        {
          ...this.actionCatalog[1],
          status: "RECOMMENDED",
          matchScore: 96,
          reasoning: "Elevated threat level: Invalidating suspicious user session."
        },
        {
          ...this.actionCatalog[0],
          status: "SECONDARY",
          matchScore: 84,
          reasoning: "Step-up MFA check for secondary registered device."
        }
      ];
    }

    // High & Critical Threat State (Risk >= 60)
    return [
      {
        ...this.actionCatalog[4],
        status: "CRITICAL_RECOMMENDED",
        matchScore: 99,
        reasoning: "Active payload / compromise detected: Immediate process kill & quarantine."
      },
      {
        ...this.actionCatalog[3],
        status: "RECOMMENDED",
        matchScore: 95,
        reasoning: "Critical threat velocity: Isolate infected endpoint from network."
      },
      {
        ...this.actionCatalog[2],
        status: "RECOMMENDED",
        matchScore: 93,
        reasoning: "Blacklist external attacker C2 / Tor Exit IP address."
      }
    ];
  }

  /**
   * Executes response action (Manual or Auto-Pilot)
   */
  executeAction(action, targetEntity, isAutoPilot = false) {
    const record = {
      id: `exe_${Date.now()}`,
      actionId: action.id,
      actionName: action.name,
      targetEntity: targetEntity || "System Perimeter",
      timestamp: new Date().toLocaleTimeString(),
      riskReduction: action.riskReduction,
      executor: isAutoPilot ? "RL Auto-Pilot Engine" : "SecOps Analyst",
      status: "EXECUTED_SUCCESS"
    };

    this.executedActionsHistory.unshift(record);
    return record;
  }
}

export const rlResponseEngineInstance = new RlResponseEngine();
