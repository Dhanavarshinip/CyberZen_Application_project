"""
Reinforcement Learning Q-Agent & Adaptive Response Simulator for CyberThreat AI System.

Implements a formal Markov Decision Process (MDP) and Q-Learning agent:
- State Space S: Discrete 4-tuple (Threat_Tier, Velocity, Blast_Radius, Asset_Criticality)
- Action Space A: 5 Discrete Actions (Observe, Elevate_Sampling, Challenge_MFA, Throttle_Network, Simulate_Isolate)
- Reward Function: Balances Threat Mitigation vs User Disruption & False Alarms
- Non-Destructive Execution: Real host actions are simulated markers only (zero disruption to physical PC).
"""

import random
import numpy as np
from typing import Dict, Any, List, Tuple, Optional


class AdaptiveResponseQLearningAgent:
    """
    Q-Learning agent learning optimal adaptive defense policies balancing
    threat containment against operational user friction.
    """

    ACTION_NAMES = [
        "OBSERVE",
        "ELEVATE_SAMPLING",
        "CHALLENGE_MFA",
        "THROTTLE_NETWORK",
        "SIMULATE_ISOLATE"
    ]

    ACTION_FRICTION_COSTS = [0.0, 2.0, 10.0, 25.0, 40.0]

    def __init__(
        self,
        learning_rate: float = 0.15,
        discount_factor: float = 0.90,
        epsilon: float = 0.30,
        epsilon_decay: float = 0.995,
        min_epsilon: float = 0.05
    ):
        self.alpha = learning_rate
        self.gamma = discount_factor
        self.epsilon = epsilon
        self.epsilon_decay = epsilon_decay
        self.min_epsilon = min_epsilon

        # State dimensions: 4 tiers x 3 velocities x 3 blast radii x 3 criticalities = 108 states
        self.state_shape = (4, 3, 3, 3)
        self.num_actions = len(self.ACTION_NAMES)
        self.q_table = np.zeros((*self.state_shape, self.num_actions), dtype=np.float32)
        self.training_episodes = 0
        self.convergence_deltas: List[float] = []

    @classmethod
    def discretize_state(
        cls,
        risk_score: float,
        velocity: float = 0.0,
        blast_radius_entities: int = 1,
        asset_type: str = "endpoint"
    ) -> Tuple[int, int, int, int]:
        """Maps continuous telemetry signals into discrete MDP state tuple."""
        # 1. Threat Tier (0: Low, 1: Medium, 2: High, 3: Critical)
        if risk_score >= 80.0:
            tier = 3
        elif risk_score >= 60.0:
            tier = 2
        elif risk_score >= 35.0:
            tier = 1
        else:
            tier = 0

        # 2. Velocity (0: Stable/Decelerating, 1: Moderate Rise, 2: Rapid Spike)
        if velocity >= 3.0:
            v_idx = 2
        elif velocity >= 0.5:
            v_idx = 1
        else:
            v_idx = 0

        # 3. Blast Radius (0: Single process/1 entity, 1: 2-3 entities, 2: >=4 entities)
        if blast_radius_entities >= 4:
            b_idx = 2
        elif blast_radius_entities >= 2:
            b_idx = 1
        else:
            b_idx = 0

        # 4. Asset Criticality (0: Normal user endpoint, 1: Server/DB, 2: Core Admin/Vault)
        if asset_type in ("admin", "vault", "identity"):
            c_idx = 2
        elif asset_type in ("server", "database", "api"):
            c_idx = 1
        else:
            c_idx = 0

        return (tier, v_idx, b_idx, c_idx)

    def select_action(self, state: Tuple[int, int, int, int], explore: bool = True) -> int:
        """Epsilon-greedy action selection."""
        if explore and random.random() < self.epsilon:
            return random.randint(0, self.num_actions - 1)
        q_values = self.q_table[state]
        # Break ties randomly
        max_q = np.max(q_values)
        best_actions = np.where(q_values == max_q)[0]
        return int(random.choice(best_actions))

    def update_q_value(
        self,
        state: Tuple[int, int, int, int],
        action: int,
        reward: float,
        next_state: Tuple[int, int, int, int]
    ) -> float:
        """Standard Bellman equation Q-value update."""
        current_q = self.q_table[state][action]
        max_next_q = np.max(self.q_table[next_state])
        target_q = reward + self.gamma * max_next_q
        delta = self.alpha * (target_q - current_q)
        self.q_table[state][action] += delta
        return abs(delta)

    @classmethod
    def compute_reward(
        cls,
        state: Tuple[int, int, int, int],
        action: int,
        next_state: Tuple[int, int, int, int]
    ) -> float:
        """
        Calculates reward signal:
        Reward = Threat Mitigation Gain - Operational User Friction - False Alarm Disruption
        """
        curr_tier, curr_v, curr_b, curr_c = state
        next_tier, _, _, _ = next_state

        friction = cls.ACTION_FRICTION_COSTS[action]
        mitigation_gain = 0.0
        penalty = 0.0

        # Risk reduction benefit
        risk_drop = max(0, curr_tier - next_tier)
        mitigation_gain += risk_drop * 35.0

        # Appropriate response matching
        if curr_tier >= 2:  # High or Critical
            if action in (3, 4):  # Throttle or Isolate
                mitigation_gain += 45.0 + (curr_c * 15.0)
            elif action == 0:  # Passive observe in emergency -> heavy penalty
                penalty += 60.0 + (curr_c * 20.0)
        elif curr_tier == 0:  # Low benign baseline
            if action == 4:  # Isolation in benign -> severe false alarm disruption
                penalty += 50.0
            elif action == 3:  # Throttling in benign
                penalty += 25.0
            elif action == 0:  # Observe in benign -> good stewardship
                mitigation_gain += 15.0

        total_reward = mitigation_gain - friction - penalty
        return total_reward

    def recommend_mitigation(
        self,
        risk_score: float,
        velocity: float = 0.0,
        blast_radius: int = 1,
        asset_type: str = "endpoint"
    ) -> Dict[str, Any]:
        """Generates dynamic RL policy mitigation recommendation."""
        state = self.discretize_state(risk_score, velocity, blast_radius, asset_type)
        best_action_idx = self.select_action(state, explore=False)
        action_name = self.ACTION_NAMES[best_action_idx]
        q_vals = [round(float(v), 2) for v in self.q_table[state]]

        rationales = {
            "OBSERVE": "Baseline benign state. Passive telemetry surveillance optimal without operational friction.",
            "ELEVATE_SAMPLING": "Early anomaly signs. Increasing telemetry sampling frequency to confirm threat progression.",
            "CHALLENGE_MFA": "Identity risk detected. Prompting step-up multi-factor authentication challenge to verify operator.",
            "THROTTLE_NETWORK": "Elevated egress velocity detected. Rate-limiting connection bandwidth to prevent exfiltration.",
            "SIMULATE_ISOLATE": "Critical multi-stage breach confirmed. Enforcing simulated sandbox session quarantine."
        }

        return {
            "recommended_action": action_name,
            "action_index": best_action_idx,
            "state_tuple": list(state),
            "state_description": f"Tier={state[0]}, Velocity={state[1]}, BlastRadius={state[2]}, Criticality={state[3]}",
            "q_values_for_state": {self.ACTION_NAMES[i]: q_vals[i] for i in range(len(self.ACTION_NAMES))},
            "estimated_operational_friction": self.ACTION_FRICTION_COSTS[best_action_idx],
            "rationale": rationales.get(action_name, "Evaluated optimal Q-policy mitigation."),
            "is_simulation_safe": True
        }
