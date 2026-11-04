# Research Limitations & Honest Engineering Disclosures

In accordance with strict research integrity and scientific honesty standards, this document outlines the operational boundaries, assumptions, and limitations of the **CyberThreat AI System**.

---

## 1. Prototype Heuristics vs. Proven Causality
- **Event Contribution**: The system identifies *estimated relative contribution* of events within an incident cluster based on anomaly magnitude and temporal position. It does **not** claim mathematical proof of physical causality.
- **Risk Weights**: The formula $R(t) = 0.4A(t) + 0.4B(t) + 0.2H(t)$ uses prototype heuristic research weights designed for initial benchmarking. Optimal weights should be tuned per operational environment via empirical Bayesian optimization or logistic regression.

## 2. ML Anomaly Score Calibration
- **Isolation Forest Output**: Raw Isolation Forest decision function values are min-max mapped to a $[0, 100]$ score. These scores represent statistical outlier distances rather than calibrated Bayesian posterior probabilities of malicious intent.

## 3. Synthetic Telemetry Scope
- **Data Source**: All telemetry used in demonstrations and unit tests is synthetically generated or derived from controlled authorized test fixtures.
- **Privacy Boundary**: The system collects and processes only authorized telemetry attributes (timestamps, event types, anonymized device/user IDs, high-level process labels). It intentionally does **not** collect passwords, private messages, financial credentials, keystroke content, or confidential file contents.

## 4. Adaptive Response Scope
- **Simulated Containment**: The Adaptive Response Engine provides policy-driven response recommendations (such as MFA step-up or session isolation). In this prototype environment, actions are executed against virtualized demo sessions and non-destructive test hooks. No destructive host alterations or network outages are triggered.

## 5. Grounded AI Investigator Boundaries
- **No Hallucination**: The AI Investigator operates in deterministic mode by default, extracting facts solely from recorded SQLite telemetry and reconstructed incident graphs. When asked about missing or unrecorded events, it returns "Insufficient evidence" rather than speculating.
