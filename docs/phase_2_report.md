# Phase 2 Report — Behavioral Digital Twin, Drift & Risk Evolution

## Implementation Summary
- **Behavioral Digital Twin**: `backend/behavioral_model/digital_twin.py` learns normative baselines across login hours, known devices, common apps, session durations, and network endpoints.
- **Behavioral Drift Calculation**: Multi-factor deviation engine normalized to $[0, 100]$.
- **Threat Risk Evolution Engine**: `backend/risk_engine/calculator.py` implementing $R(t) = 0.4A(t) + 0.4B(t) + 0.2H(t)$ with decay weighting for historical risk.
- **Validation**: Mathematical formulas and baseline learning verified with `test_digital_twin_baseline_learning` and `test_risk_engine_formula`.
