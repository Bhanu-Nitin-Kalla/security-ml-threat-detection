# Architecture – Security ML Threat Detection

## 1. High-level Flow

```text
[generate_auth_logs]  -> raw auth events
      |
      v
[features]            -> per-user behavioural features
      |
      v
[ml_anomaly]          -> anomaly_score, anomaly_flag
      |
      v
[detections]          -> risk_score, severity, reason, MITRE
