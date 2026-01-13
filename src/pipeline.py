"""
pipeline.py

End-to-end runner:
  1) generate logs
  2) build user features
  3) run ML anomaly detection
  4) run rule + ML detections
"""

from generate_auth_logs import generate_auth_logs
from features import load_logs, build_user_features
from ml_anomaly import compute_anomaly_scores
from detections import build_alerts


def main():
    # 1) Generate logs
    logs = generate_auth_logs()
    logs.to_csv("data/synthetic_auth_logs.csv", index=False)

    # 2) Build features
    logs = load_logs()
    features = build_user_features(logs)
    features.to_csv("data/user_features.csv", index=False)

    # 3) ML anomaly detection
    features_with_ml = compute_anomaly_scores(features)
    features_with_ml.to_csv("data/user_features_with_anomaly.csv", index=False)

    # 4) Run detections (rule + ML)
    alerts = build_alerts(features_with_ml)
    alerts.to_csv("data/alerts.csv", index=False)

    print(f"Generated {len(logs)} log events")
    print(f"Built features for {len(features)} users")
    print(f"Produced {len(alerts)} alerts\n")

    print("Top alerts:")
    print(alerts.head(10))


if __name__ == "__main__":
    main()
