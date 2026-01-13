"""
pipeline.py

End-to-end runner:
  1) generate logs
  2) build user features
  3) run ML anomaly detection
  4) run rule + ML detections (user-level)
  5) run IP-level password spray detection
  6) run impossible travel detection
"""

from generate_auth_logs import generate_auth_logs
from features import load_logs, build_user_features
from ml_anomaly import compute_anomaly_scores
from detections import build_alerts
from ip_detections import detect_password_spray
from impossible_travel import find_impossible_travel


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

    # 4) User-level detections (rule + ML)
    alerts = build_alerts(features_with_ml)
    alerts.to_csv("data/alerts.csv", index=False)

    # 5) IP-level password spray detections
    ip_alerts = detect_password_spray(logs)
    ip_alerts.to_csv("data/ip_password_spray_alerts.csv", index=False)

    # 6) Impossible travel detections
    travel_alerts = find_impossible_travel(logs)
    travel_alerts.to_csv("data/impossible_travel_alerts.csv", index=False)

    print(f"Generated {len(logs)} log events")
    print(f"Built features for {len(features)} users")
    print(f"Produced {len(alerts)} user-level alerts")
    print(f"Produced {len(ip_alerts)} IP password spray alerts")
    print(f"Produced {len(travel_alerts)} impossible travel alerts\n")

    print("Top user alerts:")
    print(alerts.head(5))

    print("\nTop IP password spray alerts:")
    print(ip_alerts.head(5))

    print("\nSample impossible travel alerts:")
    print(travel_alerts.head(5))


if __name__ == "__main__":
    main()
