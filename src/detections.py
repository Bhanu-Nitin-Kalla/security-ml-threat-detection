"""
detections.py

Rule + ML-based detection on top of per-user features.

Signals:
  - failed_login_ratio  (brute force / password issues)
  - off_hours_ratio     (suspicious timing / valid accounts misuse)
  - few logins but many failures
  - anomaly_score / anomaly_flag from Isolation Forest
"""

import pandas as pd

FEATURES_PATH = "data/user_features.csv"
ALERTS_PATH = "data/alerts.csv"


def load_features(path: str = FEATURES_PATH) -> pd.DataFrame:
    return pd.read_csv(path)


def score_user(row: pd.Series) -> dict:
    reasons = []
    score = 0
    mitre_tags = set()

    # reconstruct failed_logins if missing
    failed_logins = row.get("failed_logins")
    if "failed_logins" not in row or pd.isna(failed_logins):
        failed_logins = int(round(row["failed_login_ratio"] * row["total_logins"]))

    flr = row["failed_login_ratio"]
    ohr = row["off_hours_ratio"]
    total = row["total_logins"]

    anomaly_score = float(row.get("anomaly_score", 0.0))
    anomaly_flag = bool(row.get("anomaly_flag", False))

    # ---- Failed login ratio (Credential Access / Brute Force) ----
    if flr >= 0.30:
        score += 50
        reasons.append(f"high failed login ratio ({flr:.2f})")
        mitre_tags.add("T1110: Brute Force")
    elif flr >= 0.15:
        score += 30
        reasons.append(f"elevated failed login ratio ({flr:.2f})")
        mitre_tags.add("T1110: Brute Force")

    # ---- Off-hours usage (Valid Accounts misuse) ----
    if ohr >= 0.60:
        score += 30
        reasons.append(f"heavy off-hours activity ({ohr:.2f})")
        mitre_tags.add("T1078: Valid Accounts")
    elif ohr >= 0.40:
        score += 15
        reasons.append(f"noticeable off-hours activity ({ohr:.2f})")
        mitre_tags.add("T1078: Valid Accounts")

    # ---- Few logins but already failing ----
    if total <= 10 and failed_logins >= 3:
        score += 20
        reasons.append(f"{failed_logins} failure(s) in only {int(total)} login(s)")

    # ---- ML anomaly score ----
    if anomaly_flag:
        score += 20
        reasons.append(f"ML anomaly flagged user (anomaly_score={anomaly_score:.2f})")
    elif anomaly_score >= 0.7:
        score += 10
        reasons.append(f"ML anomaly score elevated (anomaly_score={anomaly_score:.2f})")

    # cap and severity
    score = min(score, 100)

    if score >= 70:
        severity = "HIGH"
    elif score >= 40:
        severity = "MEDIUM"
    elif score >= 10:
        severity = "LOW"
    else:
        severity = "NONE"

    reason_text = "; ".join(reasons) if reasons else "no notable anomalies"
    mitre_text = ", ".join(sorted(mitre_tags)) if mitre_tags else ""

    return {
        "failed_logins": failed_logins,
        "risk_score": score,
        "severity": severity,
        "reason": reason_text,
        "mitre_technique": mitre_text,
    }


def build_alerts(features_df: pd.DataFrame) -> pd.DataFrame:
    alerts = features_df.copy()

    scored = alerts.apply(score_user, axis=1, result_type="expand")
    alerts = pd.concat([alerts, scored], axis=1)

    # keep only users with some risk
    alerts = alerts[alerts["severity"] != "NONE"]

    # sort most suspicious first
    alerts = alerts.sort_values(
        ["risk_score", "failed_login_ratio", "off_hours_ratio", "anomaly_score"],
        ascending=[False, False, False, False],
    ).reset_index(drop=True)

    return alerts


if __name__ == "__main__":
    feats = load_features()
    print("User features (sample):")
    print(feats.head())

    alerts_df = build_alerts(feats)
    print("\nAlerts (top 10):")
    print(alerts_df.head(10))

    alerts_df.to_csv(ALERTS_PATH, index=False)
    print(f"\nWrote {len(alerts_df)} alerts to {ALERTS_PATH}")
