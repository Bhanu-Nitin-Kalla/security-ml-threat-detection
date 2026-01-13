"""
ip_detections.py

Detect password spray / brute-force behaviour at the IP level:
  - many distinct users targeted from a single src_ip
  - high fraction of failed logins

Outputs a DataFrame of suspicious IPs that can be exported to CSV.
"""

from __future__ import annotations

import pandas as pd


LOG_PATH = "data/synthetic_auth_logs.csv"
IP_ALERT_PATH = "data/ip_password_spray_alerts.csv"


def load_logs(path: str = LOG_PATH) -> pd.DataFrame:
    return pd.read_csv(path, parse_dates=["timestamp"])


def detect_password_spray(
    logs_df: pd.DataFrame,
    min_distinct_users: int = 10,
    min_total_attempts: int = 30,
    min_failure_ratio: float = 0.6,
) -> pd.DataFrame:
    """
    Identify IPs that:
      - have hit at least `min_distinct_users` different accounts
      - have at least `min_total_attempts` total login attempts
      - and show a failure ratio >= `min_failure_ratio`
    """
    required = {"src_ip", "user", "success"}
    missing = required - set(logs_df.columns)
    if missing:
        raise ValueError(f"logs_df missing required columns: {missing}")

    df = logs_df.copy()
    df["success"] = df["success"].astype(bool)

    grouped = df.groupby("src_ip")

    agg = grouped.agg(
        total_attempts=("success", "count"),
        failures=("success", lambda x: (~x).sum()),
        distinct_users=("user", "nunique"),
    ).reset_index()

    agg["failure_ratio"] = agg["failures"] / agg["total_attempts"].replace(0, 1)

    # filter for suspicious IPs
    suspicious = agg[
        (agg["distinct_users"] >= min_distinct_users)
        & (agg["total_attempts"] >= min_total_attempts)
        & (agg["failure_ratio"] >= min_failure_ratio)
    ].copy()

    # add a sample of users targeted (for context)
    if not suspicious.empty:
        user_lists = (
            df[df["src_ip"].isin(suspicious["src_ip"])]
            .groupby("src_ip")["user"]
            .apply(lambda s: ", ".join(sorted(set(s))[:10]))
            .rename("sample_users")
        )
        suspicious = suspicious.merge(user_lists, on="src_ip", how="left")

    return suspicious


if __name__ == "__main__":
    logs = load_logs()
    alerts = detect_password_spray(logs)
    alerts.to_csv(IP_ALERT_PATH, index=False)
    print(f"Wrote {len(alerts)} IP password spray alerts to {IP_ALERT_PATH}")
    print(alerts.head())
