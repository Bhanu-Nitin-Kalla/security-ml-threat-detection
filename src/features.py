"""
features.py

Takes synthetic_auth_logs.csv and builds simple per-user behavioral features.
This is the first step toward our detection engine.
"""

import pandas as pd


INPUT_PATH = "data/synthetic_auth_logs.csv"
OUTPUT_PATH = "data/user_features.csv"


def load_logs(path: str = INPUT_PATH) -> pd.DataFrame:
    """Load the raw authentication logs."""
    df = pd.read_csv(path, parse_dates=["timestamp"])
    return df


def build_user_features(df: pd.DataFrame) -> pd.DataFrame:
    """
    For each user, compute:
      - total_logins
      - failed_logins
      - failed_login_ratio
      - off_hours_logins
      - off_hours_ratio
    """
    required_cols = {"user", "success", "off_hours"}
    missing = required_cols - set(df.columns)
    if missing:
        raise ValueError(f"Missing required columns in logs: {missing}")

    df = df.copy()
    df["success"] = df["success"].astype(bool)
    df["off_hours"] = df["off_hours"].astype(bool)

    grouped = df.groupby("user")

    agg = grouped.agg(
        total_logins=("timestamp", "count"),
        failed_logins=("success", lambda x: (~x).sum()),
        off_hours_logins=("off_hours", "sum"),
    ).reset_index()

    # avoid divide-by-zero just in case
    denom = agg["total_logins"].replace(0, 1)

    agg["failed_login_ratio"] = agg["failed_logins"] / denom
    agg["off_hours_ratio"] = agg["off_hours_logins"] / denom

    return agg


if __name__ == "__main__":
    logs_df = load_logs()
    print("Raw logs:")
    print(logs_df)

    features_df = build_user_features(logs_df)
    print("\nUser features:")
    print(features_df)

    features_df.to_csv(OUTPUT_PATH, index=False)
    print(f"\nWrote user features to {OUTPUT_PATH}")
