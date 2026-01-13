"""
ml_anomaly.py

Unsupervised anomaly detection on top of per-user features using Isolation Forest.

We assume most users are "normal" and a small fraction behave strangely.
This module adds:
  - anomaly_score (higher = more anomalous)
  - anomaly_flag (True/False)
"""

from __future__ import annotations

from typing import List

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest


def _select_feature_columns(df: pd.DataFrame) -> List[str]:
    """
    Choose numeric columns to feed into the model.
    We exclude identifiers like 'user'.
    """
    exclude = {"user"}
    numeric_cols = df.select_dtypes(include=[np.number]).columns
    return [c for c in numeric_cols if c not in exclude]


def compute_anomaly_scores(
    features_df: pd.DataFrame,
    contamination: float = 0.1,
    random_state: int = 42,
) -> pd.DataFrame:
    """
    Fit IsolationForest on the feature set and return a copy of features_df with:
      - anomaly_score (float, higher = more anomalous)
      - anomaly_flag (bool, True if model thinks this is an outlier)
    """
    df = features_df.copy()
    feature_cols = _select_feature_columns(df)

    if not feature_cols:
        raise ValueError("No numeric feature columns found for anomaly detection.")

    X = df[feature_cols].values

    model = IsolationForest(
        n_estimators=100,
        contamination=contamination,
        random_state=random_state,
    )
    model.fit(X)

    # decision_function: higher = more normal → we invert it
    raw_scores = model.decision_function(X)
    anomaly_scores = -raw_scores

    # normalize roughly into 0–1 range for easier reasoning
    # (not perfect, but good enough for this project)
    scores_min = anomaly_scores.min()
    scores_max = anomaly_scores.max()
    if scores_max > scores_min:
        norm_scores = (anomaly_scores - scores_min) / (scores_max - scores_min)
    else:
        norm_scores = np.zeros_like(anomaly_scores)

    preds = model.predict(X)  # -1 = anomaly, 1 = normal

    df["anomaly_score"] = norm_scores
    df["anomaly_flag"] = preds == -1

    return df


if __name__ == "__main__":
    # quick manual test if you ever want to run this file directly
    features = pd.read_csv("data/user_features.csv")
    out = compute_anomaly_scores(features)
    out.to_csv("data/user_features_with_anomaly.csv", index=False)
    print("Wrote user_features_with_anomaly.csv with anomaly scores.")
    print(out.head())
