
"""
impossible_travel.py

Detect "impossible travel" per user based on:
  - sequence of login timestamps
  - country-level geo codes

We model each country with an approximate lat/long and compute
great-circle distance between logins. If the distance is large but
the time delta is small, we flag an impossible travel alert.
"""

from __future__ import annotations

from dataclasses import dataclass
from math import radians, sin, cos, asin, sqrt
from typing import Dict, Tuple

import pandas as pd


LOG_PATH = "data/synthetic_auth_logs.csv"
TRAVEL_ALERT_PATH = "data/impossible_travel_alerts.csv"


# approximate country centroids (lat, lon in degrees)
COUNTRY_COORDS: Dict[str, Tuple[float, float]] = {
    "US": (38.0, -97.0),
    "IN": (20.6, 78.9),
    "GB": (54.0, -2.0),
    "DE": (51.2, 10.4),
    "CA": (56.1, -106.3),
    "SG": (1.35, 103.8),
    "AU": (-25.3, 133.8),
}


@dataclass
class TravelThresholds:
    distance_km: float = 3000.0  # long-haul distance
    max_hours: float = 5.0       # too little time to realistically travel


def load_logs(path: str = LOG_PATH) -> pd.DataFrame:
    return pd.read_csv(path, parse_dates=["timestamp"])


def _haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Great-circle distance between two points on Earth in km."""
    R = 6371.0
    phi1, phi2 = radians(lat1), radians(lat2)
    dphi = radians(lat2 - lat1)
    dlambda = radians(lon2 - lon1)

    a = sin(dphi / 2) ** 2 + cos(phi1) * cos(phi2) * sin(dlambda / 2) ** 2
    c = 2 * asin(sqrt(a))
    return R * c


def find_impossible_travel(
    logs_df: pd.DataFrame,
    thresholds: TravelThresholds | None = None,
) -> pd.DataFrame:
    """
    For each user, sort events by timestamp and look at consecutive logins.
    If the geo changes and the travel would require unrealistic speed,
    flag an impossible travel event.
    """
    thresholds = thresholds or TravelThresholds()

    required = {"user", "timestamp", "geo"}
    missing = required - set(logs_df.columns)
    if missing:
        raise ValueError(f"logs_df missing required columns: {missing}")

    df = logs_df.copy()
    df = df.sort_values(["user", "timestamp"])

    alerts = []

    for user, user_df in df.groupby("user"):
        user_df = user_df.sort_values("timestamp")
        prev_row = None

        for _, row in user_df.iterrows():
            if prev_row is None:
                prev_row = row
                continue

            geo1 = str(prev_row["geo"])
            geo2 = str(row["geo"])

            if geo1 == geo2:
                prev_row = row
                continue

            if geo1 not in COUNTRY_COORDS or geo2 not in COUNTRY_COORDS:
                prev_row = row
                continue

            lat1, lon1 = COUNTRY_COORDS[geo1]
            lat2, lon2 = COUNTRY_COORDS[geo2]

            dist_km = _haversine_km(lat1, lon1, lat2, lon2)
            hours = (row["timestamp"] - prev_row["timestamp"]).total_seconds() / 3600.0

            if hours <= 0:
                prev_row = row
                continue

            speed = dist_km / hours

            # flag as impossible if distance is large and time is short
            if dist_km >= thresholds.distance_km and hours <= thresholds.max_hours:
                alerts.append(
                    {
                        "user": user,
                        "from_geo": geo1,
                        "to_geo": geo2,
                        "from_timestamp": prev_row["timestamp"],
                        "to_timestamp": row["timestamp"],
                        "distance_km": round(dist_km, 1),
                        "hours_between": round(hours, 2),
                        "speed_kmh": round(speed, 1),
                    }
                )

            prev_row = row

    return pd.DataFrame(alerts)


if __name__ == "__main__":
    logs = load_logs()
    alerts = find_impossible_travel(logs)
    alerts.to_csv(TRAVEL_ALERT_PATH, index=False)
    print(f"Wrote {len(alerts)} impossible travel alerts to {TRAVEL_ALERT_PATH}")
    print(alerts.head())
