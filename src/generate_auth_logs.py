"""
generate_auth_logs.py

Generate synthetic authentication logs for our security-ml-threat-detection project.

This version creates MANY users and MANY events so downstream detections
look realistic, like VPN / SSO logs in a real environment.
"""

from datetime import datetime, timedelta
import random
import pandas as pd


def generate_auth_logs(
    num_users: int = 150,
    days: int = 7,
    avg_events_per_user_per_day: int = 20,
    seed: int = 42,
) -> pd.DataFrame:
    random.seed(seed)

    users = [f"user_{i:03d}" for i in range(1, num_users + 1)]
    # small subset of "risky" users
    num_risky = max(3, num_users // 15)
    risky_users = set(random.sample(users, num_risky))

    now = datetime.utcnow()
    start = now - timedelta(days=days)

    events = []

    for user in users:
        # baseline success prob
        base_success_prob = 0.93
        if user in risky_users:
            base_success_prob = 0.75  # more failures for risky users

        # how many events this user generates
        total_events = random.randint(
            max(5, avg_events_per_user_per_day * days // 2),
            avg_events_per_user_per_day * days * 2,
        )

        # each user has 1–3 devices
        num_devices = random.randint(1, 3)
        device_ids = [f"dev_{user}_{i}" for i in range(1, num_devices + 1)]
        seen_devices = set()

        for _ in range(total_events):
            # random time in window
            delta_seconds = random.randint(0, int((now - start).total_seconds()))
            ts = start + timedelta(seconds=delta_seconds)

            # derive off_hours
            off_hours = ts.hour < 7 or ts.hour >= 19

            # random IP + geo + auth system
            src_ip = f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
            geo = random.choice(["US", "IN", "GB", "DE", "CA", "SG", "AU"])
            auth_system = random.choice(["vpn", "okta", "ad"])

            device_id = random.choice(device_ids)
            is_new_device = device_id not in seen_devices
            if is_new_device:
                seen_devices.add(device_id)

            # tweak success prob for off-hours (more risky)
            success_prob = base_success_prob - (0.08 if off_hours else 0.0)
            success_prob = max(0.05, min(0.99, success_prob))

            success = random.random() < success_prob

            events.append(
                {
                    "timestamp": ts,
                    "user": user,
                    "src_ip": src_ip,
                    "geo": geo,
                    "device_id": device_id,
                    "auth_system": auth_system,
                    "event_type": "login",
                    "success": success,
                    "is_new_device": is_new_device,
                    "off_hours": off_hours,
                }
            )

    df = pd.DataFrame(events).sort_values(["user", "timestamp"]).reset_index(drop=True)
    return df


if __name__ == "__main__":
    logs = generate_auth_logs()
    output_path = "data/synthetic_auth_logs.csv"
    logs.to_csv(output_path, index=False)
    print(f"Wrote {len(logs)} events to {output_path}")
