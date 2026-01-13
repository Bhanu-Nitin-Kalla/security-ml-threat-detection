# Threat Model – Identity Anomaly Detection Lab

## 1. Assets

- **User identities** represented by logical user IDs (e.g. `user_001`)
- **Authentication sessions** simulated via VPN / SSO / AD-style logs
- **Access channels**
  - Source IPs (internal ranges in this lab)
  - Geo locations (country level)
  - Devices (logical device IDs per user)

Even though this is synthetic data, the model mirrors a real corporate identity perimeter.

---

## 2. Adversary Goals

1. **Obtain valid credentials** and use them for:
   - Interactive logins to VPN / SSO / AD
   - Lateral movement and data access

2. **Avoid detection** by:
   - Blending into normal user behaviour
   - Spreading attempts over time
   - Using off-hours and new devices

---

## 3. Attack Scenarios Covered

### 3.1 Brute Force / Password Spray

- Many failed logins for a single user
- Persistent elevated failure ratio over time
- Mapped to **MITRE T1110 – Brute Force**

Detection signals:

- `failed_login_ratio` above normal baselines
- Multiple failures in a small number of total logins
- ML anomaly score highlighting users whose failure patterns differ from the population

---

### 3.2 Suspicious Off-hours Activity (Valid Account Misuse)

- Logins happening mainly outside business hours
- Could indicate compromised credentials used when the user is unlikely to notice
- Mapped to **MITRE T1078 – Valid Accounts**

Detection signals:

- `off_hours_ratio` significantly higher than typical users
- Combination with elevated failure ratios
- ML anomaly score reflecting unusual time-of-day behaviour

---

### 3.3 Noisy Probing from Newly Active Users

- Accounts with **few total logins** but **multiple failures already**
- Could indicate testing weak or default passwords after initial provisioning

Detection signals:

- `total_logins` small but `failed_logins` non-zero
- Heavier scoring when this pattern appears early in the account history

---

## 4. Out of Scope / Limitations

- No device posture checks (OS version, patch level, etc.)
- No network-level telemetry (flows, DNS, HTTP)
- No MFA signals (approvals / denials)
- No geo-velocity / impossible travel logic yet
- Synthetic data distribution is controlled and may not reflect all real-world noise patterns

These limitations are intentional for a focused identity-behaviour lab.

---

## 5. Detection Strategy

1. **Behaviour aggregation (UEBA style)**
   - Aggregate events by user over a time window
   - Focus on ratios and patterns, not single log lines

2. **Rules first, ML second**
   - Transparent rules for:
     - high/elevated failure ratios
     - heavy/noticeable off-hours usage
     - low-volume accounts with early failures
   - ML (Isolation Forest) adds an additional anomaly signal but does not replace rules

3. **Risk scoring**
   - Convert signals into a `risk_score` (0–100) and `severity` band
   - Provide a human-readable `reason` for each alert
   - Attach `mitre_technique` tags to help SOC analysts map to ATT&CK

---

## 6. Intended Consumers

- **Detection engineers** evaluating new identity detections
- **SOC analysts** needing prioritised, explainable alerts
- **Security engineers** experimenting with UEBA-style features and ML
