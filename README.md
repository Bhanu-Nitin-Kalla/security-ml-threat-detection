# Security ML Threat Detection – Identity Anomaly Lab

> Mini detection engine that models suspicious authentication behaviour using
> security rules **plus** unsupervised ML (Isolation Forest), producing
> risk-scored alerts with MITRE ATT&CK tags.

---

## 1. Problem

Modern SOCs are flooded with noisy auth logs from VPN, SSO and AD.  
Analysts need **prioritised, explainable alerts** that highlight:

- Unusual failure patterns (brute force / password spray)
- Suspicious off-hours usage of valid accounts
- Users whose behaviour is statistically different from the population

This project simulates that problem end-to-end and shows how a **security engineer**
can design detections as code with a small ML layer on top.

---

## 2. What this project does

End-to-end pipeline:

1. **Generate auth logs**  
   - `src/generate_auth_logs.py`  
   - 150 users over 7 days  
   - realistic mix of:
     - success / failure
     - off-hours vs business hours
     - multiple devices, IPs, geos
     - a small “risky” cohort with higher failure rates

2. **Build user-level behavioural features**  
   - `src/features.py`  
   - For each user:
     - `total_logins`
     - `failed_login_ratio`
     - `off_hours_ratio`
     - `distinct_ips`, `distinct_geos`, `distinct_devices` (easy to extend)

3. **Run ML anomaly detection (Isolation Forest)**  
   - `src/ml_anomaly.py`  
   - Unsupervised model on user features  
   - Adds:
     - `anomaly_score` (0–1, higher = more anomalous)
     - `anomaly_flag` (True/False)

4. **Combine rules + ML into risk-scored alerts**  
   - `src/detections.py`  
   - Rule signals:
     - high / elevated `failed_login_ratio` → **T1110 Brute Force**
     - heavy / noticeable `off_hours_ratio` → **T1078 Valid Accounts**
     - “few logins but multiple failures” → early probing / misuse
   - ML signal:
     - boosts risk when `anomaly_flag` is true or `anomaly_score` is high
   - Outputs per user:
     - `risk_score` (0–100)
     - `severity` (`LOW` / `MEDIUM` / `HIGH`)
     - `reason` – human-readable evidence string
     - `mitre_technique` – ATT&CK technique labels

5. **One-command pipeline**  
   - `src/pipeline.py`  
   - Regenerates logs, features, anomaly scores and alerts in a single run.

---

## 3. How to run

### 3.1 Environment

```bash
# (Optional) create a dedicated conda env
conda create -n sec-ml python=3.11 -y
conda activate sec-ml

# Install dependencies
pip install -r REQUIREMENTS.TXT
