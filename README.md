# 🔐 Security ML Threat Detection – Identity Anomaly Lab

> A lightweight **identity threat detection engine** that models suspicious
authentication behavior using **security rules + unsupervised ML (Isolation Forest)**,
producing **risk-scored, explainable alerts** mapped to **MITRE ATT&CK**.

This lab demonstrates how a **security engineer** can augment traditional
rule-based detections with machine learning to improve **signal quality and alert
prioritization** in modern SOC environments.

---

## 🧠 Problem Statement

Modern SOCs ingest massive volumes of authentication telemetry from
VPNs, SSO platforms, and directory services.  
While rules can detect obvious abuse, they often generate **high noise and low
context**.

Analysts need alerts that:
- Prioritize **behavioral outliers**, not just threshold breaches
- Provide **human-readable evidence**
- Reduce alert fatigue while preserving detection coverage

This project simulates that challenge end-to-end and shows how **ML can enhance —
not replace — security rules**.

---

## 🎯 Detection Objectives

The system focuses on identifying **identity misuse signals**, including:

- Abnormal authentication failure patterns *(password spraying, brute force attempts)*
- Suspicious off-hours usage of valid credentials
- Users whose authentication behavior is statistically anomalous compared to peers

---

## 🏗️ Architecture Overview

```text
Auth Log Generation
        ↓
Feature Engineering (per user)
        ↓
Unsupervised ML (Isolation Forest)
        ↓
Rule-Based Signals
        ↓
Risk Scoring + MITRE ATT&CK Mapping
        ↓
SOC-Ready Alerts

---

## 🔧 What This Project Does

### 1️⃣ Authentication Log Simulation
**File:** `src/generate_auth_logs.py`

- Generates realistic authentication telemetry:
  - ~150 users over multiple days
  - Successful and failed login attempts
  - Business-hours vs off-hours activity
  - Multiple IPs, devices, and geolocations
- Injects a small **high-risk user cohort** with elevated failure rates

This simulates real-world SOC authentication noise instead of toy datasets.

---

### 2️⃣ User-Level Behavioral Feature Engineering
**File:** `src/features.py`

Transforms raw logs into **per-user behavioral features**, including:

- `total_logins`
- `failed_login_ratio`
- `off_hours_ratio`
- `distinct_ips`
- `distinct_geos`
- `distinct_devices`

Features are intentionally **simple, explainable, and SOC-aligned**.

---

### 3️⃣ Unsupervised ML Anomaly Detection
**File:** `src/ml_anomaly.py`

- Uses **Isolation Forest** to model baseline user behavior
- Requires **no labeled data**
- Produces:
  - `anomaly_score` (continuous risk indicator)
  - `anomaly_flag` (outlier classification)

ML is used to **rank behavioral risk**, not replace detections.

---

### 4️⃣ Rule + ML Fusion into Risk-Scored Alerts
**File:** `src/detections.py`

Combines **security rules** with ML output:

**Rule Signals**
- High failure ratio → **MITRE T1110 (Brute Force)**
- Off-hours usage → **MITRE T1078 (Valid Accounts)**

**ML Signal**
- Increases risk when anomaly scores exceed baseline

**Final Output (per user)**
- `risk_score` (0–100)
- `severity` (`LOW`, `MEDIUM`, `HIGH`)
- `reason` (human-readable explanation)
- `mitre_technique` (ATT&CK mapping)

This mirrors how **SOC alerts must be actionable and explainable**.

---

### 5️⃣ One-Command Execution Pipeline
**File:** `src/pipeline.py`

Runs the entire workflow in sequence:
1. Generate logs  
2. Build features  
3. Compute anomaly scores  
4. Produce risk-scored alerts  

Designed for repeatability and automation.

---

## ▶️ How to Run
```bash  
conda create -n sec-ml python=3.11 -y
conda activate sec-ml
pip install -r REQUIREMENTS.TXT

python src/pipeline.py
```

## 📊 Sample Output

Below is an example of SOC-ready alerts produced by the pipeline (`src/pipeline.py`):

| user_id | risk_score | severity | reason | mitre_technique |
|-------|------------|----------|--------|-----------------|
| user_12 | 92 | HIGH | High authentication failure rate combined with anomalous login behavior | T1110 (Brute Force) |
| user_07 | 68 | MEDIUM | Off-hours authentication activity deviates from historical baseline | T1078 (Valid Accounts) |
| user_21 | 35 | LOW | Slight deviation in login frequency, below alert threshold | None |

Each alert includes:
- A normalized **risk_score (0–100)**
- Human-readable **reason** for analyst triage
- Mapped **MITRE ATT&CK technique** when applicable

This output format mirrors how alerts are consumed by SOC analysts and SIEM platforms.







