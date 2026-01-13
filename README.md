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

- Generates realistic identity telemetry:
  - 150 users over 7 days
  - Success and failure events
  - Business hours vs off-hours
  - Multiple IPs, devices, and geolocations
- Injects a small **high-risk user cohort** with elevated failure and anomaly rates

This avoids toy datasets and mirrors **real SOC ingestion challenges**.

---

### 2️⃣ User-Level Behavioral Feature Engineering
**File:** `src/features.py`

Aggregates raw logs into **per-user behavior profiles**, including:

- `total_logins`
- `failed_login_ratio`
- `off_hours_ratio`
- `distinct_ips`
- `distinct_geos`
- `distinct_devices`

Features are intentionally simple, interpretable, and extensible — matching how
security detections are built in practice.

---

### 3️⃣ Unsupervised ML Anomaly Detection
**File:** `src/ml_anomaly.py`

- Uses **Isolation Forest** to model normal user behavior
- No labels required (realistic SOC constraint)
- Produces:
  - `anomaly_score` (0–1, higher = more anomalous)
  - `anomaly_flag` (boolean outlier indicator)

ML is used to **rank behavioral risk**, not blindly classify users.

---

### 4️⃣ Rule + ML Fusion into Risk-Scored Alerts
**File:** `src/detections.py`

Combines **deterministic security rules** with ML output:

**Rule Signals**
- High failure ratio → **MITRE T1110 (Brute Force)**
- Elevated off-hours usage → **MITRE T1078 (Valid Accounts)**
- Low volume with multiple failures → early probing or credential misuse

**ML Signal**
- Increases risk when:
  - `anomaly_flag == True`
  - `anomaly_score` exceeds learned baseline

**Final Output (per user)**
- `risk_score` (0–100)
- `severity` (`LOW`, `MEDIUM`, `HIGH`)
- `reason` (human-readable justification)
- `mitre_technique` (ATT&CK mapping)

This mirrors how **SOC detections must be explainable and actionable**.

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

### Environment Setup

```bash
conda create -n sec-ml python=3.11 -y
conda activate sec-ml
pip install -r REQUIREMENTS.TXT

python src/pipeline.py


## Why This Matters (Security Perspective)

Demonstrates detection engineering, not just ML modeling

Shows how ML can reduce false positives rather than inflate alerts

Emphasizes interpretability, a critical SOC requirement

Aligns detections to MITRE ATT&CK, enabling threat-informed defense

## Future Enhancements

Time-series features (burstiness, session duration)

Per-role or peer-group baselining

Integration with SIEM-style ingestion formats

Alert suppression and decay logic

Visualization of anomaly score distributions.

