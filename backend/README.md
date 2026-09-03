# HawkEye SOC — Backend & Analytics Engine

**Causal SOC Alert Correlation, Machine Learning Root Cause Intelligence & Risk Scoring**

The HawkEye SOC backend provides high-performance alert ingestion, temporal/entity correlation, machine learning root-cause analysis using a trained RandomForest classifier, deterministic 5-signal risk scoring, and automated SOAR response orchestration.

## Architecture & Capabilities

1. **Correlation Engine (`backend/app/correlation/`)**:
   - Clusters incoming security telemetry by host, identity, network IP, and temporal sliding windows.
   - Reconstructs end-to-end attack timelines mapped to MITRE ATT&CK tactics and techniques.

2. **Machine Learning Root Cause Classifier (`backend/app/ml/`)**:
   - Feature extractor (`feature_engineering.py`) generating a 12-dimensional vector.
   - RandomForest classifier (`root_cause_model.pkl` / `predictor.py`) predicting root causes (e.g. `compromised_account`, `ransomware`, `malware`, `phishing`, `insider`).
   - Confidence scoring and decision signal tracking.

3. **Deterministic Risk Scoring (`backend/app/analytics/risk_scoring.py`)**:
   - Weighted multi-signal risk model producing an exact score (0–100) and discrete risk levels (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFORMATIONAL`).
   - Signal weights: Critical Alert (+30), Privilege Escalation (+25), Sensitive Data Access (+20), Multiple Devices (+15), Multiple Source IPs (+10).

4. **Attack Simulation Engine**:
   - High-fidelity synthetic attack scenarios (`ransomware`, `credential_theft`, `phishing`, `malware`, `insider_threat`).
   - Generates interconnected SIEM telemetry alerts, affected assets, and timeline events for live demonstrations.

## API Endpoints

| Method | Path               | Description                                                        |
|--------|--------------------|--------------------------------------------------------------------|
| GET    | `/health`          | Health check & service readiness probe                             |
| GET    | `/alerts`          | Query ingested and simulated security alerts                       |
| POST   | `/alerts`          | Ingest raw alert telemetry & trigger automated correlation         |
| GET    | `/incidents`       | List correlated security incidents with risk scores & ML outcomes |
| GET    | `/incidents/{id}`  | Retrieve detailed incident record, timeline, and affected assets   |
| POST   | `/analyze`         | Canonical deep causal & ML analysis endpoint for SOC triage        |
| POST   | `/simulate`        | Inject synthetic attack scenario into correlation pipeline         |

## Setup & Running

```bash
cd backend
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

| POST   | `/alerts/`        | Echoes back a submitted `Alert`       |
| GET    | `/incidents/`     | Dummy list of incidents               |
## Configuration

`app/config.py` defines application settings and data persistence paths:
- `ALERTS_CSV_PATH` (default: `app/data/alerts.csv`)
- `INCIDENTS_CSV_PATH` (default: `app/data/incidents.csv`)

CORS is configured for `http://localhost:3000` by default (configurable via `FRONTEND_ORIGIN`).

