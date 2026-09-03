# HawkEye SOC

**AI-assisted Security Operations Center for causal alert correlation, root-cause intelligence, risk prioritization, and analyst-guided response.**

HawkEye SOC is a security operations platform that turns fragmented SIEM/EDR telemetry into correlated security incidents. Instead of treating every alert independently, it uses shared entities and time relationships to reconstruct an attack chain, estimates the probable root cause with machine learning, calculates an explainable risk score, and surfaces containment actions for an analyst.

## Why HawkEye SOC?

Modern SOC teams can receive many alerts from the same attack. The difficult part is not collecting alerts — it is understanding **which alerts belong to the same incident, what happened first, and what action should be taken safely**.

HawkEye SOC focuses on:

- **Causal alert correlation** across users, devices, IP addresses, and time.
- **Incident formation** from related alert clusters.
- **Attack timelines** with MITRE ATT&CK technique context.
- **ML-assisted root-cause prediction** using incident-level telemetry.
- **Explainable risk scoring** based on multiple security signals.
- **Analyst-guided response** through containment and asset-isolation actions.
- **Synthetic attack simulation** for repeatable demonstrations and testing.

## Core Workflow

```text
Raw Security Alerts
        ↓
Entity Resolution
(user / device / IP / timestamp)
        ↓
Causal Correlation
        ↓
Incident Formation + Timeline
        ↓
ML Root-Cause Prediction
        ↓
Explainable Risk Scoring
        ↓
Recommended / Analyst-Guided Response
```

## Key Features

### 1. Alert ingestion and triage

The backend accepts individual and batch alert telemetry and supports filtering by severity, status, incident, and search terms.

### 2. Causal correlation

Alerts are correlated using shared infrastructure and identity entities together with temporal relationships. Related alerts are grouped into incidents instead of being handled as isolated events.

### 3. Incident timeline

Correlated incidents preserve the progression of security events and associated MITRE ATT&CK techniques, helping analysts understand how an attack developed.

### 4. ML root-cause intelligence

The project includes a trained **Random Forest** classifier for probabilistic root-cause prediction. The predictor also exposes confidence and indicates when analyst verification is required.

The supported root-cause classes in the current model are:

- `benign`
- `compromised_account`
- `insider`
- `malware`
- `phishing`

The ML component is intended as decision support; it does not replace the correlation engine or the analyst.

### 5. Explainable risk scoring

The current deterministic risk engine evaluates five signals:

| Signal | Maximum contribution |
|---|---:|
| Critical alert | +30 |
| Privilege escalation | +25 |
| Sensitive data access | +20 |
| Multiple devices | +15 |
| Multiple source IPs | +10 |

Risk levels are derived from the resulting 0–100 score:

- **Critical:** 80+
- **High:** 60–79
- **Medium:** 40–59
- **Low:** 20–39
- **Informational:** below 20

### 6. Attack simulation

The simulator currently provides these synthetic scenarios:

- Credential theft
- Phishing
- Malware
- Insider threat
- Ransomware

Each scenario generates a sequence of security alerts representing a plausible attack progression and sends them through the backend pipeline.

### 7. Response actions

The incident API supports analyst-guided actions such as:

- Executing recommended incident actions.
- Toggling asset isolation.
- Updating incident status.
- Updating alert status.
- Running deeper incident analysis.

## Technology Stack

### Frontend

- React
- TypeScript
- Vite
- Tailwind CSS
- Lucide React
- Motion

### Backend

- Python
- FastAPI
- Pydantic
- Pandas
- NumPy

### Machine Learning

- Scikit-learn
- Random Forest
- Joblib

## Project Structure

```text
hawkeye-soc/
├── backend/
│   ├── app/
│   │   ├── analytics/
│   │   ├── correlation/
│   │   ├── data/
│   │   ├── ml/
│   │   ├── reporting/
│   │   ├── routes/
│   │   ├── simulator/
│   │   ├── services/
│   │   ├── main.py
│   │   ├── models.py
│   │   └── schemas.py
│   └── requirements.txt
├── frontend/
│   ├── src/
│   ├── index.html
│   └── package.json
├── README.md
└── PROJECT_STRUCTURE.md
```

## API

The current FastAPI backend exposes the following main endpoints:

| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/health` | Backend health and telemetry status |
| GET | `/alerts` | Query alerts |
| POST | `/alerts` | Ingest a single alert |
| POST | `/alerts/batch` | Ingest multiple alerts |
| GET | `/alerts/{id}` | Retrieve an alert |
| PUT | `/alerts/{id}/status` | Update alert status |
| GET | `/incidents` | List correlated incidents and KPIs |
| GET | `/incident/{id}` | Retrieve an incident |
| PUT | `/incidents/{id}/status` | Update incident status |
| POST | `/analyze` | Run deep analysis |
| POST | `/simulate` | Run an attack simulation |
| GET | `/simulator/scenarios` | List simulator scenarios |
| POST | `/incidents/{id}/actions/{id}/execute` | Execute a response action |
| POST | `/incidents/{id}/assets/{id}/toggle-isolation` | Toggle asset isolation |

FastAPI also provides interactive API documentation when the backend is running:

```text
http://localhost:8001/docs
```

## Running Locally

### 1. Backend

From the project root:

```bash
cd backend

python3.12 -m venv venv
source venv/bin/activate

pip install --upgrade pip
pip install -r requirements.txt

uvicorn app.main:app --host 0.0.0.0 --port 8001
```

### 2. Frontend

In a second terminal, from the project root:

```bash
cd frontend
npm install
npm run dev
```

The frontend is configured to run on:

```text
http://localhost:3000
```

## Verification

Check the backend health endpoint:

```bash
curl http://localhost:8001/health
```

Then open:

```text
http://localhost:3000
```

You can also inspect the API through FastAPI Swagger:

```text
http://localhost:8001/docs
```

## Data

The repository contains synthetic SOC alert telemetry under:

```text
backend/app/data/alerts.csv
```

The simulator also generates synthetic attack telemetry for repeatable testing and demonstrations.

No production security telemetry is required to run the included demo pipeline.

## Design Principles

HawkEye SOC is built around four principles:

1. **Correlate before escalating.**
2. **Find the probable root cause, not just the loudest alert.**
3. **Make risk explainable.**
4. **Keep the analyst in control of response actions.**

## Project Goal

> **Most SOC tools tell you what happened. HawkEye tells you why it happened first and what to do next.**

HawkEye SOC is designed to reduce alert fatigue and investigation overhead by transforming fragmented security alerts into an explainable, prioritized incident.

## Status

This repository contains the current hackathon implementation, including the React frontend, FastAPI backend, correlation engine, ML root-cause component, risk analytics, reporting modules, and synthetic attack simulator.
