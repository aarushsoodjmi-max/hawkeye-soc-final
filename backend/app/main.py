"""
HawkEye SOC — Unified Backend
=============================
FastAPI application entrypoint providing canonical REST endpoints for:
- GET  /alerts
- GET  /alerts/{id}
- POST /alerts (single & batch)
- PUT  /alerts/{id}/status
- GET  /incidents
- GET  /incidents/{id}
- GET  /incident/{id}
- PUT  /incidents/{id}/status
- POST /incidents/{id}/actions/{id}/execute
- POST /incidents/{id}/assets/{id}/toggle-isolation
- POST /analyze
- POST /simulate
- GET  /simulator/scenarios
- GET  /health
"""

import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import settings
from app.routes import alerts, incidents, analyze, simulator
from app.store import store

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("hawkeye.main")


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("HawkEye SOC Backend initializing...")
    logger.info("Active incidents: %d, Active alerts: %d", len(store.incidents), len(store.alerts))
    yield
    logger.info("HawkEye SOC Backend shutting down.")


app = FastAPI(
    title="HawkEye SOC Backend",
    description="Causal SOC Alert Correlation, Root Cause Intelligence, and Attack Simulation Engine",
    version="2.4.0",
    lifespan=lifespan,
)

# Configure CORS using FRONTEND_ORIGIN
frontend_origin = settings.FRONTEND_ORIGIN
allowed_origins = (
    [origin.strip() for origin in frontend_origin.split(",") if origin.strip()]
    if frontend_origin
    else ["http://localhost:3000"]
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Route registrations
app.include_router(alerts.router, prefix="/alerts", tags=["Alerts"])
app.include_router(incidents.router, prefix="/incidents", tags=["Incidents"])
app.include_router(incidents.router, prefix="/incident", tags=["Incidents"])
app.include_router(analyze.router, prefix="/analyze", tags=["Analysis"])
app.include_router(simulator.router, prefix="/simulate", tags=["Simulator"])
app.include_router(simulator.router, prefix="/simulator", tags=["Simulator"])


@app.get("/health", tags=["Health"])
def health_check():
    """Service health and telemetry check."""
    return {
        "status": "ok",
        "service": "HawkEye SOC Backend",
        "version": "2.4.0",
        "activeIncidents": len(store.incidents),
        "totalAlerts": len(store.alerts),
    }
