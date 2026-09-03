"""
HawkEye SOC — Incidents Routes
==============================
Provides real incident management, triage, SOAR execution, and asset isolation.
"""

from typing import Any, Dict, List, Optional
from fastapi import APIRouter, HTTPException, Path
from pydantic import BaseModel

from app.schemas import (
    AnalyzeRequest,
    AnalyzeResponse,
    Incident,
    IncidentsResponse,
    RecommendedAction,
    StatusUpdateRequest,
)
from app.store import store

router = APIRouter()


@router.get("", response_model=IncidentsResponse)
@router.get("/", response_model=IncidentsResponse)
def list_incidents():
    """Return all active and correlated SOC incidents along with real-time KPIs."""
    incidents, kpis = store.get_incidents()
    from datetime import datetime, timezone
    return IncidentsResponse(
        incidents=incidents,
        kpis=kpis,
        timestamp=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    )


@router.get("/{incident_id}", response_model=Incident)
def get_incident(incident_id: str):
    """Retrieve full details of a correlated incident."""
    incident = store.get_incident_by_id(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found")
    return incident


@router.put("/{incident_id}/status")
def update_incident_status(incident_id: str, payload: StatusUpdateRequest):
    """Update incident status (ACTIVE, TRIAGING, CONTAINED, MITIGATED, CLOSED)."""
    updated = store.update_incident_status(incident_id, payload.status)
    if not updated:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found")
    return {"message": "Incident status updated", "incident": updated}


@router.post("/{incident_id}/actions/{action_id}/execute")
def execute_recommended_action(
    incident_id: str = Path(..., description="Target incident ID"),
    action_id: str = Path(..., description="Action ID to execute"),
):
    """
    Execute a SOAR containment/remediation playbook action.
    Updates asset isolation status if host quarantine action.
    """
    action = store.execute_action(incident_id, action_id)
    if not action:
        raise HTTPException(
            status_code=404,
            detail=f"Action {action_id} not found for incident {incident_id}",
        )
    return {
        "success": True,
        "message": f"Action {action.title} executed successfully",
        "action": action,
    }


@router.post("/{incident_id}/assets/{asset_id}/toggle-isolation")
def toggle_asset_isolation(
    incident_id: str = Path(..., description="Incident ID"),
    asset_id: str = Path(..., description="Asset ID to toggle"),
):
    """Toggle asset status between COMPROMISED and ISOLATED."""
    incident = store.toggle_asset_isolation(incident_id, asset_id)
    if not incident:
        raise HTTPException(
            status_code=404,
            detail=f"Asset {asset_id} or incident {incident_id} not found",
        )
    return {
        "success": True,
        "message": "Asset isolation status toggled",
        "incident": incident,
    }


@router.post("/{incident_id}/analyze", response_model=AnalyzeResponse)
def analyze_incident_scoped(incident_id: str, payload: Optional[AnalyzeRequest] = None):
    """Execute deep ML/AI analysis on a specific incident."""
    notes = payload.analystNotes if payload else None
    include_pcap = payload.includeTelemetryPcap if payload else False
    success, analysis, updated_incident = store.run_deep_analysis(
        incident_id, analyst_notes=notes, include_pcap=include_pcap
    )
    if not success or not analysis or not updated_incident:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found")
    return AnalyzeResponse(
        success=True,
        analysis=analysis,
        updatedIncident=updated_incident,
    )
