"""
HawkEye SOC — Analysis Route
============================
Handles POST /analyze from frontend triage console.
Dispatches neural and heuristic analysis pipeline.
"""

from fastapi import APIRouter, HTTPException
from app.schemas import AnalyzeRequest, AnalyzeResponse
from app.store import store

router = APIRouter()


@router.post("", response_model=AnalyzeResponse)
@router.post("/", response_model=AnalyzeResponse)
def analyze_incident(payload: AnalyzeRequest):
    """
    POST /analyze
    Executes deep causal analysis on the specified incident using the ML predictor,
    explainability engine, and risk matrix.
    """
    success, analysis, updated_incident = store.run_deep_analysis(
        incident_id=payload.incidentId,
        analyst_notes=payload.analystNotes,
        include_pcap=payload.includeTelemetryPcap or False,
    )
    if not success or not analysis or not updated_incident:
        raise HTTPException(
            status_code=404,
            detail=f"Incident '{payload.incidentId}' could not be found for analysis.",
        )

    return AnalyzeResponse(
        success=True,
        analysis=analysis,
        updatedIncident=updated_incident,
    )
