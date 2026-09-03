"""
risk_scoring.py
================

Weighted, rule-based (no ML) risk scoring for a single correlated incident.

Score is built from five independent signals, each contributing a fixed
weight when present. Weights were chosen so the maximum possible score is
exactly 100:

    +---------------------------+--------+
    | Signal                    | Weight |
    +---------------------------+--------+
    | Critical severity alert   |   30   |
    | Privilege escalation      |   25   |
    | Sensitive data access     |   20   |
    | Multiple devices involved |   15   |
    | Multiple source IPs       |   10   |
    +---------------------------+--------+
    | Maximum                   |  100   |
    +---------------------------+--------+

Dependencies: none beyond the standard library.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------

WEIGHTS: Dict[str, int] = {
    "critical_alert": 30,
    "privilege_escalation": 25,
    "data_access": 20,
    "multiple_devices": 15,
    "multiple_ips": 10,
}

# Keyword fragments (case-insensitive substring match) used to detect
# privilege-escalation and data-access techniques from an incident's
# "techniques" list. Kept intentionally small/explicit for auditability -
# extend as new detection content is onboarded.
PRIVILEGE_ESCALATION_KEYWORDS = [
    "privilege escalation",
    "token manipulation",
    "uac bypass",
]

DATA_ACCESS_KEYWORDS = [
    "data access",
    "sensitive data",
    "file access",
    "database access",
    "exfiltration",
]

# Risk-level thresholds (inclusive lower bound), evaluated highest-first.
RISK_LEVEL_THRESHOLDS: List[tuple] = [
    (80, "Critical"),
    (60, "High"),
    (40, "Medium"),
    (20, "Low"),
    (0, "Informational"),
]


# --------------------------------------------------------------------------
# Internal helpers
# --------------------------------------------------------------------------

def _has_critical_alert(incident: Dict[str, Any]) -> bool:
    """True if the incident itself, or any nested alert, is Critical severity."""
    if str(incident.get("severity") or "").strip().lower() == "critical":
        return True
    for alert in incident.get("alerts") or []:
        if str(alert.get("severity") or "").strip().lower() == "critical":
            return True
    return False


def _techniques_lower(incident: Dict[str, Any]) -> List[str]:
    return [str(t).strip().lower() for t in (incident.get("techniques") or [])]


def _has_keyword(techniques_lower: List[str], keywords: List[str]) -> bool:
    return any(kw in tech for tech in techniques_lower for kw in keywords)


def _has_multiple_devices(incident: Dict[str, Any]) -> bool:
    return len(set(incident.get("devices") or [])) > 1


def _has_multiple_ips(incident: Dict[str, Any]) -> bool:
    return len(set(incident.get("ips") or [])) > 1


def _risk_level_for_score(score: int) -> str:
    for lower_bound, label in RISK_LEVEL_THRESHOLDS:
        if score >= lower_bound:
            return label
    return "Informational"  # unreachable safeguard


# --------------------------------------------------------------------------
# Public API
# --------------------------------------------------------------------------

def calculate_risk_score(incident: Dict[str, Any]) -> Dict[str, Any]:
    """
    Calculate a 0-100 risk score for a single correlated incident.

    Parameters
    ----------
    incident : dict
        Expected fields (all optional, read defensively):
            "severity"   : str                 e.g. "Critical"
            "alerts"     : list[dict]           each optionally with "severity"
            "techniques" : list[str]            e.g. ["privilege escalation", ...]
            "devices"    : list[str]
            "ips"        : list[str]

    Returns
    -------
    dict
        {
            "incident_id": str | None,
            "risk_score": int,        # 0-100
            "risk_level": str,        # Informational | Low | Medium | High | Critical
            "breakdown": {
                "critical_alert": {"triggered": bool, "points": int},
                "privilege_escalation": {"triggered": bool, "points": int},
                "data_access": {"triggered": bool, "points": int},
                "multiple_devices": {"triggered": bool, "points": int},
                "multiple_ips": {"triggered": bool, "points": int},
            }
        }
    """
    techniques_lower = _techniques_lower(incident)

    signals = {
        "critical_alert": _has_critical_alert(incident),
        "privilege_escalation": _has_keyword(techniques_lower, PRIVILEGE_ESCALATION_KEYWORDS),
        "data_access": _has_keyword(techniques_lower, DATA_ACCESS_KEYWORDS),
        "multiple_devices": _has_multiple_devices(incident),
        "multiple_ips": _has_multiple_ips(incident),
    }

    breakdown = {
        name: {
            "triggered": triggered,
            "points": WEIGHTS[name] if triggered else 0,
        }
        for name, triggered in signals.items()
    }

    raw_score = sum(item["points"] for item in breakdown.values())
    risk_score = min(raw_score, 100)  # weights already sum to 100, this is a safeguard

    return {
        "incident_id": incident.get("incident_id"),
        "risk_score": risk_score,
        "risk_level": _risk_level_for_score(risk_score),
        "breakdown": breakdown,
    }


def score_incidents(incidents: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Batch convenience wrapper around ``calculate_risk_score``."""
    return [calculate_risk_score(incident) for incident in (incidents or [])]


def average_risk_score(incidents: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Aggregate risk statistics across a set of incidents - useful for a SOC
    dashboard "overall risk posture" widget.

    Returns
    -------
    dict
        {
            "average_risk_score": float,
            "highest_risk_score": int,
            "risk_level_counts": {"Critical": 2, "High": 3, ...},
            "incident_count": int,
        }
    """
    scored = score_incidents(incidents)
    if not scored:
        return {
            "average_risk_score": 0.0,
            "highest_risk_score": 0,
            "risk_level_counts": {},
            "incident_count": 0,
        }

    scores = [s["risk_score"] for s in scored]
    level_counts: Dict[str, int] = {}
    for s in scored:
        level_counts[s["risk_level"]] = level_counts.get(s["risk_level"], 0) + 1

    return {
        "average_risk_score": round(sum(scores) / len(scores), 2),
        "highest_risk_score": max(scores),
        "risk_level_counts": level_counts,
        "incident_count": len(scored),
    }
