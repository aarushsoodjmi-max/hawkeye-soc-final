"""
HawkEye SOC — Inference / Predictor
======================================
Exposes two primary inference functions:

    load_model(model_path)          → loads and caches the model bundle
    predict_root_cause(features)    → returns root cause, confidence, and verification flags
    predict_with_probabilities(f)   → includes full probability distribution across classes

Confidence Thresholds:
    >= 0.70 → "ML-supported root cause" (high confidence)
    < 0.70  → "Low-confidence ML prediction" (analyst verification required)

No API routes, no UI, no FastAPI. Import and call directly.
"""

from __future__ import annotations

import logging
import threading
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd

# Local modules
import sys
sys.path.insert(0, str(Path(__file__).parent))
from feature_engineering import FEATURE_COLUMNS, build_feature_row

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
log = logging.getLogger("hawkeye.predictor")

# ---------------------------------------------------------------------------
# Default model path
# ---------------------------------------------------------------------------
_DEFAULT_MODEL_PATH = Path(__file__).parent / "root_cause_model.pkl"

# ---------------------------------------------------------------------------
# Thread-safe model cache
# ---------------------------------------------------------------------------
_lock = threading.Lock()
_bundle: dict[str, Any] | None = None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def load_model(model_path: str | Path | None = None) -> None:
    """
    Load (and cache) the trained model bundle from disk.
    Safe to call multiple times.
    """
    global _bundle

    resolved = Path(model_path) if model_path else _DEFAULT_MODEL_PATH

    with _lock:
        if _bundle is not None and _bundle.get("_loaded_from") == str(resolved):
            return

        if not resolved.exists():
            log.warning("Model bundle %s not found. Attempting automatic training...", resolved)
            try:
                from train_model import auto_train_if_needed
                auto_train_if_needed(resolved)
            except Exception as exc:
                raise FileNotFoundError(
                    f"Model file not found: {resolved}. Auto-training failed: {exc}"
                ) from exc

        log.info("Loading model bundle from %s …", resolved)
        bundle = joblib.load(resolved)

        for key in ("model", "label_encoder", "feature_columns"):
            if key not in bundle:
                raise RuntimeError(
                    f"Model bundle missing required key: '{key}'. Re-train model."
                )

        bundle["_loaded_from"] = str(resolved)
        _bundle = bundle
        log.info(
            "Model loaded successfully (%s). Classes: %s | Features: %d",
            bundle.get("model_type", type(bundle["model"]).__name__),
            bundle.get("classes", []),
            len(bundle["feature_columns"]),
        )


def predict_root_cause(features: dict[str, Any]) -> dict[str, Any]:
    """
    Predict root cause of an incident from its feature dict.

    Confidence rules:
      >= 0.70 → "ML-supported root cause"
      < 0.70  → "Low-confidence ML prediction" (analyst verification required)

    Returns
    -------
    dict:
      {
        "root_cause": str,
        "confidence": float,
        "confidence_status": str,
        "requires_analyst_verification": bool,
      }
    """
    if not isinstance(features, dict):
        raise ValueError(f"'features' must be a dict, got {type(features).__name__}.")

    if _bundle is None:
        load_model()

    bundle = _bundle
    clf = bundle["model"]
    le = bundle["label_encoder"]
    feat_cols = bundle["feature_columns"]

    # Build aligned feature row
    feature_df = build_feature_row(features).reindex(columns=feat_cols, fill_value=0.0)

    # Predict probabilities
    if hasattr(clf, "predict_proba"):
        proba = clf.predict_proba(feature_df)[0]
        idx = int(np.argmax(proba))
        label = str(le.inverse_transform([idx])[0])
        conf = float(proba[idx])
    else:
        label = str(le.inverse_transform(clf.predict(feature_df))[0])
        conf = 0.50

    confidence_status = "ML-supported root cause" if conf >= 0.70 else "Low-confidence ML prediction"
    requires_verification = bool(conf < 0.70)

    return {
        "root_cause": label,
        "confidence": round(conf, 4),
        "confidence_status": confidence_status,
        "requires_analyst_verification": requires_verification,
    }


def predict_with_probabilities(features: dict[str, Any]) -> dict[str, Any]:
    """
    Predict root cause and return full per-class probability distribution.
    """
    if _bundle is None:
        load_model()

    bundle = _bundle
    clf = bundle["model"]
    le = bundle["label_encoder"]
    feat_cols = bundle["feature_columns"]

    feature_df = build_feature_row(features).reindex(columns=feat_cols, fill_value=0.0)

    if hasattr(clf, "predict_proba"):
        proba = clf.predict_proba(feature_df)[0]
        idx = int(np.argmax(proba))
        label = str(le.inverse_transform([idx])[0])
        conf = float(proba[idx])
        class_proba = {
            str(cls): round(float(p), 4)
            for cls, p in zip(le.classes_, proba)
        }
    else:
        label = str(le.inverse_transform(clf.predict(feature_df))[0])
        conf = 0.50
        class_proba = {str(c): 0.20 for c in le.classes_}

    confidence_status = "ML-supported root cause" if conf >= 0.70 else "Low-confidence ML prediction"
    requires_verification = bool(conf < 0.70)

    return {
        "root_cause": label,
        "confidence": round(conf, 4),
        "confidence_status": confidence_status,
        "requires_analyst_verification": requires_verification,
        "probabilities": class_proba,
    }
