"""
CloudGuard Risk Predictor
Loads trained Random Forest model and provides robust inference for AWS configuration risks.
"""
import os
import sys
import json
import logging
from typing import Dict, Any, Union, Optional
import pandas as pd
import joblib

# Bootstrap project paths
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from ml_model.feature_extractor import (
    FEATURE_NAMES,
    FEATURE_DESCRIPTIONS,
    extract_features_from_dict,
    extract_features_from_findings,
    features_to_dataframe,
)

logger = logging.getLogger("cloudguard.ml")

MODEL_PATH = os.path.join(BASE_DIR, "ml_model", "models", "random_forest_risk_model.joblib")
METADATA_PATH = os.path.join(BASE_DIR, "ml_model", "models", "model_metadata.json")

# In-memory model cache
_CACHED_MODEL = None
_CACHED_METADATA = None


def load_model(model_path: Optional[str] = None, metadata_path: Optional[str] = None):
    """
    Loads model and metadata from disk, caching the result in memory.
    Raises FileNotFoundError with helpful instructions if artifacts are missing.
    """
    global _CACHED_MODEL, _CACHED_METADATA

    m_path = model_path or MODEL_PATH
    meta_path = metadata_path or METADATA_PATH

    if not os.path.exists(m_path):
        raise FileNotFoundError(
            f"Trained model not found at '{m_path}'. "
            "Please train the model first by executing: python ml_model/train_model.py"
        )

    _CACHED_MODEL = joblib.load(m_path)

    if os.path.exists(meta_path):
        try:
            with open(meta_path, "r") as f:
                _CACHED_METADATA = json.load(f)
        except Exception as e:
            logger.warning(f"Could not load metadata from {meta_path}: {e}")
            _CACHED_METADATA = {}
    else:
        _CACHED_METADATA = {"model_version": "1.0.0", "model_type": "RandomForestClassifier"}

    return _CACHED_MODEL, _CACHED_METADATA


def get_model_info() -> Dict[str, Any]:
    """Returns metadata regarding the active machine learning model."""
    global _CACHED_MODEL, _CACHED_METADATA

    if _CACHED_MODEL is None:
        load_model()

    return {
        "status": "ready",
        "model_path": MODEL_PATH,
        "model_version": _CACHED_METADATA.get("model_version", "1.0.0"),
        "model_type": _CACHED_METADATA.get("model_type", "RandomForestClassifier"),
        "trained_at": _CACHED_METADATA.get("trained_at", "N/A"),
        "metrics": _CACHED_METADATA.get("metrics", {}),
        "features": FEATURE_NAMES,
        "feature_descriptions": FEATURE_DESCRIPTIONS,
        "classes": _CACHED_METADATA.get("classes", ["HIGH", "LOW", "MEDIUM"]),
    }


def predict_risk(config_or_findings: Union[Dict[str, Any], list]) -> Dict[str, Any]:
    """
    Predicts the risk category (LOW, MEDIUM, or HIGH) for a given AWS configuration.

    Supports:
    - Dict with feature flags (e.g. {"ssh_port_22_open": 1, ...})
    - List of CloudGuard finding dicts (e.g. from scanner/main_scanner.py)

    Returns:
    {
        "predicted_risk": "HIGH",
        "confidence": 0.85,
        "class_probabilities": {
            "LOW": 0.05,
            "MEDIUM": 0.10,
            "HIGH": 0.85
        },
        "features": { ... },
        "active_flags": [ ... ],
        "model_version": "1.0.0",
        "disclaimer": "..."
    }
    """
    global _CACHED_MODEL, _CACHED_METADATA

    if _CACHED_MODEL is None:
        load_model()

    # 1. Normalize input features
    if isinstance(config_or_findings, list):
        features = extract_features_from_findings(config_or_findings)
    elif isinstance(config_or_findings, dict):
        # Check if dict represents findings container or direct features
        if "findings" in config_or_findings and isinstance(config_or_findings["findings"], list):
            features = extract_features_from_findings(config_or_findings["findings"])
        else:
            features = extract_features_from_dict(config_or_findings)
    else:
        raise ValueError(f"Unsupported input type for prediction: {type(config_or_findings).__name__}")

    # 2. Build DataFrame
    X_df = features_to_dataframe(features)

    # 3. Model inference
    predicted_class = str(_CACHED_MODEL.predict(X_df)[0])
    probabilities = _CACHED_MODEL.predict_proba(X_df)[0]
    classes = _CACHED_MODEL.classes_.tolist()

    class_probs = {
        cls_name: round(float(prob), 4)
        for cls_name, prob in zip(classes, probabilities)
    }

    # Ensure all expected classes exist in dictionary
    for standard_class in ["LOW", "MEDIUM", "HIGH"]:
        if standard_class not in class_probs:
            class_probs[standard_class] = 0.0

    confidence = round(float(max(probabilities)), 4)

    # Active risk flags for explainability
    active_flags = [
        {"feature": k, "description": FEATURE_DESCRIPTIONS.get(k, k)}
        for k, v in features.items()
        if v == 1
    ]

    return {
        "predicted_risk": predicted_class,
        "confidence": confidence,
        "class_probabilities": class_probs,
        "features": features,
        "active_flags": active_flags,
        "model_version": _CACHED_METADATA.get("model_version", "1.0.0"),
        "model_type": _CACHED_METADATA.get("model_type", "RandomForestClassifier"),
        "disclaimer": (
            "Statistical prediction generated by Random Forest model. "
            "Use as supplementary intelligence alongside deterministic rule-based checks; "
            "probabilities do not guarantee security status."
        ),
    }
