"""FastAPI entrypoint for email phishing prediction."""

from __future__ import annotations

from functools import lru_cache
import json
import logging
import os
from pathlib import Path
import pickle
from typing import Any, Dict, List, Sequence

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from feature_extractor_email import DEFAULT_FEATURE_ORDER, extract_email_features, load_feature_order


logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))
logger = logging.getLogger("ai-browser-shield-email-ml")

BASE_DIR = Path(__file__).resolve().parents[1]
MODEL_PATH = Path(os.getenv("EMAIL_MODEL_PATH", BASE_DIR / "backend" / "models" / "email_phishing_model.pkl"))
METADATA_PATH = Path(os.getenv("EMAIL_MODEL_METADATA_PATH", BASE_DIR / "backend" / "models" / "email_model_metadata.json"))


class EmailPredictionRequest(BaseModel):
    """Validated request body for phishing email prediction."""

    subject: str = Field(default="", max_length=255)
    sender: str = Field(default="", max_length=255)
    body: str = Field(default="", max_length=20000)
    links: List[str] = Field(default_factory=list)
    has_attachments: bool = Field(default=False)
    attachment_names: List[str] = Field(default_factory=list)


class EmailPredictionResponse(BaseModel):
    """Structured phishing prediction response."""

    phishing_probability: float
    decision: str
    confidence: float
    top_features: List[str]


class HealthResponse(BaseModel):
    """Health response describing model readiness."""

    status: str
    model_loaded: bool
    model_path: str
    feature_count: int
    feature_names: List[str]
    error: str | None = None


class LoadedEmailModel(BaseModel):
    """Container for model runtime metadata."""

    model: Any
    feature_names: List[str]
    model_path: str

    model_config = {"arbitrary_types_allowed": True}


def _read_metadata_feature_names() -> List[str]:
    """Read feature names from metadata if present."""
    if not METADATA_PATH.exists():
        return DEFAULT_FEATURE_ORDER.copy()
    try:
        payload = json.loads(METADATA_PATH.read_text(encoding="utf-8"))
        feature_names = payload.get("feature_names")
        if isinstance(feature_names, list) and all(isinstance(name, str) for name in feature_names):
            return feature_names
    except (OSError, json.JSONDecodeError) as error:
        logger.warning("Failed to parse email model metadata: %s", error)
    return DEFAULT_FEATURE_ORDER.copy()


@lru_cache(maxsize=1)
def load_model() -> LoadedEmailModel:
    """Load the phishing email model and infer feature order."""
    if not MODEL_PATH.exists():
        raise FileNotFoundError(f"Email phishing model not found at {MODEL_PATH}")

    with MODEL_PATH.open("rb") as handle:
        model = pickle.load(handle)

    feature_names: List[str]
    if hasattr(model, "feature_names_in_"):
        feature_names = [str(name) for name in list(model.feature_names_in_)]
    elif hasattr(model, "n_features_in_"):
        count = int(model.n_features_in_)
        metadata_names = _read_metadata_feature_names()
        feature_names = metadata_names[:count] if len(metadata_names) >= count else metadata_names
    else:
        feature_names = load_feature_order(BASE_DIR)

    if not feature_names:
        feature_names = DEFAULT_FEATURE_ORDER.copy()

    return LoadedEmailModel(
        model=model,
        feature_names=feature_names,
        model_path=str(MODEL_PATH),
    )


def _decision_from_probability(probability: float) -> str:
    """Map phishing probability to a product decision."""
    if probability >= 0.85:
        return "BLOCK"
    if probability >= 0.40:
        return "WARNING"
    return "SAFE"


def _confidence_from_probability(probability: float) -> float:
    """Convert class probability to a calibrated confidence score."""
    distance = abs(probability - 0.5) * 2
    return round(max(0.01, min(1.0, distance)), 4)


def _top_features(
    feature_names: Sequence[str],
    feature_values: Dict[str, float],
    model: Any,
    limit: int = 5,
) -> List[str]:
    """Return the most influential non-zero features for the prediction."""
    importances = getattr(model, "feature_importances_", None)
    ranked: List[tuple[str, float]] = []

    if importances is not None and len(importances) == len(feature_names):
        for name, importance in zip(feature_names, importances):
            value = float(feature_values.get(name, 0.0))
            if value <= 0:
                continue
            ranked.append((name, float(importance) * value))
    else:
        for name in feature_names:
            value = float(feature_values.get(name, 0.0))
            if value > 0:
                ranked.append((name, value))

    ranked.sort(key=lambda item: item[1], reverse=True)
    return [name for name, _ in ranked[:limit]]


def _build_health_response() -> HealthResponse:
    """Construct the current service health payload."""
    try:
        loaded = load_model()
        return HealthResponse(
            status="ok",
            model_loaded=True,
            model_path=loaded.model_path,
            feature_count=len(loaded.feature_names),
            feature_names=loaded.feature_names,
            error=None,
        )
    except Exception as error:
        logger.warning("Email model unavailable: %s", error)
        feature_names = _read_metadata_feature_names()
        return HealthResponse(
            status="degraded",
            model_loaded=False,
            model_path=str(MODEL_PATH),
            feature_count=len(feature_names),
            feature_names=feature_names,
            error=str(error),
        )


app = FastAPI(title="AI Browser Shield Email ML", version="1.0.0")


@app.on_event("startup")
def startup_event() -> None:
    """Attempt to load the model at startup and log readiness."""
    health = _build_health_response()
    if health.model_loaded:
        logger.info(
            "Email ML model loaded from %s with %s features",
            health.model_path,
            health.feature_count,
        )
        return
    logger.error("Email ML startup degraded: %s", health.error)


@app.get("/health", response_model=HealthResponse)
def health() -> HealthResponse:
    """Return model load state and feature metadata."""
    return _build_health_response()


@app.post("/predict/email", response_model=EmailPredictionResponse)
def predict_email(request: EmailPredictionRequest) -> EmailPredictionResponse:
    """Predict phishing risk for an extracted email."""
    try:
        loaded = load_model()
    except Exception as error:
        logger.error("Prediction attempted while model unavailable: %s", error)
        raise HTTPException(status_code=503, detail=f"email model unavailable: {error}") from error

    features = extract_email_features(
        subject=request.subject,
        sender=request.sender,
        body=request.body,
        links=request.links,
        has_attachments=request.has_attachments,
        attachment_names=request.attachment_names,
        feature_order=loaded.feature_names,
    )
    vector = features.to_vector().reshape(1, -1)

    if not hasattr(loaded.model, "predict_proba"):
        raise HTTPException(status_code=500, detail="loaded model does not support probability predictions")

    try:
        probabilities = loaded.model.predict_proba(vector)[0]
        phishing_probability = float(probabilities[1])
    except Exception as error:
        logger.exception("Email model prediction failed")
        raise HTTPException(status_code=500, detail=f"prediction failed: {error}") from error

    decision = _decision_from_probability(phishing_probability)
    confidence = _confidence_from_probability(phishing_probability)
    top_features = _top_features(loaded.feature_names, features.features, loaded.model)

    return EmailPredictionResponse(
        phishing_probability=round(max(0.0, min(1.0, phishing_probability)), 4),
        decision=decision,
        confidence=confidence,
        top_features=top_features,
    )
