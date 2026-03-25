"""
predictor.py
Loads phishing_model_v5.pkl from the same directory (fastapi-backend/)
and exposes a singleton `predictor` used by main.py.
"""

import numpy as np
import joblib
from pathlib import Path
from feature_extractor import extract_features, FEATURE_NAMES

# Model sits in the same folder as this file
MODEL_PATH = Path(__file__).parent / "phishing_model_v5.pkl"


class PhishingPredictor:
    def __init__(self):
        if not MODEL_PATH.exists():
            raise FileNotFoundError(
                f"Model file not found: {MODEL_PATH}\n"
                "Make sure phishing_model_v5.pkl is inside fastapi-backend/"
            )
        print(f"[predictor] Loading model from {MODEL_PATH} ...")
        self.model = joblib.load(MODEL_PATH)
        # Warm-up: forces LightGBM to initialise its predictor thread pool
        self._warmup()
        print(f"[predictor] Ready — {self.model._n_features} features, "
              f"{self.model.n_estimators} trees")

    def _warmup(self):
        dummy = np.zeros((1, 23), dtype=np.float64)
        self.model.predict_proba(dummy)

    def predict(self, url: str) -> dict:
        """
        Returns:
          {
            "url": str,
            "phishing_probability": float,   # 0.0–1.0  (class 1 = phishing)
            "feature_values": dict,          # name → value for explainability
          }
        """
        features = extract_features(url)
        arr      = np.array([features], dtype=np.float64)
        prob     = float(self.model.predict_proba(arr)[0][1])

        return {
            "url": url,
            "phishing_probability": round(prob, 6),
            "feature_values": dict(zip(FEATURE_NAMES, features)),
        }


# ── Singleton — imported once by main.py at startup ───────────────────────────
predictor = PhishingPredictor()
