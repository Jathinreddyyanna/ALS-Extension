from __future__ import annotations

import os
import re
from typing import Any

from flask import Flask, jsonify, request

from detect import (
    link_risk_score,
    manipulation_score,
    predict as ml_predict,
    sender_risk_score,
)


app = Flask(__name__)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(BASE_DIR, "clean_model.joblib")


def _has_high_risk_intent(text: str, links: list[str]) -> bool:
    lower = text.lower()
    high_risk_re = re.compile(
        r"verify your account|login now|update password|share otp|share pin|cvv|bank details|"
        r"transfer now|pay now|upi id|wire transfer|crypto payment|claim prize now|click here now|"
        r"account suspended|limited time",
        re.IGNORECASE,
    )
    suspicious_link_re = re.compile(r"bit\.ly|tinyurl|forms\.gle|wa\.me|t\.me|rb\.gy|goo\.gl", re.IGNORECASE)
    ip_link_re = re.compile(r"https?://\d{1,3}(?:\.\d{1,3}){3}", re.IGNORECASE)
    return bool(
        high_risk_re.search(lower)
        or suspicious_link_re.search(lower)
        or ip_link_re.search(lower)
        or any(suspicious_link_re.search(l or "") or ip_link_re.search(l or "") for l in links)
    )


def _is_benign_bulletin(text: str) -> bool:
    lower = text.lower()
    benign_re = re.compile(
        r"holiday|circular|office closed|school closed|public holiday|notice|timetable|schedule|"
        r"meeting agenda|minutes of meeting|event update|festival leave|vacation|academic calendar",
        re.IGNORECASE,
    )
    return bool(benign_re.search(lower))


def _risk_label(score: float, has_high_risk_intent: bool) -> str:
    if score >= 0.7 and has_high_risk_intent:
        return "dangerous"
    if score >= 0.4:
        return "suspicious"
    return "safe"


def _detected_patterns(text: str, sender: str | None, links: list[str]) -> list[str]:
    patterns: list[str] = []
    lower_text = text.lower()

    if links or re.search(r"http[s]?://", lower_text):
        link_score = link_risk_score(text)
        if link_score > 0:
            patterns.append("Suspicious links detected")

    if manipulation_score(text) >= 0.2:
        patterns.append("Urgency/manipulation language")

    if sender and sender_risk_score(sender, text) >= 0.3:
        patterns.append("Sender identity risk")

    if re.search(r"bit\.ly|tinyurl|forms\.gle|wa\.me|t\.me", lower_text):
        patterns.append("Shortened or redirect-style URL")

    return patterns


@app.get("/health")
def health() -> Any:
    return jsonify({"status": "ok"})


@app.post("/predict")
def predict() -> Any:
    try:
        payload = request.get_json(silent=True) or {}
        subject = str(payload.get("subject", "") or "")
        body = str(payload.get("body", "") or "")
        sender = payload.get("from") or payload.get("fromEmail") or payload.get("sender")
        sender = str(sender) if sender else None
        platform = str(payload.get("platform", "unknown") or "unknown")
        links = payload.get("links") or []
        if not isinstance(links, list):
            links = []

        text = f"{subject}\n{body}".strip()
        if not text:
            return jsonify(
                {
                    "risk_label": "safe",
                    "final_risk_label": "safe",
                    "final_score": 0.0,
                    "platform": platform,
                    "explanation": "No message content found to analyze.",
                    "detected_patterns": [],
                }
            )

        result = ml_predict(MODEL_PATH, text, sender)
        score = float(result.get("final_score", 0.0))
        has_high_risk_intent = _has_high_risk_intent(text, links)
        is_benign_bulletin = _is_benign_bulletin(text)

        # Damp false positives for benign circular/holiday announcements with no phishing intent.
        if is_benign_bulletin and not has_high_risk_intent:
            score = min(score * 0.45, 0.35)

        label = _risk_label(score, has_high_risk_intent)

        patterns = _detected_patterns(text, sender, links)
        if is_benign_bulletin and not has_high_risk_intent:
            patterns.append("Informational bulletin language")
        explanation = (
            f"ML risk score is {round(score * 100)}%. "
            f"Classified as {label}. "
            f"{'Detected signals: ' + ', '.join(patterns) + '.' if patterns else 'No strong risk patterns detected.'}"
        )

        return jsonify(
            {
                "risk_label": label,
                "final_risk_label": label,
                "final_score": score,
                "platform": platform,
                "explanation": explanation,
                "detected_patterns": patterns,
                "ml_probability": float(result.get("ml_probability", score)),
            }
        )
    except Exception as exc:
        return (
            jsonify(
                {
                    "risk_label": "error",
                    "final_risk_label": "error",
                    "final_score": 0.0,
                    "platform": "unknown",
                    "explanation": f"Prediction failed: {exc}",
                    "detected_patterns": [],
                    "error": str(exc),
                }
            ),
            500,
        )


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
