from __future__ import annotations

import json
import os
import re
from typing import Any

from flask import Flask, jsonify, request
from dotenv import load_dotenv

try:
    import google.generativeai as genai
except Exception:  # pragma: no cover - optional dependency during local dev
    genai = None

from detect import (
    link_risk_score,
    manipulation_score,
    predict as ml_predict,
    sender_risk_score,
)


app = Flask(__name__)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
load_dotenv(os.path.join(BASE_DIR, "../../../.env"))
MODEL_PATH = os.path.join(BASE_DIR, "clean_model.joblib")
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "").strip()
GEMINI_MODEL = os.getenv("EMAIL_EXPLAIN_MODEL", "gemini-1.5-flash")


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


def _heuristic_explanation(label: str, score: float, patterns: list[str]) -> str:
    if label == "dangerous":
        return (
            f"This message shows strong phishing or scam signals with a risk score of {round(score * 100)}%. "
            f"{'Detected signals: ' + ', '.join(patterns) + '.' if patterns else 'It uses high-risk patterns often seen in credential theft or payment scams.'}"
        )
    if label == "suspicious":
        return (
            f"This message should be treated cautiously. The estimated risk score is {round(score * 100)}%. "
            f"{'Detected signals: ' + ', '.join(patterns) + '.' if patterns else 'Some scam-like traits were detected, but they are not conclusive.'}"
        )
    return "No strong phishing or scam indicators were confirmed from the available content."


def _fallback_agent_result(
    *,
    label: str,
    score: float,
    ml_score: float,
    platform: str,
    patterns: list[str],
) -> dict[str, Any]:
    return {
        "agent_score": round(score * 100, 2),
        "detected_patterns": patterns,
        "explanation": _heuristic_explanation(label, score, patterns),
        "final_risk_label": label,
        "final_score": score,
        "ml_score": ml_score,
        "platform": platform,
        "source": "fallback",
    }


def _agent_prompt(
    *,
    subject: str,
    body: str,
    sender: str | None,
    links: list[str],
    platform: str,
    ml_score: float,
    label: str,
    patterns: list[str],
) -> str:
    return f"""You are a cybersecurity review agent analyzing email and chat content for phishing and scam risk.
Return ONLY strict JSON with this exact shape:
{{
  "agent_score": <number 0-100>,
  "detected_patterns": ["up to 6 short phrases"],
  "explanation": "2-4 sentences in plain English explaining why the content is safe, suspicious, or dangerous.",
  "final_risk_label": "safe" | "suspicious" | "dangerous"
}}

Context:
- Platform: {platform}
- Sender: {sender or "unknown"}
- Subject: {subject}
- Links: {json.dumps(links[:10])}
- ML score (0-1): {ml_score:.4f}
- Initial label: {label}
- Heuristic patterns: {json.dumps(patterns)}

Message body:
{body[:2500]}

Rules:
- Use the ML score as a strong signal, but refine the explanation with concrete reasoning.
- Be cautious with internship, fee, Google Form, impersonation, urgency, payment, account verification, and credential theft patterns.
- If the content looks like an informational bulletin or clearly benign operational notice, say so.
- Keep explanations specific and user-facing, not generic."""


def _run_explainability_agent(
    *,
    subject: str,
    body: str,
    sender: str | None,
    links: list[str],
    platform: str,
    ml_score: float,
    label: str,
    patterns: list[str],
) -> dict[str, Any] | None:
    if not GEMINI_API_KEY or not genai:
        return None

    try:
        genai.configure(api_key=GEMINI_API_KEY)
        model = genai.GenerativeModel(GEMINI_MODEL)
        response = model.generate_content(
            _agent_prompt(
                subject=subject,
                body=body,
                sender=sender,
                links=links,
                platform=platform,
                ml_score=ml_score,
                label=label,
                patterns=patterns,
            ),
            generation_config={
                "temperature": 0.1,
                "response_mime_type": "application/json",
            },
        )

        raw = (response.text or "").strip()
        parsed = json.loads(raw)
        if not parsed.get("explanation"):
          return None

        detected_patterns = parsed.get("detected_patterns")
        if not isinstance(detected_patterns, list):
            detected_patterns = patterns

        final_label = parsed.get("final_risk_label")
        if final_label not in {"safe", "suspicious", "dangerous"}:
            final_label = label

        try:
            agent_score = float(parsed.get("agent_score", round(ml_score * 100, 2)))
        except Exception:
            agent_score = round(ml_score * 100, 2)

        return {
            "agent_score": max(0.0, min(agent_score, 100.0)),
            "detected_patterns": detected_patterns[:6],
            "explanation": str(parsed.get("explanation", "")).strip(),
            "final_risk_label": final_label,
        }
    except Exception:
        return None


@app.get("/health")
def health() -> Any:
    return jsonify(
        {
            "status": "ok",
            "model_path": MODEL_PATH,
            "gemini_configured": bool(GEMINI_API_KEY),
        }
    )


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
                    "agent_score": 0.0,
                    "detected_patterns": [],
                    "explanation": "No message content found to analyze.",
                    "final_risk_label": "safe",
                    "final_score": 0.0,
                    "ml_score": 0.0,
                    "platform": platform,
                }
            )

        result = ml_predict(MODEL_PATH, text, sender)
        ml_score = float(result.get("final_score", 0.0))
        has_high_risk_intent = _has_high_risk_intent(text, links)
        is_benign_bulletin = _is_benign_bulletin(text)

        score = ml_score
        if is_benign_bulletin and not has_high_risk_intent:
            score = min(score * 0.45, 0.35)

        label = _risk_label(score, has_high_risk_intent)
        patterns = _detected_patterns(text, sender, links)
        if is_benign_bulletin and not has_high_risk_intent:
            patterns.append("Informational bulletin language")

        agent_result = _run_explainability_agent(
            subject=subject,
            body=body,
            sender=sender,
            links=links,
            platform=platform,
            ml_score=ml_score,
            label=label,
            patterns=patterns,
        )

        if agent_result is None:
            agent_result = _fallback_agent_result(
                label=label,
                score=score,
                ml_score=ml_score,
                platform=platform,
                patterns=patterns,
            )
        else:
            agent_result["final_score"] = score
            agent_result["ml_score"] = ml_score
            agent_result["platform"] = platform
            agent_result["source"] = "gemini"

        return jsonify(agent_result)
    except Exception as exc:
        return (
            jsonify(
                {
                    "agent_score": 0.0,
                    "detected_patterns": [],
                    "explanation": f"Prediction failed: {exc}",
                    "final_risk_label": "error",
                    "final_score": 0.0,
                    "ml_score": 0.0,
                    "platform": "unknown",
                    "error": str(exc),
                }
            ),
            500,
        )


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
