"""
AI Browser Shield — FastAPI Backend
Handles Gemini AI analysis + threat database
"""
import asyncio
import json
import os
import re
import time
from contextlib import asynccontextmanager
from typing import Optional
from urllib.parse import urlparse

import aiosqlite
from google import genai
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, HttpUrl, field_validator

load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), ".env"), encoding="utf-8-sig")

# ── Gemini setup ──────────────────────────────────────────────────────────────
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
GENAI_CLIENT = genai.Client() if GEMINI_API_KEY else None

DB_PATH = "data/shield.db"
CACHE_TTL = 60 * 60 * 24  # 24 hours


# ── DB init ───────────────────────────────────────────────────────────────────
async def init_db():
    os.makedirs("data", exist_ok=True)
    async with aiosqlite.connect(DB_PATH) as db:
        await db.executescript("""
            CREATE TABLE IF NOT EXISTS url_cache (
                url       TEXT PRIMARY KEY,
                result    TEXT NOT NULL,
                score     INTEGER NOT NULL DEFAULT 0,
                cached_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS reports (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                url         TEXT NOT NULL,
                domain      TEXT NOT NULL,
                category    TEXT NOT NULL,
                description TEXT,
                created_at  INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS domain_stats (
                domain       TEXT PRIMARY KEY,
                risk_score   INTEGER DEFAULT 0,
                report_count INTEGER DEFAULT 0,
                categories   TEXT DEFAULT '[]',
                updated_at   INTEGER NOT NULL
            );
        """)
        await db.commit()


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    yield


# ── App ───────────────────────────────────────────────────────────────────────
app = FastAPI(title="AI Browser Shield", version="3.0.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],           # tighten in prod to your extension ID
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)


# ── Pydantic models ───────────────────────────────────────────────────────────
class UrlScanRequest(BaseModel):
    url: str
    score: Optional[int] = None          # local score from extension (optional)
    risk_level: Optional[str] = None     # pre-computed risk level (optional)
    indicators: Optional[list[str]] = [] # heuristic flags (optional)

    @field_validator("url")
    @classmethod
    def validate_url(cls, v):
        try:
            p = urlparse(v)
            if p.scheme not in ("http", "https"):
                raise ValueError("URL must use http or https")
            if not p.netloc:
                raise ValueError("URL has no domain")
        except Exception as e:
            raise ValueError(str(e))
        return v


class FileScanRequest(BaseModel):
    filename: str
    extension: str
    mime_type: str
    size_bytes: Optional[int] = 0
    source_url: Optional[str] = ""
    content_snippet: Optional[str] = ""


class ReportRequest(BaseModel):
    url: str
    category: str
    description: Optional[str] = ""

    @field_validator("category")
    @classmethod
    def validate_category(cls, v):
        valid = {"phishing", "scam", "malware", "redirect", "popup_abuse", "other"}
        if v not in valid:
            raise ValueError(f"category must be one of: {', '.join(valid)}")
        return v


# ── Gemini helpers ────────────────────────────────────────────────────────────
async def analyze_url_with_gemini(
    url: str,
    score: int,
    risk_level: str,
    indicators: list[str],
) -> dict | None:
    if not GENAI_CLIENT:
        return None

    try:
        hostname = urlparse(url).hostname or url
    except Exception:
        hostname = url

    indicator_text = (
        f"Detected red flags: {', '.join(indicators)}"
        if indicators
        else "No specific heuristic flags"
    )

    prompt = f"""You are a cybersecurity AI for a browser extension. Analyze this URL.

URL: {url}
Domain: {hostname}
Risk Score: {score}/100 ({risk_level})
{indicator_text}

Respond ONLY in valid JSON — no markdown, no extra text:
{{
  "verdict": "SAFE or SUSPICIOUS or MALICIOUS",
  "explanation": "One clear sentence. For safe/known sites: say what it is. For phishing: name the brand being impersonated and the trick. Max 30 words.",
  "threats": ["array", "of", "specific", "threat", "details"],
  "confidence": 0.0
}}

Rules:
- youtube.com, google.com, amazon.com, microsoft.com etc → verdict=SAFE, explain what the site is
- Sites impersonating brands → verdict=MALICIOUS, name the brand
- Unknown but clean-looking → verdict=SAFE
- confidence is 0.0 to 1.0"""

    try:
        # Run in thread pool so we don't block the event loop
        loop = asyncio.get_event_loop()
        response = await loop.run_in_executor(
            None,
            lambda: GENAI_CLIENT.models.generate_content(
                model="gemini-3-flash-preview",
                contents=prompt,
            )
        )

        text = response.text.strip()
        # Strip markdown fences if model added them
        text = re.sub(r"```json\s*|\s*```", "", text).strip()

        parsed = json.loads(text)
        return {
            "verdict": parsed.get("verdict", "SAFE"),
            "explanation": parsed.get("explanation", "Analysis complete."),
            "threats": parsed.get("threats", []),
            "confidence": float(parsed.get("confidence", 0.7)),
        }

    except json.JSONDecodeError as e:
        print(f"[Gemini] JSON parse error: {e} | raw: {text[:200]}")
        return None
    except Exception as e:
        print(f"[Gemini] Error: {type(e).__name__}: {e}")
        return None


async def analyze_file_with_gemini(req: FileScanRequest) -> dict | None:
    if not GENAI_CLIENT:
        return None

    size_kb = round(req.size_bytes / 1024) if req.size_bytes else 0
    prompt = f"""You are a cybersecurity AI analyzing a downloaded file.

File: {req.filename}
Extension: {req.extension}
MIME type: {req.mime_type}
Size: {size_kb} KB
Downloaded from: {req.source_url or 'unknown'}
{f'Content preview: {req.content_snippet[:200]}' if req.content_snippet else ''}

Respond ONLY in valid JSON — no markdown, no extra text:
{{
  "verdict": "SAFE or SUSPICIOUS or MALICIOUS",
  "explanation": "Brief explanation of why (max 30 words)",
  "recommended_action": "keep or quarantine or delete",
  "confidence": 0.0,
  "indicators": ["list", "of", "concerns"]
}}"""

    try:
        loop = asyncio.get_event_loop()
        response = await loop.run_in_executor(
            None,
            lambda: GENAI_CLIENT.models.generate_content(
                model="gemini-3-flash-preview",
                contents=prompt,
            )
        )
        text = re.sub(r"```json\s*|\s*```", "", response.text.strip()).strip()
        parsed = json.loads(text)
        return {
            "verdict": parsed.get("verdict", "SAFE"),
            "explanation": parsed.get("explanation", "File scan complete."),
            "recommended_action": parsed.get("recommended_action", "keep"),
            "confidence": float(parsed.get("confidence", 0.7)),
            "indicators": parsed.get("indicators", []),
        }
    except Exception as e:
        print(f"[Gemini file] Error: {e}")
        return None


def get_fallback_explanation(score: int, risk_level: str, indicators: list[str]) -> str:
    top = f" It {indicators[0].lower()}." if indicators else ""
    if risk_level == "CRITICAL":
        return f"This site is almost certainly malicious.{top} Leave immediately."
    if risk_level == "HIGH":
        return f"Multiple suspicious signals detected.{top} Avoid entering personal info."
    if risk_level == "MEDIUM":
        return "Some unusual patterns detected. Proceed with caution."
    return "No threats detected. This site appears safe."


# ── Cache helpers ─────────────────────────────────────────────────────────────
async def get_cached(url: str) -> dict | None:
    async with aiosqlite.connect(DB_PATH) as db:
        async with db.execute(
            "SELECT result, cached_at FROM url_cache WHERE url = ?", (url,)
        ) as cur:
            row = await cur.fetchone()
    if not row:
        return None
    if time.time() - row[1] > CACHE_TTL:
        return None
    result = json.loads(row[0])
    result["cached"] = True
    return result


async def set_cached(url: str, result: dict, score: int):
    clean = {k: v for k, v in result.items() if k != "cached"}
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            "INSERT OR REPLACE INTO url_cache (url, result, score, cached_at) VALUES (?, ?, ?, ?)",
            (url, json.dumps(clean), score, int(time.time()))
        )
        await db.commit()


# ── Routes ────────────────────────────────────────────────────────────────────

@app.get("/health")
async def health():
    return {
        "status": "ok",
        "version": "3.0.0",
        "gemini": bool(GEMINI_API_KEY),
        "model": "gemini-3-flash-preview",
    }


@app.post("/api/v1/scan/url")
async def scan_url(req: UrlScanRequest):
    url = req.url
    score = req.score or 0
    risk_level = req.risk_level or ("CRITICAL" if score >= 75 else "HIGH" if score >= 55 else "MEDIUM" if score >= 30 else "LOW")
    indicators = req.indicators or []

    # Check cache first
    cached = await get_cached(url)
    if cached:
        return cached

    # Call Gemini
    gemini = await analyze_url_with_gemini(url, score, risk_level, indicators)

    if gemini:
        verdict = gemini["verdict"]
        explanation = gemini["explanation"]
        threats = gemini["threats"]
        confidence = gemini["confidence"]
        # Override risk level based on verdict if Gemini is confident
        if confidence >= 0.8:
            if verdict == "MALICIOUS" and risk_level not in ("CRITICAL", "HIGH"):
                risk_level = "HIGH"
                score = max(score, 60)
            elif verdict == "SAFE":
                risk_level = "LOW"
                score = min(score, 20)
    else:
        explanation = get_fallback_explanation(score, risk_level, indicators)
        verdict = "SAFE" if risk_level == "LOW" else "MALICIOUS" if risk_level == "CRITICAL" else "SUSPICIOUS"
        threats = indicators
        confidence = 0.5

    recommended_action = (
        "block" if risk_level == "CRITICAL" else
        "warn"  if risk_level in ("HIGH", "MEDIUM") else
        "allow"
    )

    result = {
        "explanation": explanation,
        "verdict": verdict,
        "risk_level": risk_level,
        "score": score,
        "recommended_action": recommended_action,
        "confidence": confidence,
        "key_indicators": threats[:5],
        "cached": False,
    }

    await set_cached(url, result, score)
    return result


@app.post("/api/v1/scan/file")
async def scan_file(req: FileScanRequest):
    HIGH_RISK = {".exe", ".bat", ".cmd", ".scr", ".pif", ".vbs", ".jar", ".ps1", ".reg", ".msi", ".dmg", ".app"}
    MEDIUM_RISK = {".zip", ".rar", ".7z", ".tar", ".gz", ".iso", ".docm", ".xlsm", ".pptm"}

    ext = req.extension.lower()
    local_indicators = []

    if ext in HIGH_RISK:
        local_indicators.append(f"High-risk file type: {ext}")
    elif ext in MEDIUM_RISK:
        local_indicators.append(f"Potentially risky file type: {ext}")

    gemini = await analyze_file_with_gemini(req)

    if gemini:
        return {
            "verdict": gemini["verdict"],
            "explanation": gemini["explanation"],
            "recommended_action": gemini["recommended_action"],
            "confidence": gemini["confidence"],
            "indicators": local_indicators + gemini["indicators"],
        }

    verdict = "SUSPICIOUS" if local_indicators else "SAFE"
    return {
        "verdict": verdict,
        "explanation": local_indicators[0] if local_indicators else "File appears safe.",
        "recommended_action": "quarantine" if local_indicators else "keep",
        "confidence": 0.6,
        "indicators": local_indicators,
    }


@app.post("/api/v1/reports")
async def submit_report(req: ReportRequest):
    try:
        domain = urlparse(req.url).hostname or "unknown"
    except Exception:
        domain = "unknown"

    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            "INSERT INTO reports (url, domain, category, description, created_at) VALUES (?, ?, ?, ?, ?)",
            (req.url, domain, req.category, req.description or "", int(time.time()))
        )
        # Update domain stats
        row = await (await db.execute("SELECT categories, report_count FROM domain_stats WHERE domain = ?", (domain,))).fetchone()
        if row:
            cats = json.loads(row[0])
            if req.category not in cats:
                cats.append(req.category)
            await db.execute(
                "UPDATE domain_stats SET report_count = report_count + 1, categories = ?, updated_at = ? WHERE domain = ?",
                (json.dumps(cats), int(time.time()), domain)
            )
        else:
            await db.execute(
                "INSERT INTO domain_stats (domain, risk_score, report_count, categories, updated_at) VALUES (?, 60, 1, ?, ?)",
                (domain, json.dumps([req.category]), int(time.time()))
            )
        await db.commit()

    return {"status": "ok"}


@app.get("/api/v1/reports/recent")
async def recent_reports():
    async with aiosqlite.connect(DB_PATH) as db:
        async with db.execute("""
            SELECT domain, category, COUNT(*) as reports, MAX(created_at) as last_seen
            FROM reports GROUP BY domain, category
            ORDER BY last_seen DESC LIMIT 20
        """) as cur:
            rows = await cur.fetchall()
    return [
        {
            "domain": r[0],
            "category": r[1],
            "reports": r[2],
            "risk_score": 60,
            "last_seen": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(r[3])),
        }
        for r in rows
    ]


@app.get("/api/v1/scan/domain/{domain}/score")
async def domain_score(domain: str):
    async with aiosqlite.connect(DB_PATH) as db:
        row = await (await db.execute("SELECT * FROM domain_stats WHERE domain = ?", (domain,))).fetchone()
        cache_row = await (await db.execute(
            "SELECT MAX(score) FROM url_cache WHERE url LIKE ? OR url LIKE ?",
            (f"http://{domain}%", f"https://{domain}%")
        )).fetchone()

    report_score = min(100, 50 + (row[2] * 10)) if row else 0
    cache_score = cache_row[0] or 0
    final_score = max(report_score, cache_score)

    return {
        "domain": domain,
        "risk_score": final_score,
        "report_count": row[2] if row else 0,
        "categories": json.loads(row[3]) if row else [],
        "last_updated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(row[4])) if row else time.strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
