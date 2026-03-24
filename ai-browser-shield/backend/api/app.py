"""
Email Phishing Detection API - Hackathon Version
================================================
Minimal Flask API for email analysis
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
import sys
import os
import json
import re
import requests
import time
import concurrent.futures
from datetime import datetime
from urllib import request as urllib_request
from urllib import error as urllib_error

try:
    import google.generativeai as genai
except Exception:
    genai = None

# Add parent directory to path to import ML model
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'scripts'))

from train_email_model import classify_email
from explain_phishing import get_quick_explanation, format_explanation

app = Flask(__name__)

# Hackathon-safe CORS: allow frontend calls from Gmail/extension/local clients.
CORS(app)

# Lightweight in-memory sender reputation store for demo visibility.
SENDER_REPUTATION = {}

GEMINI_KEYS = [
    k for k in [
        os.getenv('GEMINI_API_KEY') or os.getenv('LLM_API_KEY'),
        os.getenv('GEMINI_API_KEY_2') or os.getenv('LLM_API_KEY_2'),
        os.getenv('GEMINI_API_KEY_3') or os.getenv('LLM_API_KEY_3'),
    ] if k
]
GEMINI_MODELS = ['gemini-2.0-flash', 'gemini-1.5-flash', 'gemini-flash-latest']
_llm_call_count = 0
LLM_DAILY_LIMIT = int(os.getenv('LLM_DAILY_LIMIT', '80'))
_last_llm_fallback_reason = 'unavailable'


def extract_links_from_text(text):
    return re.findall(r"https?://[^\s<>\"'{}|\\^`\[\]]+", str(text or ''), re.IGNORECASE)


def build_link_features(links):
    suspicious_tlds = ('.xyz', '.tk', '.ml', '.ga', '.cf', '.top', '.click', '.link')
    shortened_hosts = ('bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly')
    features = []
    for link in links:
        lower = link.lower()
        features.append({
            'url': link,
            'shortened': any(host in lower for host in shortened_hosts),
            'suspicious_tld': any(lower.endswith(tld) or ('.' + tld.lstrip('.')) in lower for tld in suspicious_tlds),
            'has_ip': bool(re.search(r'\d{1,3}(\.\d{1,3}){3}', lower)),
        })
    return features


def _safe_risk_score(value, default=50):
    try:
        score = int(round(float(value)))
    except Exception:
        if default is None:
            return None
        try:
            score = int(round(float(default)))
        except Exception:
            score = 50
    return max(0, min(100, score))


def get_risk_level(score):
    score = _safe_risk_score(score, default=50)
    if score <= 29:
        return 'LOW'
    if score <= 69:
        return 'MEDIUM'
    return 'HIGH'


def parse_llm_response(content):
    parsed = _extract_json_from_text(content)
    if not isinstance(parsed, dict):
        return None

    score = _safe_risk_score(parsed.get('llm_risk_score'), default=None)
    if score is None:
        return None

    intent = str(parsed.get('intent', '')).strip().lower()
    if intent not in {'job_scam', 'impersonation', 'financial_fraud', 'phishing', 'legitimate'}:
        return None

    reasons = parsed.get('reasons', [])
    if not isinstance(reasons, list):
        return None
    reasons = [str(item).strip() for item in reasons if str(item).strip()][:3]

    language = str(parsed.get('language', '')).strip().lower()
    if language not in {'english', 'hindi', 'telugu', 'other'}:
        language = 'other'

    return {
        'llm_risk_score': score,
        'intent': intent,
        'reasons': reasons,
        'language': language,
    }


def classify_with_llm(prompt):
    global _llm_call_count, _last_llm_fallback_reason

    if genai is None:
        _last_llm_fallback_reason = 'unavailable'
        print('[LLM ERROR RESPONSE]: google-generativeai package not available')
        return None

    if _llm_call_count >= LLM_DAILY_LIMIT:
        _last_llm_fallback_reason = 'daily_limit'
        print('[LLM] Daily quota guard hit - skipping LLM call')
        return None

    for key in GEMINI_KEYS:
        for model_name in GEMINI_MODELS:
            try:
                genai.configure(api_key=key)
                model = genai.GenerativeModel(model_name)
                response = model.generate_content(prompt)
                _llm_call_count += 1

                content = str(getattr(response, 'text', '') or '').strip()
                print('[LLM STATUS CODE]:', 200, '| model:', model_name)
                print('[LLM RAW RESPONSE]:', content)

                content = content.replace('```json', '').replace('```', '').strip()
                parsed = parse_llm_response(content)
                if parsed:
                    _last_llm_fallback_reason = ''
                    print(f"[LLM] Success - model={model_name}, calls_today={_llm_call_count}")
                    return parsed
            except Exception as e:
                err = str(e)
                if '429' in err or 'quota' in err.lower():
                    _last_llm_fallback_reason = 'quota_exceeded'
                    print('[LLM STATUS CODE]:', 429, '| model:', model_name)
                    print('[LLM ERROR RESPONSE]:', err[:300])
                    time.sleep(0.4)
                    break
                if '404' in err or 'not found' in err.lower():
                    print('[LLM STATUS CODE]:', 404, '| model:', model_name)
                    print('[LLM ERROR RESPONSE]:', err[:300])
                    continue

                _last_llm_fallback_reason = 'unavailable'
                print('[LLM ERROR RESPONSE]:', err[:300])
                return None

    if not _last_llm_fallback_reason:
        _last_llm_fallback_reason = 'unavailable'
    print('[LLM] All keys and models exhausted - falling back to ML')
    return None


def call_llm_analysis(email_text, sender_email, links, ml_score):
    try:
        prompt = f'''You are a phishing detection AI.

Analyze the email and return ONLY valid JSON:

{{
"llm_risk_score": number (0-100),
"intent": "job_scam | impersonation | financial_fraud | phishing | legitimate",
"reasons": ["reason1", "reason2", "reason3"],
"language": "english | hindi | telugu | other"
}}

Email:
{email_text}

Sender:
{sender_email}

Links:
{links}

ML_SCORE:
{ml_score}

Rules:

* Do not invent information
* Keep reasons short and clear
* Focus on real phishing signals
* Avoid false positives

Return ONLY JSON.'''

        return classify_with_llm(prompt)
    except Exception:
        return None


def classify_with_llm_timeout(email_data):
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(
                call_llm_analysis,
                email_data.get('email_text', ''),
                email_data.get('sender_email', ''),
                email_data.get('links', []),
                email_data.get('ml_score', 50),
            )
            return future.result(timeout=4)
    except concurrent.futures.TimeoutError:
        return None
    except Exception:
        return None


def merge_scores(ml_score, llm_score, has_links, text_length):
    is_text_heavy = text_length > 200

    if not has_links and is_text_heavy:
        final = 0.4 * ml_score + 0.6 * llm_score
    else:
        final = 0.7 * ml_score + 0.3 * llm_score

    return int(final)


def _extract_json_from_text(raw_text):
    if not raw_text:
        return None
    raw_text = raw_text.strip()
    try:
        return json.loads(raw_text)
    except Exception:
        pass

    start = raw_text.find('{')
    end = raw_text.rfind('}')
    if start != -1 and end != -1 and end > start:
        try:
            return json.loads(raw_text[start:end + 1])
        except Exception:
            pass

    start = raw_text.find('[')
    end = raw_text.rfind(']')
    if start != -1 and end != -1 and end > start:
        try:
            return json.loads(raw_text[start:end + 1])
        except Exception:
            pass

    return None


def _normalize_llm_assessment(obj, links):
    if not isinstance(obj, dict):
        return None

    risk_score = obj.get('risk_score', 0)
    try:
        risk_score = int(max(0, min(100, round(float(risk_score)))))
    except Exception:
        risk_score = 0

    risk_level = str(obj.get('risk_level', 'Low')).strip().title()
    if risk_level not in ('Low', 'Medium', 'High'):
        risk_level = 'Low' if risk_score < 30 else 'Medium' if risk_score < 60 else 'High'

    intent = str(obj.get('intent', 'Normal')).strip()
    allowed_intents = {
        'Job Scam', 'Bank Fraud', 'Otp Theft', 'OTP Theft', 'Account Verification', 'Delivery Scam', 'Normal'
    }
    if intent not in allowed_intents:
        intent = 'Normal'
    if intent == 'Otp Theft':
        intent = 'OTP Theft'

    user_summary = str(obj.get('user_summary', 'No major phishing indicators detected.')).strip()[:220]

    highlighted_warnings = obj.get('highlighted_warnings', [])
    if not isinstance(highlighted_warnings, list):
        highlighted_warnings = []
    highlighted_warnings = [str(x).strip() for x in highlighted_warnings if str(x).strip()][:3]

    link_analysis = obj.get('link_analysis', [])
    normalized_links = []
    if isinstance(link_analysis, list):
        for item in link_analysis:
            if not isinstance(item, dict):
                continue
            url = str(item.get('url', '')).strip()
            risk = str(item.get('risk', 'Low')).strip().title()
            if risk not in ('Low', 'Medium', 'High'):
                risk = 'Low'
            reason = str(item.get('reason', '')).strip()[:240]
            if url:
                normalized_links.append({'url': url, 'risk': risk, 'reason': reason})

    if not normalized_links and links:
        normalized_links = [{'url': u, 'risk': 'Low', 'reason': 'No explicit malicious signal from LLM output'} for u in links[:5]]

    recommended_action = str(obj.get('recommended_action', 'Safe')).strip()
    if recommended_action not in ('Safe', 'Caution', 'Do Not Click'):
        recommended_action = 'Safe' if risk_level == 'Low' else 'Caution' if risk_level == 'Medium' else 'Do Not Click'

    confidence = obj.get('confidence', 0.7)
    try:
        confidence = float(max(0.0, min(1.0, confidence)))
    except Exception:
        confidence = 0.7

    return {
        'risk_score': risk_score,
        'risk_level': risk_level,
        'intent': intent,
        'user_summary': user_summary,
        'highlighted_warnings': highlighted_warnings,
        'link_analysis': normalized_links,
        'recommended_action': recommended_action,
        'confidence': confidence,
    }


def safe_fallback():
    return {
        'risk_score': 50,
        'risk_level': 'Medium',
        'intent': 'Normal',
        'user_summary': 'Could not complete advanced analysis. Please review links and sender carefully.',
        'highlighted_warnings': ['LLM analysis unavailable, fallback to core detector.'],
        'link_analysis': [],
        'recommended_action': 'Caution',
        'confidence': 0.5,
    }


MASTER_EMAIL_PROMPT = """You are an advanced AI system for phishing email detection.

Your job is to deeply analyze an email and determine if it is malicious, suspicious, or safe.

You must combine:
- language understanding
- sender analysis
- link risk
- psychological manipulation patterns

---

INPUT:

EMAIL_CONTENT:
{email_text}

SENDER:
{sender_email}

LINKS_EXTRACTED:
{links}

LINK_FEATURES:
{link_features}

ML_SCORE:
{ml_score}

---

ANALYZE THE FOLLOWING:

1. Intent of the email
2. Presence of urgency or pressure tactics
3. Impersonation (bank, company, HR, etc.)
4. Suspicious or mismatched links
5. Emotional manipulation or social engineering

INSTRUCTIONS:
- Ensure output is consistent with structured signals
- Do not invent information not present in input

---

OUTPUT STRICT JSON:

{{
    "risk_score": number (0-100),
    "risk_level": "Low | Medium | High",
    "intent": "Job Scam | Bank Fraud | OTP Theft | Account Verification | Delivery Scam | Normal",
    "user_summary": "short one-line explanation",
    "highlighted_warnings": ["specific suspicious sentence or pattern", "another issue"],
    "link_analysis": [{{"url": "", "risk": "Low | Medium | High", "reason": ""}}],
    "recommended_action": "Safe | Caution | Do Not Click",
    "confidence": number
}}"""


INLINE_HIGHLIGHT_PROMPT = """You are an AI that identifies suspicious parts of an email.

Highlight exact phrases that indicate phishing.

INPUT:
{email_text}

INSTRUCTIONS:
- Extract only suspicious phrases
- Keep them short
- Focus on urgency, threats, fake offers, impersonation
- Do not invent information not present in input

OUTPUT:

["Verify your account immediately", "Your account will be suspended", "Click here to claim reward"]"""


MULTILINGUAL_PROMPT = """You are a multilingual phishing detection system.

Analyze the email even if it is in Hindi, Telugu, or mixed language.

INPUT:
{email_text}

OUTPUT:

{{
    "language": "",
    "risk_score": number,
    "intent": "",
    "reason": ""
}}"""


EXPLANATION_PROMPT = """Explain the phishing risk in simple terms.

INPUT:
{analysis_output}

INSTRUCTIONS:
- No technical words
- Max 2 lines
- Make user understand danger

OUTPUT:
"""""


def _call_llm_api(prompt, expect='json'):
    api_url = os.getenv('LLM_API_URL', '').strip()
    api_key = os.getenv('LLM_API_KEY', '').strip()
    model = os.getenv('LLM_MODEL', 'gpt-4o-mini').strip()
    timeout = int(os.getenv('LLM_TIMEOUT_SECONDS', '8'))

    if not api_url or not api_key:
        return None

    payload = {
        'model': model,
        'messages': [
            {'role': 'system', 'content': 'Return only valid JSON. Do not add markdown.'},
            {'role': 'user', 'content': prompt}
        ],
        'temperature': 0.1,
    }

    if expect in ('json', 'json_array'):
        payload['response_format'] = {'type': 'json_object'} if expect == 'json' else None
        if payload.get('response_format') is None:
            payload.pop('response_format', None)

    req = urllib_request.Request(
        api_url,
        data=json.dumps(payload).encode('utf-8'),
        headers={
            'Authorization': f'Bearer {api_key}',
            'Content-Type': 'application/json',
        },
        method='POST'
    )

    try:
        with urllib_request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode('utf-8', errors='ignore')
    except (urllib_error.URLError, urllib_error.HTTPError, TimeoutError) as e:
        print('[LLM] API call failed:', str(e))
        return None
    except Exception as e:
        print('[LLM] Unexpected error:', str(e))
        return None

    decoded = _extract_json_from_text(raw)
    if not isinstance(decoded, dict):
        return None

    content = None
    if 'choices' in decoded:
        try:
            content = decoded['choices'][0]['message']['content']
        except Exception:
            content = None
    elif 'output_text' in decoded:
        content = decoded.get('output_text')
    else:
        # Some providers return the JSON object directly.
        return _normalize_llm_assessment(decoded, links)

    parsed = _extract_json_from_text(content or '')
    if expect == 'json':
        return parsed if isinstance(parsed, dict) else None
    if expect == 'json_array':
        return parsed if isinstance(parsed, list) else None
    return str(content or '').strip()


def run_master_email_prompt(email_text, sender_email, links, link_features, ml_score):
    prompt = MASTER_EMAIL_PROMPT.format(
        email_text=email_text,
        sender_email=sender_email,
        links=json.dumps(links, ensure_ascii=True),
        link_features=json.dumps(link_features, ensure_ascii=True),
        ml_score=ml_score,
    )
    obj = _call_llm_api(prompt, expect='json')
    normalized = _normalize_llm_assessment(obj, links)
    return normalized if normalized else safe_fallback()


def highlight_suspicious_parts(email_text):
    prompt = INLINE_HIGHLIGHT_PROMPT.format(email_text=email_text)
    arr = _call_llm_api(prompt, expect='json_array')
    if isinstance(arr, list):
        return [str(x).strip() for x in arr if str(x).strip()][:5]
    return []


def analyze_language_and_risk(email_text):
    prompt = MULTILINGUAL_PROMPT.format(email_text=email_text)
    obj = _call_llm_api(prompt, expect='json')
    if not isinstance(obj, dict):
        return {'language': 'unknown', 'risk_score': 0, 'intent': 'Normal', 'reason': 'Unavailable'}
    return {
        'language': str(obj.get('language', 'unknown')),
        'risk_score': int(max(0, min(100, round(float(obj.get('risk_score', 0)))))) if str(obj.get('risk_score', '0')).replace('.', '', 1).isdigit() else 0,
        'intent': str(obj.get('intent', 'Normal')),
        'reason': str(obj.get('reason', '')),
    }


def generate_user_explanation(analysis_output):
    prompt = EXPLANATION_PROMPT.format(analysis_output=json.dumps(analysis_output, ensure_ascii=True))
    text = _call_llm_api(prompt, expect='text')
    return (text or '').strip()[:240]


# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def detect_features_from_text(text, sender, subject):
    """
    Simple heuristic to detect which features triggered.
    (In production, you'd track this during ML inference)
    """
    features = []

    text_lower = (text or "").lower()
    sender_lower = (sender or "").lower()
    subject_lower = (subject or "").lower()
    combined = text_lower + " " + subject_lower

    # URL features
    if any(tld in combined for tld in ['.xyz', '.tk', '.ml', '.ga', '.cf', '.top']):
        features.append('suspicious_tld')

    if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', combined):
        features.append('has_ip_url')

    if any(short in combined for short in ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co']):
        features.append('has_shortened_url')

    # Urgency signals
    urgency_words = ['urgent', 'immediately', 'expire', 'now', 'hurry', 'quick', 'asap', 'last chance']
    if any(word in combined for word in urgency_words):
        features.append('urgency_score')

    # Money signals
    money_patterns = ['₹', '$', 'prize', 'reward', 'won', 'winner', 'refund', 'claim']
    if any(pattern in combined for pattern in money_patterns):
        features.append('money_signal')

    # Sender features
    if re.search(r'\d', sender_lower.split('@')[0] if '@' in sender_lower else ''):
        features.append('sender_has_numbers')

    free_providers = ['gmail.com', 'yahoo.com', 'outlook.com', 'hotmail.com']
    if any(provider in sender_lower for provider in free_providers):
        features.append('free_email_provider')

    # Brand mismatch
    brands = ['amazon', 'google', 'hdfc', 'sbi', 'icici', 'bank', 'government', 'aadhaar']
    for brand in brands:
        if brand in combined and brand not in sender_lower:
            features.append('brand_mismatch')
            break

    # Display mismatch
    if '<' in sender and '>' in sender:
        display_part = sender.split('<')[0].strip().lower()
        email_part = sender.split('<')[1].split('>')[0].lower()
        if display_part and display_part not in email_part:
            features.append('sender_display_mismatch')

    # Link text vs URL mismatch in HTML anchors.
    href_matches = re.findall(r'<a[^>]+href=["\']([^"\']+)["\'][^>]*>([^<]+)</a>', text or '', re.IGNORECASE)
    for href, link_text in href_matches:
        href_lower = (href or '').lower()
        link_text_lower = (link_text or '').strip().lower()
        if link_text_lower and link_text_lower.startswith('http') and link_text_lower not in href_lower:
            features.append('link_text_mismatch')
            break

    # Domain similarity (e.g., amaz0n vs amazon).
    sender_domain = extract_sender_domain(sender_lower)
    if sender_domain:
        normalized_domain = normalize_lookalike(sender_domain)
        brand_targets = ['amazon', 'google', 'microsoft', 'paypal', 'hdfc', 'icici', 'sbi']
        has_digit = bool(re.search(r'\d', sender_domain))
        for brand in brand_targets:
            if brand in normalized_domain and brand not in sender_domain and has_digit:
                features.append('domain_similarity')
                break

    return features


def extract_sender_domain(sender_value):
    email_match = re.search(r'[\w\.-]+@([\w\.-]+\.\w+)', sender_value or '', re.IGNORECASE)
    return email_match.group(1).lower() if email_match else ''


def normalize_lookalike(value):
    mapping = str.maketrans({'0': 'o', '1': 'l', '3': 'e', '4': 'a', '5': 's', '7': 't', '@': 'a', '$': 's'})
    return (value or '').lower().translate(mapping)


def get_human_reasons(detected_features):
    reason_map = {
        'suspicious_tld': 'Suspicious domain extension detected (e.g., .xyz/.tk)',
        'has_ip_url': 'Contains raw IP-based link instead of normal domain',
        'has_shortened_url': 'Uses shortened URL that can hide destination',
        'urgency_score': 'Urgency language detected (pressure to act quickly)',
        'money_signal': 'Money/reward claim detected',
        'sender_has_numbers': 'Sender address pattern looks machine-generated',
        'brand_mismatch': 'Sender domain does not match claimed brand',
        'sender_display_mismatch': 'Displayed sender name mismatches actual email',
        'link_text_mismatch': 'Link text does not match actual target URL',
        'domain_similarity': 'Sender domain resembles a known brand (lookalike domain)'
    }

    reasons = [reason_map[f] for f in detected_features if f in reason_map]
    if not reasons:
        return ['Behavior pattern appears unusual based on learned phishing signals']
    return reasons[:3]


def infer_attack_type(detected_features):
    feature_set = set(detected_features)
    if 'link_text_mismatch' in feature_set:
        return 'Link Spoofing'
    if 'domain_similarity' in feature_set or 'brand_mismatch' in feature_set or 'sender_display_mismatch' in feature_set:
        return 'Brand Impersonation'
    if 'has_ip_url' in feature_set or 'suspicious_tld' in feature_set or 'has_shortened_url' in feature_set:
        return 'Malicious Link'
    if 'urgency_score' in feature_set or 'money_signal' in feature_set:
        return 'Social Engineering'
    return 'Unknown Pattern'


def update_sender_reputation(sender, flagged):
    key = (sender or '').strip().lower()
    if not key:
        return 'new'

    if key not in SENDER_REPUTATION:
        SENDER_REPUTATION[key] = {
            'first_seen': datetime.utcnow().isoformat() + 'Z',
            'seen_count': 0,
            'flagged_count': 0
        }

    entry = SENDER_REPUTATION[key]
    entry['seen_count'] += 1
    if flagged:
        entry['flagged_count'] += 1

    if entry['seen_count'] == 1:
        return 'new'
    if entry['flagged_count'] > 0:
        return 'flagged'
    return 'known'


def infer_email_type(text, subject):
    """Infer email type from content."""
    combined = (text + " " + subject).lower()

    if any(word in combined for word in ['bank', 'account', 'transaction', 'upi', 'payment']):
        return 'bank'
    elif any(word in combined for word in ['package', 'delivery', 'parcel', 'shipment']):
        return 'package'
    elif any(word in combined for word in ['prize', 'winner', 'lottery', 'won', 'congratulations']):
        return 'prize'
    elif any(word in combined for word in ['job', 'hiring', 'recruitment', 'position', 'offer']):
        return 'job'
    else:
        return 'generic'


# ============================================================================
# API ENDPOINTS
# ============================================================================

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint."""
    return jsonify({
        'status': 'ok',
        'service': 'email-phishing-detection',
        'version': '1.0'
    })


@app.route('/analyze-email', methods=['POST'])
def analyze_email():
    try:
        data = request.get_json(silent=True) or {}

        email_text = str(data.get('email_text', data.get('text', '')) or '').strip()
        sender_email = str(data.get('sender_email', data.get('sender', '')) or '').strip()

        if not email_text or not sender_email:
            return jsonify({
                'risk_score': 50,
                'risk_level': 'MEDIUM',
                'intent': 'phishing',
                'reasons': ['email_text and sender_email are required'],
                'analysis_source': 'ml_only',
                'analysis_note': 'LLM unavailable'
            }), 400

        links = extract_links_from_text(email_text)
        has_links = len(links) > 0
        text_length = len(email_text)

        ml_score = 50
        ml_intent = 'phishing'
        ml_reasons = []

        try:
            ml_result = classify_email(email_text, sender_email, '', is_spam=False)
            if isinstance(ml_result, dict):
                ml_score = _safe_risk_score(ml_result.get('risk_score', 50), default=50)
                ml_intent = 'legitimate' if ml_score < 50 else 'phishing'
                reasons = ml_result.get('reasons', [])
                if isinstance(reasons, list):
                    ml_reasons = [str(r).strip() for r in reasons if str(r).strip()][:3]
        except Exception:
            ml_score = 50

        llm_result = classify_with_llm_timeout({
            'email_text': email_text,
            'sender_email': sender_email,
            'links': links,
            'ml_score': ml_score,
        })

        if llm_result:
            final_score = merge_scores(
                ml_score,
                _safe_risk_score(llm_result.get('llm_risk_score', ml_score), default=ml_score),
                has_links,
                text_length,
            )
            final_score = _safe_risk_score(final_score, default=ml_score)
            intent = str(llm_result.get('intent', ml_intent))
            reasons = llm_result.get('reasons', [])
            if not isinstance(reasons, list):
                reasons = []
            reasons = [str(r).strip() for r in reasons if str(r).strip()][:3]
            analysis_source = 'ml+llm'
            analysis_note = 'Full AI analysis'
        else:
            final_score = _safe_risk_score(ml_score, default=50)
            intent = ml_intent
            reasons = ml_reasons
            analysis_source = 'ml_only'
            if _last_llm_fallback_reason in {'quota_exceeded', 'daily_limit'}:
                analysis_note = 'LLM quota exceeded'
            else:
                analysis_note = 'LLM unavailable'

        if not reasons:
            reasons = ['No strong phishing signal detected from available analysis']

        return jsonify({
            'risk_score': final_score,
            'risk_level': get_risk_level(final_score),
            'intent': intent,
            'reasons': reasons,
            'analysis_source': analysis_source,
            'analysis_note': analysis_note,
        }), 200

    except Exception:
        fallback_score = 50
        return jsonify({
            'risk_score': fallback_score,
            'risk_level': get_risk_level(fallback_score),
            'intent': 'phishing',
            'reasons': ['Analysis failed. Returned safe fallback result.'],
            'analysis_source': 'ml_only',
            'analysis_note': 'LLM unavailable',
        }), 200


@app.route('/warmup', methods=['GET'])
def warmup():
    test = classify_with_llm('Test. Reply with: {"llm_risk_score": 0, "intent": "legitimate", "reasons": ["ok"], "language": "english"}')
    return jsonify({'llm_available': test is not None})


@app.route('/batch-analyze', methods=['POST'])
def batch_analyze():
    """
    Analyze multiple emails at once (optional, for demo).

    Request:
        {
            "emails": [
                {"text": "...", "sender": "...", "subject": "..."},
                {"text": "...", "sender": "...", "subject": "..."}
            ]
        }
    """
    try:
        data = request.get_json()
        emails = data.get('emails', [])

        if not emails:
            return jsonify({'error': 'No emails provided'}), 400

        results = []
        for email in emails[:10]:  # Limit to 10 for demo
            text = email.get('text', '')
            sender = email.get('sender', '')
            subject = email.get('subject', '')

            if text:
                result = classify_email(text, sender, subject, is_spam=bool(email.get('is_spam', False)))
                results.append({
                    'subject': subject[:50] + '...' if len(subject) > 50 else subject,
                    'risk_score': result['risk_score'],
                    'label': result['label']
                })

        return jsonify({
            'total': len(results),
            'results': results
        }), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ============================================================================
# MAIN
# ============================================================================

if __name__ == '__main__':
    print("="*70)
    print("EMAIL PHISHING DETECTION API")
    print("="*70)
    print("\nStarting Flask server...")
    print("API will be available at: http://localhost:5000")
    print("\nEndpoints:")
    print("  GET  /health          - Health check")
    print("  POST /analyze-email   - Analyze single email")
    print("  POST /batch-analyze   - Analyze multiple emails (optional)")
    print("\nPress Ctrl+C to stop")
    print("="*70 + "\n")

    # Run server
    app.run(
        host='0.0.0.0',  # Allow external access
        port=5000,
        debug=True  # Enable debug mode for development
    )
