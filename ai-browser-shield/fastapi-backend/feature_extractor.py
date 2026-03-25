"""
feature_extractor.py
Extracts exactly 23 features matching phishing_model_v5 training columns.

Feature order MUST match the model's training order:
  [0]  url_length
  [1]  num_dots
  [2]  num_hyphens
  [3]  num_slashes
  [4]  num_question
  [5]  num_equal
  [6]  num_at
  [7]  num_digits
  [8]  domain_length
  [9]  subdomain_length
  [10] tld_length
  [11] subdomain_count
  [12] has_ip
  [13] has_https
  [14] has_http
  [15] keyword_count
  [16] has_digit_substitution
  [17] path_length
  [18] query_length
  [19] num_special_chars
  [20] entropy
  [21] suspicious_tld
  [22] high_risk_flag
"""

import re
import math
from urllib.parse import urlparse

# ── Heuristic lists ────────────────────────────────────────────────────────────

PHISHING_KEYWORDS = [
    "login", "signin", "sign-in", "verify", "verification",
    "bank", "secure", "account", "update", "confirm",
    "password", "credential", "auth", "authenticate",
    "paypal", "ebay", "amazon", "microsoft", "apple",
    "support", "suspend", "unusual", "limited", "restore",
]

# Common digit-for-letter substitutions used in phishing domains
DIGIT_SUBS = {"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t"}

SUSPICIOUS_TLDS = {
    ".xyz", ".top", ".click", ".gq", ".ml", ".cf", ".tk",
    ".pw", ".cc", ".ru", ".cn", ".info", ".biz", ".online",
    ".site", ".live", ".stream", ".download", ".win",
}

SPECIAL_CHAR_RE = re.compile(r'[@!#$%^&*()=+\[\]{};\'\\"|<>,?~`]')
IP_RE           = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((v / n) * math.log2(v / n) for v in freq.values())


def _has_digit_substitution(text: str) -> bool:
    restored = text.lower()
    for digit, letter in DIGIT_SUBS.items():
        restored = restored.replace(digit, letter)
    return any(kw in restored for kw in PHISHING_KEYWORDS)


def extract_features(url: str) -> list[float]:
    """
    Returns a list of 23 floats in the exact order the model was trained on.
    Never raises — returns a zero-vector on any parse error.
    """
    try:
        parsed   = urlparse(url)
        hostname = (parsed.hostname or "").lower()
        path     = parsed.path  or ""
        query    = parsed.query or ""
        full     = url.lower()

        # Domain decomposition
        parts          = hostname.split(".")
        tld            = ("." + parts[-1])    if len(parts) >= 1 else ""
        domain_part    = parts[-2]            if len(parts) >= 2 else hostname
        subdomain_part = ".".join(parts[:-2]) if len(parts) > 2  else ""
        subdomain_count = max(0, len(parts) - 2)

        return [
            float(len(url)),                                            # url_length
            float(url.count(".")),                                      # num_dots
            float(url.count("-")),                                      # num_hyphens
            float(url.count("/")),                                      # num_slashes
            float(url.count("?")),                                      # num_question
            float(url.count("=")),                                      # num_equal
            float(url.count("@")),                                      # num_at
            float(sum(c.isdigit() for c in url)),                       # num_digits
            float(len(domain_part)),                                    # domain_length
            float(len(subdomain_part)),                                 # subdomain_length
            float(len(tld)),                                            # tld_length
            float(subdomain_count),                                     # subdomain_count
            float(bool(IP_RE.match(hostname))),                         # has_ip
            float(parsed.scheme == "https"),                            # has_https
            float(parsed.scheme == "http"),                             # has_http
            float(sum(kw in full for kw in PHISHING_KEYWORDS)),         # keyword_count
            float(_has_digit_substitution(full)),                       # has_digit_substitution
            float(len(path)),                                           # path_length
            float(len(query)),                                          # query_length
            float(len(SPECIAL_CHAR_RE.findall(url))),                   # num_special_chars
            float(_entropy(url)),                                       # entropy
            float(tld in SUSPICIOUS_TLDS),                             # suspicious_tld
            float(                                                      # high_risk_flag
                bool(IP_RE.match(hostname))
                or tld in SUSPICIOUS_TLDS
                or subdomain_count > 3
                or len(url) > 100
                or url.count("@") > 0
            ),
        ]

    except Exception:
        return [0.0] * 23


FEATURE_NAMES = [
    "url_length", "num_dots", "num_hyphens", "num_slashes",
    "num_question", "num_equal", "num_at", "num_digits",
    "domain_length", "subdomain_length", "tld_length", "subdomain_count",
    "has_ip", "has_https", "has_http", "keyword_count",
    "has_digit_substitution", "path_length", "query_length",
    "num_special_chars", "entropy", "suspicious_tld", "high_risk_flag",
]
