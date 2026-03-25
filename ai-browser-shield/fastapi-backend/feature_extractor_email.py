"""Feature extraction helpers for the phishing email classifier."""

from __future__ import annotations

from dataclasses import dataclass
import json
import re
from pathlib import Path
from typing import Dict, Iterable, List, Sequence
from urllib.parse import urlparse

import numpy as np


DEFAULT_FEATURE_ORDER: List[str] = [
    "email_length",
    "word_count",
    "capital_ratio",
    "special_char_ratio",
    "urgency_score",
    "money_signal",
    "url_count",
    "has_url",
    "has_ip_url",
    "has_shortened_url",
    "suspicious_tld",
    "url_domain_mismatch",
    "sender_has_numbers",
    "free_email_provider",
    "sender_display_mismatch",
    "brand_mismatch",
    "has_attachments",
    "attachment_suspicious",
    "html_to_text_ratio",
]

URL_PATTERN = re.compile(r"https?://[^\s<>\"'{}|\\^`\[\]]+", re.IGNORECASE)
EMAIL_PATTERN = re.compile(r"[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}")
ANCHOR_PATTERN = re.compile(
    r"<a[^>]+href=[\"']([^\"']+)[\"'][^>]*>([^<]+)</a>",
    re.IGNORECASE,
)

URGENCY_KEYWORDS = (
    "urgent",
    "immediately",
    "now",
    "expire",
    "expires",
    "limited",
    "act now",
    "hurry",
    "quick",
    "asap",
    "last chance",
)
MONEY_PATTERNS = (
    r"\$\d+",
    r"rs\.?\s*\d+",
    r"inr\s*\d+",
    r"rupees?",
    r"dollars?",
    r"prize",
    r"reward",
    r"won",
    r"winner",
)
SHORTENER_DOMAINS = (
    "bit.ly",
    "tinyurl.com",
    "goo.gl",
    "t.co",
    "ow.ly",
)
SUSPICIOUS_TLDS = (
    ".xyz",
    ".tk",
    ".ml",
    ".ga",
    ".cf",
    ".top",
    ".click",
    ".link",
)
FREE_EMAIL_PROVIDERS = (
    "gmail.com",
    "yahoo.com",
    "outlook.com",
    "hotmail.com",
    "aol.com",
    "mail.com",
    "protonmail.com",
)
KNOWN_BRANDS = (
    "amazon",
    "google",
    "microsoft",
    "apple",
    "paypal",
    "netflix",
    "facebook",
    "instagram",
    "bank",
    "hdfc",
    "icici",
    "sbi",
    "axis",
    "government",
    "irs",
    "uidai",
    "aadhaar",
)
SUSPICIOUS_ATTACHMENTS = (".exe", ".zip", ".scr", ".bat", ".vbs", ".js", ".jar")


@dataclass(frozen=True)
class EmailFeatures:
    """Structured email features and supporting metadata."""

    features: Dict[str, float]
    feature_order: Sequence[str]
    urls: List[str]

    def to_vector(self) -> np.ndarray:
        """Return the feature vector in model order."""
        return np.array([self.features.get(name, 0.0) for name in self.feature_order], dtype=float)


def _safe_text(value: str | None) -> str:
    """Normalize a nullable text field to a stripped string."""
    return str(value or "").strip()


def _extract_sender_email(sender: str) -> str:
    """Extract the sender email address from a free-form sender string."""
    match = EMAIL_PATTERN.search(sender)
    return match.group(0).lower() if match else ""


def _extract_urls(text: str, links: Iterable[str]) -> List[str]:
    """Collect and de-duplicate URLs from the body and explicit link list."""
    discovered = list(URL_PATTERN.findall(text))
    discovered.extend(str(link).strip() for link in links if str(link).strip())
    unique_urls: List[str] = []
    seen: set[str] = set()
    for url in discovered:
        if url not in seen:
            seen.add(url)
            unique_urls.append(url)
    return unique_urls


def _extract_text_features(body: str) -> Dict[str, float]:
    """Compute body-level lexical features."""
    email_length = len(body)
    words = body.split()
    word_count = len(words)
    capital_ratio = sum(1 for char in body if char.isupper()) / email_length if email_length > 0 else 0.0
    special_char_ratio = sum(1 for char in body if char in "!@#$%^&*()") / email_length if email_length > 0 else 0.0
    lowered = body.lower()
    urgency_score = float(sum(1 for keyword in URGENCY_KEYWORDS if keyword in lowered))
    money_signal = float(sum(1 for pattern in MONEY_PATTERNS if re.search(pattern, lowered)))
    return {
        "email_length": float(email_length),
        "word_count": float(word_count),
        "capital_ratio": float(capital_ratio),
        "special_char_ratio": float(special_char_ratio),
        "urgency_score": urgency_score,
        "money_signal": money_signal,
    }


def _extract_url_features(body: str, urls: Sequence[str]) -> Dict[str, float]:
    """Compute link-based phishing features."""
    url_count = len(urls)
    has_url = 1.0 if url_count > 0 else 0.0
    has_ip_url = 0.0
    has_shortened_url = 0.0
    suspicious_tld = 0.0
    url_domain_mismatch = 0.0

    for url in urls:
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            if re.search(r"\d{1,3}(?:\.\d{1,3}){3}", domain):
                has_ip_url = 1.0
            if any(shortener in domain for shortener in SHORTENER_DOMAINS):
                has_shortened_url = 1.0
            if any(domain.endswith(tld) for tld in SUSPICIOUS_TLDS):
                suspicious_tld = 1.0
        except ValueError:
            continue

    for href, link_text in ANCHOR_PATTERN.findall(body):
        try:
            href_domain = urlparse(href).netloc.lower()
        except ValueError:
            continue
        normalized_text = link_text.strip().lower()
        if len(normalized_text) > 5 and normalized_text not in href_domain and href_domain not in normalized_text:
            url_domain_mismatch = 1.0
            break

    return {
        "url_count": float(url_count),
        "has_url": has_url,
        "has_ip_url": has_ip_url,
        "has_shortened_url": has_shortened_url,
        "suspicious_tld": suspicious_tld,
        "url_domain_mismatch": url_domain_mismatch,
    }


def _extract_sender_features(sender: str, body: str, subject: str) -> Dict[str, float]:
    """Compute sender-based authenticity features."""
    sender_email = _extract_sender_email(sender)
    sender_has_numbers = 0.0
    free_email_provider = 0.0
    sender_display_mismatch = 0.0
    brand_mismatch = 0.0

    if sender_email:
        local_part, _, domain = sender_email.partition("@")
        if re.search(r"\d", local_part):
            sender_has_numbers = 1.0
        if domain in FREE_EMAIL_PROVIDERS:
            free_email_provider = 1.0

        display_match = re.search(r"^([^<]+)<", sender)
        if display_match:
            display_name = display_match.group(1).strip().lower()
            if display_name and display_name not in sender_email:
                sender_display_mismatch = 1.0

        combined = f"{subject} {body}".lower()
        sender_domain = domain.replace(".com", "").replace(".org", "").replace(".in", "")
        if any(brand in combined and brand not in sender_domain for brand in KNOWN_BRANDS):
            brand_mismatch = 1.0

    return {
        "sender_has_numbers": sender_has_numbers,
        "free_email_provider": free_email_provider,
        "sender_display_mismatch": sender_display_mismatch,
        "brand_mismatch": brand_mismatch,
    }


def _extract_structural_features(body: str, has_attachments: bool, attachment_names: Sequence[str]) -> Dict[str, float]:
    """Compute structure and attachment-oriented phishing features."""
    lowered = body.lower()
    has_attachment_signal = 1.0 if has_attachments else 0.0
    attachment_suspicious = 1.0 if any(
        name.lower().endswith(ext) for name in attachment_names for ext in SUSPICIOUS_ATTACHMENTS
    ) else 0.0
    if not has_attachment_signal:
        attachment_keywords = (
            "attachment",
            "attached",
            "file attached",
            "document attached",
            "please find attached",
            "see attachment",
        )
        if any(keyword in lowered for keyword in attachment_keywords):
            has_attachment_signal = 1.0
        if any(ext in lowered for ext in SUSPICIOUS_ATTACHMENTS):
            attachment_suspicious = 1.0

    html_tags = re.findall(r"<[^>]+>", body)
    html_chars = sum(len(tag) for tag in html_tags)
    html_to_text_ratio = html_chars / len(body) if body else 0.0

    return {
        "has_attachments": has_attachment_signal,
        "attachment_suspicious": attachment_suspicious,
        "html_to_text_ratio": float(html_to_text_ratio),
    }


def load_feature_order(base_dir: Path) -> List[str]:
    """Load feature order from model metadata when available."""
    metadata_path = base_dir / "backend" / "models" / "email_model_metadata.json"
    if metadata_path.exists():
        try:
            payload = json.loads(metadata_path.read_text(encoding="utf-8"))
            feature_names = payload.get("feature_names")
            if isinstance(feature_names, list) and all(isinstance(name, str) for name in feature_names):
                return feature_names
        except (OSError, json.JSONDecodeError):
            return DEFAULT_FEATURE_ORDER.copy()
    return DEFAULT_FEATURE_ORDER.copy()


def extract_email_features(
    *,
    subject: str,
    sender: str,
    body: str,
    links: Iterable[str] | None = None,
    has_attachments: bool = False,
    attachment_names: Sequence[str] | None = None,
    feature_order: Sequence[str] | None = None,
) -> EmailFeatures:
    """Extract the full email classifier feature set."""
    normalized_subject = _safe_text(subject)
    normalized_sender = _safe_text(sender)
    normalized_body = _safe_text(body)
    safe_links = list(links or [])
    safe_attachment_names = [str(name).strip() for name in attachment_names or [] if str(name).strip()]
    urls = _extract_urls(normalized_body, safe_links)
    ordered_features = list(feature_order or DEFAULT_FEATURE_ORDER)

    features: Dict[str, float] = {}
    features.update(_extract_text_features(normalized_body))
    features.update(_extract_url_features(normalized_body, urls))
    features.update(_extract_sender_features(normalized_sender, normalized_body, normalized_subject))
    features.update(_extract_structural_features(normalized_body, has_attachments, safe_attachment_names))

    for name in ordered_features:
        features.setdefault(name, 0.0)

    return EmailFeatures(features=features, feature_order=ordered_features, urls=urls)
