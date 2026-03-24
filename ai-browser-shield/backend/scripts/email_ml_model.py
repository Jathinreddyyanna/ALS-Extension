"""
Phishing Email Classification Model
====================================
Lightweight ML model for detecting phishing emails using RandomForest.

Features: 17 total (6 text + 6 URL + 4 sender + 1 structural)
Algorithm: RandomForestClassifier
Training Time: ~2-5 minutes on 5000 samples
"""

import re
import pickle
import json
from typing import Dict, List, Tuple
from urllib.parse import urlparse

import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, classification_report
)


# ============================================================================
# FEATURE EXTRACTION FUNCTIONS
# ============================================================================

def extract_text_features(text: str) -> Dict[str, float]:
    """
    Extract 6 text-based statistical and linguistic features.

    Args:
        text: Email body content

    Returns:
        Dictionary with 6 text features
    """
    if not text or not isinstance(text, str):
        text = ""

    # Statistical features
    email_length = len(text)
    words = text.split()
    word_count = len(words)

    # Character ratios
    if email_length > 0:
        capital_ratio = sum(1 for c in text if c.isupper()) / email_length
        special_char_ratio = sum(1 for c in text if c in '!@#$%^&*()') / email_length
    else:
        capital_ratio = 0.0
        special_char_ratio = 0.0

    # Linguistic signals
    urgency_keywords = [
        'urgent', 'immediately', 'now', 'expire', 'expires', 'limited',
        'act now', 'hurry', 'quick', 'asap', 'ending soon', 'last chance'
    ]
    text_lower = text.lower()
    urgency_score = sum(1 for keyword in urgency_keywords if keyword in text_lower)

    # Money signals
    money_patterns = [r'\$\d+', r'₹\d+', r'rupees?', r'dollars?', r'prize', r'reward', r'won', r'winner']
    money_signal = sum(1 for pattern in money_patterns if re.search(pattern, text_lower))

    return {
        'email_length': email_length,
        'word_count': word_count,
        'capital_ratio': capital_ratio,
        'special_char_ratio': special_char_ratio,
        'urgency_score': urgency_score,
        'money_signal': money_signal,
    }


def extract_urls_from_text(text: str) -> List[str]:
    """
    Extract all URLs from email text.

    Args:
        text: Email body content

    Returns:
        List of extracted URLs
    """
    if not text or not isinstance(text, str):
        return []

    # Regex pattern for URLs
    url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
    urls = re.findall(url_pattern, text, re.IGNORECASE)
    return urls


def extract_url_features(text: str) -> Dict[str, float]:
    """
    Extract 6 URL-based features from email content.

    Args:
        text: Email body content

    Returns:
        Dictionary with 6 URL features
    """
    urls = extract_urls_from_text(text)
    url_count = len(urls)
    has_url = 1.0 if url_count > 0 else 0.0

    # Initialize features
    has_ip_url = 0.0
    has_shortened_url = 0.0
    suspicious_tld = 0.0
    url_domain_mismatch = 0.0

    # Shortened URL services
    shortener_domains = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'short.link']

    # Suspicious TLDs
    suspicious_tlds = ['.xyz', '.tk', '.ml', '.ga', '.cf', '.top', '.work', '.click', '.link']

    if urls:
        for url in urls:
            try:
                parsed = urlparse(url)
                domain = parsed.netloc.lower()

                # Check for IP address in URL
                ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
                if re.search(ip_pattern, domain):
                    has_ip_url = 1.0

                # Check for URL shorteners
                if any(shortener in domain for shortener in shortener_domains):
                    has_shortened_url = 1.0

                # Check for suspicious TLDs
                if any(domain.endswith(tld) for tld in suspicious_tlds):
                    suspicious_tld = 1.0

                # URL-text mismatch detection (basic)
                # Look for anchor text like <a href="url">text</a>
                href_pattern = r'<a[^>]+href=["\']([^"\']+)["\'][^>]*>([^<]+)</a>'
                matches = re.findall(href_pattern, text, re.IGNORECASE)
                for href, link_text in matches:
                    href_domain = urlparse(href).netloc.lower()
                    if link_text.lower() not in href_domain and href_domain not in link_text.lower():
                        # Check if link text contains a brand name but URL doesn't
                        if len(link_text) > 5:  # Avoid short text false positives
                            url_domain_mismatch = 1.0
                            break

            except Exception:
                continue  # Skip malformed URLs

    return {
        'url_count': url_count,
        'has_url': has_url,
        'has_ip_url': has_ip_url,
        'has_shortened_url': has_shortened_url,
        'suspicious_tld': suspicious_tld,
        'url_domain_mismatch': url_domain_mismatch,
    }


def extract_sender_features(sender: str, text: str, subject: str = "") -> Dict[str, float]:
    """
    Extract 4 sender-based features.

    Args:
        sender: Sender email address
        text: Email body content
        subject: Email subject line

    Returns:
        Dictionary with 4 sender features
    """
    if not sender or not isinstance(sender, str):
        sender = ""

    if not text:
        text = ""

    # Initialize features
    sender_has_numbers = 0.0
    free_email_provider = 0.0
    sender_display_mismatch = 0.0
    brand_mismatch = 0.0

    # Extract email parts
    email_pattern = r'[\w\.-]+@[\w\.-]+\.\w+'
    email_match = re.search(email_pattern, sender)

    if email_match:
        email_addr = email_match.group(0).lower()

        # Check if sender has numbers
        if re.search(r'\d', email_addr.split('@')[0]):
            sender_has_numbers = 1.0

        # Check for free email providers
        free_providers = ['gmail.com', 'yahoo.com', 'outlook.com', 'hotmail.com',
                          'aol.com', 'mail.com', 'protonmail.com']
        domain = email_addr.split('@')[-1]
        if domain in free_providers:
            free_email_provider = 1.0

        # Check display name mismatch
        # Example: "Amazon Support <phisher@malicious.com>"
        display_name_pattern = r'^([^<]+)<'
        display_match = re.search(display_name_pattern, sender)
        if display_match:
            display_name = display_match.group(1).strip().lower()
            if display_name and display_name not in email_addr:
                sender_display_mismatch = 1.0

        # Brand impersonation detection
        known_brands = [
            'amazon', 'google', 'microsoft', 'apple', 'paypal', 'netflix',
            'facebook', 'instagram', 'bank', 'hdfc', 'icici', 'sbi', 'axis',
            'government', 'irs', 'uidai', 'aadhaar'
        ]
        combined_text = (text + ' ' + subject).lower()
        sender_domain = domain.replace('.com', '').replace('.org', '').replace('.in', '')

        for brand in known_brands:
            if brand in combined_text and brand not in sender_domain:
                brand_mismatch = 1.0
                break

    return {
        'sender_has_numbers': sender_has_numbers,
        'free_email_provider': free_email_provider,
        'sender_display_mismatch': sender_display_mismatch,
        'brand_mismatch': brand_mismatch,
    }


def extract_structural_features(text: str) -> Dict[str, float]:
    """
    Extract 3 structural features from email.

    Args:
        text: Email body content

    Returns:
        Dictionary with 3 structural features
    """
    if not text or not isinstance(text, str):
        text = ""

    # Attachment detection (basic - looks for attachment keywords)
    attachment_keywords = ['attachment', 'attached', 'file attached', 'document attached',
                          'please find attached', 'see attachment']
    has_attachments = 1.0 if any(kw in text.lower() for kw in attachment_keywords) else 0.0

    # Suspicious attachment extensions mentioned in text
    suspicious_extensions = ['.exe', '.zip', '.scr', '.bat', '.vbs', '.js', '.jar']
    attachment_suspicious = 1.0 if any(ext in text.lower() for ext in suspicious_extensions) else 0.0

    # HTML to text ratio (approximate)
    html_tag_pattern = r'<[^>]+>'
    html_tags = re.findall(html_tag_pattern, text)
    html_chars = sum(len(tag) for tag in html_tags)
    text_chars = len(text)

    if text_chars > 0:
        html_to_text_ratio = html_chars / text_chars
    else:
        html_to_text_ratio = 0.0

    return {
        'has_attachments': has_attachments,
        'attachment_suspicious': attachment_suspicious,
        'html_to_text_ratio': html_to_text_ratio,
    }


def extract_all_features(text: str, sender: str, subject: str = "") -> Dict[str, float]:
    """
    Extract all 17 features from an email.

    Args:
        text: Email body content
        sender: Sender email address
        subject: Email subject line (optional)

    Returns:
        Dictionary with all 17 features in fixed order
    """
    features = {}

    try:
        # Text features (6)
        features.update(extract_text_features(text))

        # URL features (6)
        features.update(extract_url_features(text))

        # Sender features (4)
        features.update(extract_sender_features(sender, text, subject))

        # Structural features (3)
        features.update(extract_structural_features(text))

    except Exception as e:
        print(f"Error extracting features: {e}")
        # Return zero features on error
        return get_zero_features()

    return features


def get_zero_features() -> Dict[str, float]:
    """Return dictionary with all features set to 0."""
    feature_names = [
        'email_length', 'word_count', 'capital_ratio', 'special_char_ratio',
        'urgency_score', 'money_signal',
        'url_count', 'has_url', 'has_ip_url', 'has_shortened_url',
        'suspicious_tld', 'url_domain_mismatch',
        'sender_has_numbers', 'free_email_provider', 'sender_display_mismatch',
        'brand_mismatch',
        'has_attachments', 'attachment_suspicious', 'html_to_text_ratio'
    ]
    return {name: 0.0 for name in feature_names}


def features_to_vector(features: Dict[str, float]) -> np.ndarray:
    """
    Convert feature dictionary to numpy array with fixed feature order.

    Args:
        features: Dictionary of features

    Returns:
        Numpy array with features in consistent order
    """
    feature_order = [
        'email_length', 'word_count', 'capital_ratio', 'special_char_ratio',
        'urgency_score', 'money_signal',
        'url_count', 'has_url', 'has_ip_url', 'has_shortened_url',
        'suspicious_tld', 'url_domain_mismatch',
        'sender_has_numbers', 'free_email_provider', 'sender_display_mismatch',
        'brand_mismatch',
        'has_attachments', 'attachment_suspicious', 'html_to_text_ratio'
    ]

    return np.array([features.get(f, 0.0) for f in feature_order])


# ============================================================================
# TRAINING PIPELINE
# ============================================================================

def load_and_preprocess_dataset(csv_path: str) -> pd.DataFrame:
    """
    Load dataset from CSV and preprocess.

    Expected CSV columns: text, sender, subject, label
    label: 0 (legitimate), 1 (phishing)

    Args:
        csv_path: Path to CSV file

    Returns:
        Preprocessed DataFrame
    """
    print(f"Loading dataset from {csv_path}...")
    df = pd.read_csv(csv_path)

    # Check required columns
    required_cols = ['text', 'sender', 'label']
    for col in required_cols:
        if col not in df.columns:
            raise ValueError(f"Missing required column: {col}")

    # Add subject column if missing
    if 'subject' not in df.columns:
        df['subject'] = ""

    # Remove duplicates
    initial_count = len(df)
    df = df.drop_duplicates(subset=['text'])
    print(f"Removed {initial_count - len(df)} duplicate emails")

    # Handle missing values
    df['text'] = df['text'].fillna("")
    df['sender'] = df['sender'].fillna("")
    df['subject'] = df['subject'].fillna("")

    # Convert labels to int
    df['label'] = df['label'].astype(int)

    print(f"Dataset loaded: {len(df)} emails")
    print(f"  - Legitimate: {sum(df['label'] == 0)}")
    print(f"  - Phishing: {sum(df['label'] == 1)}")

    return df


def extract_features_from_dataframe(df: pd.DataFrame) -> Tuple[np.ndarray, np.ndarray]:
    """
    Extract features from all emails in DataFrame.

    Args:
        df: DataFrame with text, sender, subject columns

    Returns:
        Tuple of (feature_matrix, labels)
    """
    print("Extracting features from all emails...")

    features_list = []
    for idx, row in df.iterrows():
        features = extract_all_features(
            text=row['text'],
            sender=row['sender'],
            subject=row['subject']
        )
        features_list.append(features_to_vector(features))

        if (idx + 1) % 500 == 0:
            print(f"  Processed {idx + 1}/{len(df)} emails")

    X = np.array(features_list)
    y = df['label'].values

    print(f"Feature extraction complete: {X.shape}")
    return X, y


def train_model(X_train: np.ndarray, y_train: np.ndarray) -> RandomForestClassifier:
    """
    Train RandomForest classifier.

    Args:
        X_train: Training feature matrix
        y_train: Training labels

    Returns:
        Trained model
    """
    print("\nTraining RandomForest model...")

    model = RandomForestClassifier(
        n_estimators=100,
        max_depth=20,
        min_samples_split=10,
        min_samples_leaf=4,
        class_weight='balanced',  # Handle imbalanced data
        random_state=42,
        n_jobs=-1  # Use all CPU cores
    )

    model.fit(X_train, y_train)
    print("Model training complete!")

    return model


def evaluate_model(model: RandomForestClassifier, X_test: np.ndarray, y_test: np.ndarray) -> Dict:
    """
    Evaluate model and compute all metrics.

    Args:
        model: Trained model
        X_test: Test feature matrix
        y_test: Test labels

    Returns:
        Dictionary with all metrics
    """
    print("\nEvaluating model...")

    # Predictions
    y_pred = model.predict(X_test)
    y_pred_proba = model.predict_proba(X_test)[:, 1]

    # Calculate metrics
    accuracy = accuracy_score(y_test, y_pred)
    precision = precision_score(y_test, y_pred, zero_division=0)
    recall = recall_score(y_test, y_pred, zero_division=0)
    f1 = f1_score(y_test, y_pred, zero_division=0)

    # Confusion matrix
    tn, fp, fn, tp = confusion_matrix(y_test, y_pred).ravel()
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0

    metrics = {
        'accuracy': float(accuracy),
        'precision': float(precision),
        'recall': float(recall),
        'f1_score': float(f1),
        'fpr': float(fpr),
        'confusion_matrix': {
            'tn': int(tn),
            'fp': int(fp),
            'fn': int(fn),
            'tp': int(tp)
        }
    }

    # Print results
    print("\n" + "="*60)
    print("MODEL PERFORMANCE METRICS")
    print("="*60)
    print(f"Accuracy:  {accuracy:.4f} ({accuracy*100:.2f}%)")
    print(f"Precision: {precision:.4f} ({precision*100:.2f}%)")
    print(f"Recall:    {recall:.4f} ({recall*100:.2f}%)")
    print(f"F1-Score:  {f1:.4f} ({f1*100:.2f}%)")
    print(f"FPR:       {fpr:.4f} ({fpr*100:.2f}%)")
    print("\nConfusion Matrix:")
    print(f"  TN: {tn}  FP: {fp}")
    print(f"  FN: {fn}  TP: {tp}")
    print("="*60)

    # Detailed classification report
    print("\nDetailed Classification Report:")
    print(classification_report(y_test, y_pred, target_names=['Legitimate', 'Phishing']))

    return metrics


def save_model_artifacts(model: RandomForestClassifier, metrics: Dict, output_dir: str = "../models"):
    """
    Save trained model and metadata.

    Args:
        model: Trained model
        metrics: Evaluation metrics
        output_dir: Directory to save artifacts
    """
    import os
    os.makedirs(output_dir, exist_ok=True)

    # Save model
    model_path = os.path.join(output_dir, "email_phishing_model.pkl")
    with open(model_path, 'wb') as f:
        pickle.dump(model, f)
    print(f"\nModel saved to: {model_path}")

    # Save metadata
    metadata = {
        'model_type': 'RandomForestClassifier',
        'n_features': 19,
        'feature_names': [
            'email_length', 'word_count', 'capital_ratio', 'special_char_ratio',
            'urgency_score', 'money_signal',
            'url_count', 'has_url', 'has_ip_url', 'has_shortened_url',
            'suspicious_tld', 'url_domain_mismatch',
            'sender_has_numbers', 'free_email_provider', 'sender_display_mismatch',
            'brand_mismatch',
            'has_attachments', 'attachment_suspicious', 'html_to_text_ratio'
        ],
        'metrics': metrics,
        'training_date': pd.Timestamp.now().isoformat(),
    }

    metadata_path = os.path.join(output_dir, "email_model_metadata.json")
    with open(metadata_path, 'w') as f:
        json.dump(metadata, f, indent=2)
    print(f"Metadata saved to: {metadata_path}")


def full_training_pipeline(csv_path: str, output_dir: str = "../models", test_size: float = 0.2):
    """
    Complete training pipeline from CSV to saved model.

    Args:
        csv_path: Path to training dataset CSV
        output_dir: Directory to save model artifacts
        test_size: Fraction of data for testing (default 0.2)
    """
    print("="*60)
    print("PHISHING EMAIL DETECTION - TRAINING PIPELINE")
    print("="*60)

    # Step 1: Load and preprocess
    df = load_and_preprocess_dataset(csv_path)

    # Step 2: Extract features
    X, y = extract_features_from_dataframe(df)

    # Step 3: Train-test split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=test_size, random_state=42, stratify=y
    )
    print(f"\nTrain-test split: {len(X_train)} train, {len(X_test)} test")

    # Step 4: Train model
    model = train_model(X_train, y_train)

    # Step 5: Evaluate
    metrics = evaluate_model(model, X_test, y_test)

    # Step 6: Save artifacts
    save_model_artifacts(model, metrics, output_dir)

    print("\n" + "="*60)
    print("TRAINING PIPELINE COMPLETE!")
    print("="*60)

    return model, metrics


# ============================================================================
# INFERENCE FUNCTION
# ============================================================================

# Global model cache
_MODEL_CACHE = None
_MODEL_PATH = None


def load_model(model_path: str = "../models/email_phishing_model.pkl"):
    """
    Load trained model from disk (cached).

    Args:
        model_path: Path to saved model

    Returns:
        Loaded model
    """
    global _MODEL_CACHE, _MODEL_PATH

    # Return cached model if already loaded
    if _MODEL_CACHE is not None and _MODEL_PATH == model_path:
        return _MODEL_CACHE

    # Load model
    with open(model_path, 'rb') as f:
        model = pickle.load(f)

    # Cache it
    _MODEL_CACHE = model
    _MODEL_PATH = model_path

    return model


def classify_email(
    email_text: str,
    sender: str,
    subject: str = "",
    model_path: str = "../models/email_phishing_model.pkl"
) -> Dict:
    """
    Classify a single email as phishing or legitimate.

    Args:
        email_text: Email body content
        sender: Sender email address
        subject: Email subject line (optional)
        model_path: Path to trained model

    Returns:
        Dictionary with classification results:
        {
            "label": "phishing" | "legitimate",
            "confidence": float (0.0 to 1.0),
            "probability": {"legitimate": float, "phishing": float},
            "risk_score": int (0-100),
            "risk_level": "LOW" | "MEDIUM" | "HIGH" | "CRITICAL",
            "recommended_action": "allow" | "warn" | "block"
        }
    """
    try:
        # Load model (cached)
        model = load_model(model_path)

        # Extract features
        features = extract_all_features(email_text, sender, subject)
        feature_vector = features_to_vector(features).reshape(1, -1)

        # Predict
        prediction = model.predict(feature_vector)[0]
        probabilities = model.predict_proba(feature_vector)[0]

        # Format output
        label = "phishing" if prediction == 1 else "legitimate"
        prob_legit = float(probabilities[0])
        prob_phishing = float(probabilities[1])
        confidence = max(prob_legit, prob_phishing)
        risk_score = int(prob_phishing * 100)

        # Determine risk level
        if risk_score >= 80:
            risk_level = "CRITICAL"
            action = "block"
        elif risk_score >= 60:
            risk_level = "HIGH"
            action = "warn"
        elif risk_score >= 30:
            risk_level = "MEDIUM"
            action = "warn"
        else:
            risk_level = "LOW"
            action = "allow"

        return {
            "label": label,
            "confidence": confidence,
            "probability": {
                "legitimate": prob_legit,
                "phishing": prob_phishing
            },
            "risk_score": risk_score,
            "risk_level": risk_level,
            "recommended_action": action
        }

    except FileNotFoundError:
        return {
            "label": "unknown",
            "confidence": 0.0,
            "probability": {"legitimate": 0.5, "phishing": 0.5},
            "risk_score": 50,
            "risk_level": "MEDIUM",
            "recommended_action": "warn",
            "error": f"Model file not found: {model_path}"
        }
    except Exception as e:
        return {
            "label": "unknown",
            "confidence": 0.0,
            "probability": {"legitimate": 0.5, "phishing": 0.5},
            "risk_score": 50,
            "risk_level": "MEDIUM",
            "recommended_action": "warn",
            "error": f"Classification error: {str(e)}"
        }


# ============================================================================
# MAIN EXECUTION
# ============================================================================

if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python email_ml_model.py <path_to_dataset.csv>")
        print("\nExample: python email_ml_model.py ../data/phishing_emails.csv")
        sys.exit(1)

    csv_path = sys.argv[1]

    # Run full training pipeline
    model, metrics = full_training_pipeline(csv_path)

    # Test inference
    print("\n" + "="*60)
    print("TESTING INFERENCE FUNCTION")
    print("="*60)

    test_email = """
    Dear Customer,

    Your account has been SUSPENDED due to suspicious activity.
    Click here IMMEDIATELY to verify: http://192.168.1.1/verify

    This is your LAST CHANCE before permanent deletion!

    Amazon Security Team
    """

    result = classify_email(
        email_text=test_email,
        sender="security123@amaz0n-secure.xyz",
        subject="URGENT: Account Suspended"
    )

    print(f"\nTest Email Classification:")
    print(f"  Label: {result['label']}")
    print(f"  Confidence: {result['confidence']:.2%}")
    print(f"  Risk Score: {result['risk_score']}/100")
    print(f"  Risk Level: {result['risk_level']}")
    print(f"  Action: {result['recommended_action']}")
