"""
Email Phishing ML Model - Complete Training Script
==================================================
Single file solution: Load data → Extract features → Train → Evaluate → Save
"""

import pandas as pd
import numpy as np
import pickle
import json
import re
from urllib.parse import urlparse
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix


# ============================================================================
# FEATURE EXTRACTION
# ============================================================================

def extract_features(text, sender, subject):
    """Extract all 19 features from email."""
    features = {}

    # Ensure strings
    text = str(text) if text else ""
    sender = str(sender) if sender else ""
    subject = str(subject) if subject else ""

    # --- TEXT FEATURES (6) ---
    email_length = len(text)
    words = text.split()
    word_count = len(words)

    if email_length > 0:
        capital_ratio = sum(1 for c in text if c.isupper()) / email_length
        special_char_ratio = sum(1 for c in text if c in '!@#$%^&*()') / email_length
    else:
        capital_ratio = 0.0
        special_char_ratio = 0.0

    urgency_keywords = ['urgent', 'immediately', 'now', 'expire', 'expires', 'limited',
                        'act now', 'hurry', 'quick', 'asap', 'last chance']
    urgency_score = sum(1 for kw in urgency_keywords if kw in text.lower())

    money_patterns = [r'\$\d+', r'₹\d+', r'rupees?', r'dollars?', r'prize', r'reward', r'won', r'winner']
    money_signal = sum(1 for p in money_patterns if re.search(p, text.lower()))

    features['email_length'] = email_length
    features['word_count'] = word_count
    features['capital_ratio'] = capital_ratio
    features['special_char_ratio'] = special_char_ratio
    features['urgency_score'] = urgency_score
    features['money_signal'] = money_signal

    # --- URL FEATURES (6) ---
    url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
    urls = re.findall(url_pattern, text, re.IGNORECASE)
    url_count = len(urls)
    has_url = 1.0 if url_count > 0 else 0.0

    has_ip_url = 0.0
    has_shortened_url = 0.0
    suspicious_tld = 0.0
    url_domain_mismatch = 0.0

    shorteners = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly']
    suspicious_tlds = ['.xyz', '.tk', '.ml', '.ga', '.cf', '.top', '.click', '.link']

    for url in urls:
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()

            if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', domain):
                has_ip_url = 1.0

            if any(s in domain for s in shorteners):
                has_shortened_url = 1.0

            if any(domain.endswith(tld) for tld in suspicious_tlds):
                suspicious_tld = 1.0

            # Check URL-text mismatch
            href_matches = re.findall(r'<a[^>]+href=["\']([^"\']+)["\'][^>]*>([^<]+)</a>', text, re.IGNORECASE)
            for href, link_text in href_matches:
                href_domain = urlparse(href).netloc.lower()
                if link_text.lower() not in href_domain and href_domain not in link_text.lower():
                    if len(link_text) > 5:
                        url_domain_mismatch = 1.0
                        break
        except:
            continue

    features['url_count'] = url_count
    features['has_url'] = has_url
    features['has_ip_url'] = has_ip_url
    features['has_shortened_url'] = has_shortened_url
    features['suspicious_tld'] = suspicious_tld
    features['url_domain_mismatch'] = url_domain_mismatch

    # --- SENDER FEATURES (4) ---
    sender_has_numbers = 0.0
    free_email_provider = 0.0
    sender_display_mismatch = 0.0
    brand_mismatch = 0.0

    email_match = re.search(r'[\w\.-]+@[\w\.-]+\.\w+', sender)
    if email_match:
        email_addr = email_match.group(0).lower()

        if re.search(r'\d', email_addr.split('@')[0]):
            sender_has_numbers = 1.0

        free_providers = ['gmail.com', 'yahoo.com', 'outlook.com', 'hotmail.com', 'aol.com']
        domain = email_addr.split('@')[-1]
        if domain in free_providers:
            free_email_provider = 1.0

        display_match = re.search(r'^([^<]+)<', sender)
        if display_match:
            display_name = display_match.group(1).strip().lower()
            if display_name and display_name not in email_addr:
                sender_display_mismatch = 1.0

        brands = ['amazon', 'google', 'microsoft', 'apple', 'paypal', 'netflix',
                  'bank', 'hdfc', 'icici', 'sbi', 'government', 'aadhaar']
        combined = (text + ' ' + subject).lower()
        sender_domain = domain.replace('.com', '').replace('.org', '').replace('.in', '')

        for brand in brands:
            if brand in combined and brand not in sender_domain:
                brand_mismatch = 1.0
                break

    features['sender_has_numbers'] = sender_has_numbers
    features['free_email_provider'] = free_email_provider
    features['sender_display_mismatch'] = sender_display_mismatch
    features['brand_mismatch'] = brand_mismatch

    # --- STRUCTURAL FEATURES (3) ---
    attachment_keywords = ['attachment', 'attached', 'file attached', 'please find attached']
    has_attachments = 1.0 if any(kw in text.lower() for kw in attachment_keywords) else 0.0

    suspicious_exts = ['.exe', '.zip', '.scr', '.bat', '.vbs', '.js', '.jar']
    attachment_suspicious = 1.0 if any(ext in text.lower() for ext in suspicious_exts) else 0.0

    html_tags = re.findall(r'<[^>]+>', text)
    html_chars = sum(len(tag) for tag in html_tags)
    html_to_text_ratio = html_chars / len(text) if len(text) > 0 else 0.0

    features['has_attachments'] = has_attachments
    features['attachment_suspicious'] = attachment_suspicious
    features['html_to_text_ratio'] = html_to_text_ratio

    return features


def features_to_array(features):
    """Convert feature dict to numpy array in fixed order."""
    order = [
        'email_length', 'word_count', 'capital_ratio', 'special_char_ratio',
        'urgency_score', 'money_signal',
        'url_count', 'has_url', 'has_ip_url', 'has_shortened_url',
        'suspicious_tld', 'url_domain_mismatch',
        'sender_has_numbers', 'free_email_provider', 'sender_display_mismatch',
        'brand_mismatch',
        'has_attachments', 'attachment_suspicious', 'html_to_text_ratio'
    ]
    return np.array([features.get(f, 0.0) for f in order])


# ============================================================================
# TRAINING
# ============================================================================

def train_model(csv_path='../data/cleaned_emails.csv'):
    """Load data, train model, evaluate, and save."""

    print("="*60)
    print("EMAIL PHISHING MODEL TRAINING")
    print("="*60)

    # Load dataset
    print(f"\n[1/6] Loading dataset from {csv_path}...")
    df = pd.read_csv(csv_path)
    print(f"      Loaded {len(df)} emails")
    print(f"      Phishing: {sum(df['label'] == 1)}, Legitimate: {sum(df['label'] == 0)}")

    # Extract features
    print("\n[2/6] Extracting features...")
    X_list = []
    for idx, row in df.iterrows():
        feats = extract_features(row['text'], row['sender'], row['subject'])
        X_list.append(features_to_array(feats))
        if (idx + 1) % 1000 == 0:
            print(f"      Processed {idx + 1}/{len(df)} emails")

    X = np.array(X_list)
    y = df['label'].values
    print(f"      Feature matrix: {X.shape}")

    # Train-test split
    print("\n[3/6] Splitting data (80% train, 20% test)...")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    print(f"      Train: {len(X_train)}, Test: {len(X_test)}")

    # Train model
    print("\n[4/6] Training RandomForest (this may take 5-10 minutes)...")
    model = RandomForestClassifier(
        n_estimators=100,
        max_depth=20,
        min_samples_split=10,
        min_samples_leaf=4,
        class_weight='balanced',
        random_state=42,
        n_jobs=-1
    )
    model.fit(X_train, y_train)
    print("      Training complete!")

    # Evaluate
    print("\n[5/6] Evaluating model...")
    y_pred = model.predict(X_test)

    accuracy = accuracy_score(y_test, y_pred)
    precision = precision_score(y_test, y_pred, zero_division=0)
    recall = recall_score(y_test, y_pred, zero_division=0)
    f1 = f1_score(y_test, y_pred, zero_division=0)

    tn, fp, fn, tp = confusion_matrix(y_test, y_pred).ravel()
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0

    print("\n" + "="*60)
    print("MODEL PERFORMANCE")
    print("="*60)
    print(f"Accuracy:  {accuracy:.4f} ({accuracy*100:.2f}%)")
    print(f"Precision: {precision:.4f} ({precision*100:.2f}%)")
    print(f"Recall:    {recall:.4f} ({recall*100:.2f}%)")
    print(f"F1-Score:  {f1:.4f} ({f1*100:.2f}%)")
    print(f"FPR:       {fpr:.4f} ({fpr*100:.2f}%)")
    print("\nConfusion Matrix:")
    print(f"  TN: {tn:5d}  FP: {fp:5d}")
    print(f"  FN: {fn:5d}  TP: {tp:5d}")
    print("="*60)

    # Save model
    print("\n[6/6] Saving model and metrics...")
    with open('../models/email_phishing_model.pkl', 'wb') as f:
        pickle.dump(model, f)
    print("      Model saved: ../models/email_phishing_model.pkl")

    # Save metrics
    metrics = {
        'accuracy': float(accuracy),
        'precision': float(precision),
        'recall': float(recall),
        'f1_score': float(f1),
        'fpr': float(fpr),
        'confusion_matrix': {'tn': int(tn), 'fp': int(fp), 'fn': int(fn), 'tp': int(tp)},
        'feature_count': 19,
        'training_samples': int(len(X_train)),
        'test_samples': int(len(X_test))
    }

    with open('../models/metrics.json', 'w') as f:
        json.dump(metrics, f, indent=2)
    print("      Metrics saved: ../models/metrics.json")

    print("\n" + "="*60)
    print("✅ TRAINING COMPLETE!")
    print("="*60)

    return model, metrics


# ============================================================================
# INFERENCE
# ============================================================================

_MODEL_CACHE = None


def _extract_domain(sender):
    sender_text = str(sender or '').lower()
    email_match = re.search(r'[\w\.-]+@([\w\.-]+\.\w+)', sender_text)
    return email_match.group(1) if email_match else ''


def _is_official_brand_sender(brand, domain):
    official = {
        'infosys': ['infosys.com'],
        'google': ['google.com'],
        'hdfc': ['hdfcbank.com'],
        'sbi': ['sbi.co.in', 'onlinesbi.com'],
        'amazon': ['amazon.com', 'amazon.in']
    }
    allowed = official.get(brand, [])
    domain = (domain or '').lower()
    return any(domain == d or domain.endswith('.' + d) for d in allowed)


def apply_context_rules(text, sender, subject, risk_score, reasons):
    """
    Lightweight context-intelligence layer to improve phishing coverage
    without model retraining.
    """
    text = str(text or '')
    sender = str(sender or '')
    subject = str(subject or '')
    combined = f"{text} {subject}".lower()
    updated_reasons = list(reasons or [])

    def add_reason(msg):
        if msg not in updated_reasons:
            updated_reasons.append(msg)

    # 1) Job scam patterns
    has_job_words = any(w in combined for w in ['internship', 'training', 'recruitment', 'shortlisted'])
    has_unofficial_flow = any(w in combined for w in ['google form', 'apply', 'registration'])
    if has_job_words and has_unofficial_flow:
        risk_score = max(risk_score, 60)
        add_reason('Unofficial job application process')

    # 2) Brand impersonation
    sender_domain = _extract_domain(sender)
    for brand in ['infosys', 'google', 'hdfc', 'sbi', 'amazon']:
        if brand in combined and not _is_official_brand_sender(brand, sender_domain):
            risk_score = max(risk_score, 70)
            add_reason('Brand impersonation detected')
            break

    # 3) WhatsApp recruitment
    if 'whatsapp' in combined:
        risk_score = max(risk_score, 65)
        add_reason('Recruitment via WhatsApp is suspicious')

    # 4) Multiple external links
    urls = re.findall(r"https?://[^\s<>\"'{}|\\^`\[\]]+", text, re.IGNORECASE)
    if len(urls) > 2:
        risk_score += 10
        add_reason('Multiple external links detected')

    risk_score = int(max(0, min(100, round(risk_score))))
    return risk_score, updated_reasons

def load_model():
    """Load trained model (cached)."""
    global _MODEL_CACHE
    if _MODEL_CACHE is None:
        with open('../models/email_phishing_model.pkl', 'rb') as f:
            _MODEL_CACHE = pickle.load(f)
    return _MODEL_CACHE


def classify_email(text, sender, subject, is_spam=False):
    """
    Classify an email as phishing or legitimate.

    Args:
        text: Email body content
        sender: Sender email address
        subject: Email subject line

    Returns:
        dict with 'label', 'risk_score', 'confidence', 'probability'
    """
    try:
        model = load_model()
        if model is None:
            print("[Model] Model is None after load_model()")
            return {'label': 'unknown', 'risk_score': 50, 'confidence': 0.0,
                    'error': 'Model failed to load'}

        features = extract_features(text, sender, subject)
        X = features_to_array(features).reshape(1, -1)

        probabilities = model.predict_proba(X)[0]
        prob_legit = float(probabilities[0])
        prob_phish = float(probabilities[1])

        print(f"[Model] Features: {features}")
        print(f"[Model] Probability phishing={prob_phish:.4f}, legitimate={prob_legit:.4f}")

        # -------------------------------
        # 1. THRESHOLD (precision-focused)
        # -------------------------------
        THRESHOLD = 0.65
        is_phishing = prob_phish >= THRESHOLD

        # -------------------------------
        # 2. RISK SCORE (aligned with decision)
        # -------------------------------
        if is_phishing:
            risk_score = prob_phish * 100
        else:
            # force safe-looking output for legitimate
            risk_score = prob_phish * 40

        # dampen low confidence
        if prob_phish < 0.6:
            risk_score *= 0.6

        risk_score = int(max(0, min(100, round(risk_score))))

        # -------------------------------
        # 3. TRUSTED DOMAIN BOOST
        # -------------------------------
        sender_text = str(sender or "").lower()
        sender_domain = ""

        email_match = re.search(r'[\w\.-]+@([\w\.-]+\.\w+)', sender_text)
        if email_match:
            sender_domain = email_match.group(1)

        trusted_keywords = [
            "bank", "hdfc", "icici", "sbi",
            "google", "amazon", "microsoft",
            "gov", "edu"
        ]

        is_trusted = any(k in sender_domain for k in trusted_keywords)

        if is_trusted and prob_phish < 0.7:
            is_phishing = False
            risk_score = min(risk_score, 25)

        # -------------------------------
        # 4. CONTEXT LAYER (no retraining)
        # -------------------------------
        reasons = []

        # Force non-zero baseline
        if risk_score < 10:
            risk_score = 10

        # Spam visibility boost
        if bool(is_spam):
            risk_score = max(risk_score, 60)
            reasons.append('Email already marked as spam')

        # Apply context intelligence rules
        risk_score, reasons = apply_context_rules(text, sender, subject, risk_score, reasons)

        # Re-evaluate label after context layer
        is_phishing = risk_score >= 50

        # -------------------------------
        # 5. FINAL OUTPUT
        # -------------------------------
        label = "phishing" if is_phishing else "legitimate"

        confidence = prob_phish if is_phishing else prob_legit

        result = {
            'label': label,
            'risk_score': risk_score,
            'confidence': float(round(confidence, 4)),
            'reasons': reasons,
            'probability': {
                'legitimate': prob_legit,
                'phishing': prob_phish
            }
        }

        print(f"[Model] Final: {label} ({risk_score}/100)")

        return result

    except FileNotFoundError as e:
        print(f"[Model] FileNotFoundError: {e}")
        print(f"[Model] Model file not found. Please ensure the model is trained.")
        return {'label': 'unknown', 'risk_score': 50, 'confidence': 0.0,
                'error': f'Model not found: {str(e)}'}
    except Exception as e:
        print(f"[Model] Exception: {e}")
        import traceback
        traceback.print_exc()
        return {'label': 'unknown', 'risk_score': 50, 'confidence': 0.0,
                'error': str(e)}


# ============================================================================
# MAIN
# ============================================================================

if __name__ == "__main__":
    import sys
    import os

    # Ensure models directory exists
    os.makedirs('../models', exist_ok=True)

    # Check if dataset exists
    if not os.path.exists('../data/cleaned_emails.csv'):
        print("❌ Error: Dataset not found at ../data/cleaned_emails.csv")
        print("   Please run dataset preparation first.")
        sys.exit(1)

    # Train model
    model, metrics = train_model()

    # Test inference
    print("\n" + "="*60)
    print("TESTING INFERENCE")
    print("="*60)

    test_cases = [
        {
            'text': 'URGENT! Your account has been SUSPENDED. Click here: http://192.168.1.1/verify',
            'sender': 'security123@amaz0n-verify.xyz',
            'subject': 'URGENT: Account Suspended',
            'expected': 'phishing'
        },
        {
            'text': 'Hi team, meeting tomorrow at 3 PM. Please review the documents beforehand.',
            'sender': 'colleague@company.com',
            'subject': 'Project Meeting',
            'expected': 'legitimate'
        },
        {
            'text': 'आपका account suspend हो गया! तुरंत verify करें: http://bit.ly/verify',
            'sender': 'support@hdfc-secure.tk',
            'subject': 'खाता निलंबित',
            'expected': 'phishing'
        }
    ]

    for i, test in enumerate(test_cases, 1):
        result = classify_email(test['text'], test['sender'], test['subject'])
        print(f"\nTest {i} (Expected: {test['expected']}):")
        print(f"  Text: {test['text'][:60]}...")
        print(f"  Label: {result['label']}")
        print(f"  Risk Score: {result['risk_score']}/100")
        print(f"  Confidence: {result['confidence']:.2%}")
        status = "✓" if result['label'] == test['expected'] else "✗"
        print(f"  Status: {status}")

    print("\n" + "="*60)
    print("✅ ALL DONE!")
    print("="*60)
    print("\nUsage:")
    print("  from train_email_model import classify_email")
    print("  result = classify_email('email text...', 'sender@...', 'subject...')")
    print("  print(result['label'], result['risk_score'])")
