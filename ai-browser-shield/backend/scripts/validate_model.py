"""
Quick Validation Test for Email ML Model
=========================================
Tests all feature extraction functions and edge cases.
"""

from email_ml_model import (
    extract_text_features,
    extract_url_features,
    extract_sender_features,
    extract_structural_features,
    extract_all_features,
    features_to_vector
)


def test_text_features():
    """Test text feature extraction."""
    print("Testing text features...")

    # Normal case
    text = "URGENT! Your account will EXPIRE in 24 hours! You won $5000!"
    features = extract_text_features(text)

    assert features['email_length'] > 0
    assert features['word_count'] > 0
    assert features['capital_ratio'] > 0  # Has uppercase
    assert features['urgency_score'] >= 2  # "URGENT", "EXPIRE"
    assert features['money_signal'] >= 1  # "$5000", "won"

    # Edge case: empty text
    features = extract_text_features("")
    assert features['email_length'] == 0
    assert features['capital_ratio'] == 0

    # Edge case: None input
    features = extract_text_features(None)
    assert features['email_length'] == 0

    print("  ✓ Text features passed")


def test_url_features():
    """Test URL feature extraction."""
    print("Testing URL features...")

    # Normal case with IP URL
    text = "Click here: http://192.168.1.1/verify and http://bit.ly/abc"
    features = extract_url_features(text)

    assert features['url_count'] == 2
    assert features['has_url'] == 1.0
    assert features['has_ip_url'] == 1.0
    assert features['has_shortened_url'] == 1.0

    # Edge case: no URLs
    features = extract_url_features("Plain text with no links")
    assert features['url_count'] == 0
    assert features['has_url'] == 0.0

    # Edge case: suspicious TLD
    text = "Visit http://phishing-site.xyz"
    features = extract_url_features(text)
    assert features['suspicious_tld'] == 1.0

    print("  ✓ URL features passed")


def test_sender_features():
    """Test sender feature extraction."""
    print("Testing sender features...")

    # Normal case: suspicious sender
    sender = "security123@phishing-site.xyz"
    text = "Your Amazon account needs verification"
    features = extract_sender_features(sender, text)

    assert features['sender_has_numbers'] == 1.0
    assert features['brand_mismatch'] == 1.0  # Mentions Amazon but sender isn't amazon.com

    # Edge case: legitimate sender
    sender = "noreply@gmail.com"
    features = extract_sender_features(sender, "")
    assert features['free_email_provider'] == 1.0

    # Edge case: display name mismatch
    sender = "Amazon Support <scammer@evil.com>"
    features = extract_sender_features(sender, "")
    assert features['sender_display_mismatch'] == 1.0

    # Edge case: empty sender
    features = extract_sender_features("", "")
    assert features['sender_has_numbers'] == 0.0

    print("  ✓ Sender features passed")


def test_structural_features():
    """Test structural feature extraction."""
    print("Testing structural features...")

    # Normal case
    text = "Please see the attached file.exe for details. <html><body><p>Content</p></body></html>"
    features = extract_structural_features(text)

    assert features['has_attachments'] == 1.0
    assert features['attachment_suspicious'] == 1.0  # .exe
    assert features['html_to_text_ratio'] > 0

    # Edge case: no HTML
    features = extract_structural_features("Plain text email")
    assert features['html_to_text_ratio'] == 0.0

    print("  ✓ Structural features passed")


def test_feature_vector():
    """Test feature vector conversion."""
    print("Testing feature vector conversion...")

    text = "Test email with http://example.com"
    sender = "test@test.com"
    subject = "Test"

    # Extract all features
    features = extract_all_features(text, sender, subject)

    # Convert to vector
    vector = features_to_vector(features)

    # Check dimensions
    assert vector.shape == (19,), f"Expected 19 features, got {vector.shape[0]}"

    # Check all values are numeric
    assert not any(pd.isna(vector)), "Feature vector contains NaN values"

    print(f"  ✓ Feature vector has correct shape: {vector.shape}")


def test_edge_cases():
    """Test various edge cases."""
    print("Testing edge cases...")

    # Edge case 1: All empty inputs
    features = extract_all_features("", "", "")
    vector = features_to_vector(features)
    assert vector.shape == (19,)
    print("  ✓ Empty inputs handled")

    # Edge case 2: Hindi text
    features = extract_all_features(
        "आपका account suspend हो गया! तुरंत verify करें",
        "scam@xyz.tk",
        "URGENT"
    )
    vector = features_to_vector(features)
    assert vector.shape == (19,)
    print("  ✓ Hindi text handled")

    # Edge case 3: Very long email
    long_text = "word " * 10000
    features = extract_all_features(long_text, "test@test.com", "")
    vector = features_to_vector(features)
    assert vector.shape == (19,)
    print("  ✓ Long email handled")

    # Edge case 4: HTML heavy
    html_text = "<div>" * 100 + "actual content" + "</div>" * 100
    features = extract_all_features(html_text, "test@test.com", "")
    vector = features_to_vector(features)
    assert vector.shape == (19,)
    print("  ✓ HTML-heavy email handled")

    # Edge case 5: Malformed URL
    text_malformed = "Visit http://example..com or htp://broken"
    features = extract_all_features(text_malformed, "test@test.com", "")
    vector = features_to_vector(features)
    assert vector.shape == (19,)
    print("  ✓ Malformed URLs handled")


def test_real_examples():
    """Test with realistic phishing and legitimate examples."""
    print("\nTesting real examples...")

    # Phishing example 1
    phishing1 = extract_all_features(
        text="URGENT! Your account has been SUSPENDED. Click here immediately: http://192.168.1.1/verify",
        sender="security123@amaz0n-verify.xyz",
        subject="Account Suspended"
    )
    vector1 = features_to_vector(phishing1)

    print("\n  Phishing Example 1 (Expected: High risk signals)")
    print(f"    - Urgency score: {phishing1['urgency_score']}")
    print(f"    - Has IP URL: {phishing1['has_ip_url']}")
    print(f"    - Suspicious TLD: {phishing1['suspicious_tld']}")
    print(f"    - Sender has numbers: {phishing1['sender_has_numbers']}")

    # Phishing example 2
    phishing2 = extract_all_features(
        text="Congratulations! You won $5000! Claim now: http://bit.ly/claim",
        sender="winner@lottery.tk",
        subject="You Won!!!"
    )
    vector2 = features_to_vector(phishing2)

    print("\n  Phishing Example 2 (Expected: High risk signals)")
    print(f"    - Money signal: {phishing2['money_signal']}")
    print(f"    - Has shortened URL: {phishing2['has_shortened_url']}")
    print(f"    - Suspicious TLD: {phishing2['suspicious_tld']}")

    # Legitimate example
    legitimate = extract_all_features(
        text="Hi team, the project review meeting is scheduled for tomorrow at 3 PM. Please review the documents.",
        sender="john.smith@company.com",
        subject="Meeting Reminder"
    )
    vector3 = features_to_vector(legitimate)

    print("\n  Legitimate Example (Expected: Low risk signals)")
    print(f"    - Urgency score: {legitimate['urgency_score']}")
    print(f"    - Money signal: {legitimate['money_signal']}")
    print(f"    - Has IP URL: {legitimate['has_ip_url']}")
    print(f"    - Free email: {legitimate['free_email_provider']}")


import pandas as pd
import numpy as np


if __name__ == "__main__":
    print("="*60)
    print("EMAIL ML MODEL - VALIDATION TESTS")
    print("="*60)

    try:
        test_text_features()
        test_url_features()
        test_sender_features()
        test_structural_features()
        test_feature_vector()
        test_edge_cases()
        test_real_examples()

        print("\n" + "="*60)
        print("✅ ALL TESTS PASSED!")
        print("="*60)
        print("\nYour model is ready for training.")
        print("\nNext steps:")
        print("  1. Generate test dataset: python generate_test_dataset.py")
        print("  2. Train model: python email_ml_model.py test_phishing_dataset.csv")
        print("  3. Test classification: python email_ml_model.py (follow prompts)")

    except AssertionError as e:
        print(f"\n❌ TEST FAILED: {e}")
        import traceback
        traceback.print_exc()
    except Exception as e:
        print(f"\n❌ ERROR: {e}")
        import traceback
        traceback.print_exc()
