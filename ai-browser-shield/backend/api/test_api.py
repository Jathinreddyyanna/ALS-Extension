"""
API Test Script
===============
Test the Flask API with sample emails
"""

import requests
import json

API_URL = "http://localhost:5000"


def test_health():
    """Test health endpoint."""
    print("Testing /health endpoint...")
    response = requests.get(f"{API_URL}/health")
    print(f"Status: {response.status_code}")
    print(f"Response: {json.dumps(response.json(), indent=2)}")
    print()


def test_phishing_email():
    """Test with obvious phishing email."""
    print("Testing phishing email detection...")

    email_data = {
        "text": "URGENT! Your HDFC account has been SUSPENDED. Click here to verify: http://192.168.1.1/verify-now",
        "sender": "security-alert@hdfc-verify.xyz",
        "subject": "URGENT: Account Suspended - Verify Immediately"
    }

    response = requests.post(
        f"{API_URL}/analyze-email",
        json=email_data,
        headers={"Content-Type": "application/json"}
    )

    print(f"Status: {response.status_code}")
    result = response.json()

    print(f"\nRisk Score: {result['risk_score']}/100")
    print(f"Label: {result['label']}")
    print(f"Risk Level: {result['risk_level']}")
    print(f"Confidence: {result['confidence']:.2%}")

    print("\nExplanation:")
    print(f"  Risk: {result['explanation']['risk_level']}")
    print("\n  Reasons:")
    for reason in result['explanation']['reasons']:
        print(f"    • {reason}")

    print("\n  Consequences:")
    for cons in result['explanation']['consequences']:
        print(f"    • {cons}")

    print("\n  Actions:")
    for action in result['explanation']['actions']:
        print(f"    {action}")

    print()


def test_legitimate_email():
    """Test with legitimate email."""
    print("Testing legitimate email...")

    email_data = {
        "text": "Hi team, reminder that our quarterly review meeting is scheduled for tomorrow at 3 PM in Conference Room B. Please come prepared with your reports.",
        "sender": "manager@company.com",
        "subject": "Quarterly Review Meeting Tomorrow"
    }

    response = requests.post(
        f"{API_URL}/analyze-email",
        json=email_data,
        headers={"Content-Type": "application/json"}
    )

    print(f"Status: {response.status_code}")
    result = response.json()

    print(f"\nRisk Score: {result['risk_score']}/100")
    print(f"Label: {result['label']}")
    print(f"Risk Level: {result['risk_level']}")
    print()


def test_hindi_phishing():
    """Test with Hindi phishing email."""
    print("Testing Hindi phishing email...")

    email_data = {
        "text": "आपका SBI account BLOCK हो गया है! तुरंत verify करें: http://sbi-secure.tk/verify",
        "sender": "sbi-alert999@sbibank.ml",
        "subject": "🚨 SBI Alert: खाता Block"
    }

    response = requests.post(
        f"{API_URL}/analyze-email",
        json=email_data,
        headers={"Content-Type": "application/json"}
    )

    print(f"Status: {response.status_code}")
    result = response.json()

    print(f"\nRisk Score: {result['risk_score']}/100")
    print(f"Label: {result['label']}")
    print(f"Risk Level: {result['risk_level']}")
    print()


def test_batch_analysis():
    """Test batch analysis endpoint."""
    print("Testing batch analysis...")

    batch_data = {
        "emails": [
            {
                "text": "URGENT! Win ₹50,000 now!",
                "sender": "winner@lottery.tk",
                "subject": "You Won!"
            },
            {
                "text": "Meeting at 3pm",
                "sender": "colleague@work.com",
                "subject": "Meeting"
            },
            {
                "text": "Your package is ready for delivery",
                "sender": "delivery@fedex.com",
                "subject": "Package Update"
            }
        ]
    }

    response = requests.post(
        f"{API_URL}/batch-analyze",
        json=batch_data,
        headers={"Content-Type": "application/json"}
    )

    print(f"Status: {response.status_code}")
    result = response.json()

    print(f"\nTotal analyzed: {result['total']}")
    print("\nResults:")
    for i, email_result in enumerate(result['results'], 1):
        print(f"  {i}. {email_result['subject']}")
        print(f"     Risk: {email_result['risk_score']}/100 ({email_result['label']})")

    print()


def run_all_tests():
    """Run all test cases."""
    print("="*70)
    print("API TEST SUITE")
    print("="*70)
    print()

    try:
        test_health()
        test_phishing_email()
        test_legitimate_email()
        test_hindi_phishing()
        test_batch_analysis()

        print("="*70)
        print("✅ ALL TESTS COMPLETED")
        print("="*70)

    except requests.exceptions.ConnectionError:
        print("❌ ERROR: Cannot connect to API")
        print("   Make sure Flask server is running:")
        print("   cd backend/api && python app.py")
    except Exception as e:
        print(f"❌ ERROR: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    run_all_tests()
