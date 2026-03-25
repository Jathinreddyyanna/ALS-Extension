"""
Phishing Email Model - Test Cases
==================================
10 realistic test emails for Indian phishing detection scenarios
"""

TEST_EMAILS = [
    # ========================================================================
    # PHISHING EMAILS (3) - Bank/UPI Scams
    # ========================================================================
    {
        'id': 1,
        'category': 'PHISHING - Bank Fraud',
        'text': '''URGENT SECURITY ALERT!

Your HDFC Bank account has been temporarily SUSPENDED due to suspicious activity detected from an unknown device.

Account Number: XXXX1234
Last Transaction: ₹15,000 to unknown payee

IMMEDIATE ACTION REQUIRED:
Click here to verify your identity and restore access: http://hdfc-secureportal.tk/verify-now

You have 24 HOURS to complete verification or your account will be PERMANENTLY BLOCKED and funds may be seized as per RBI regulations.

DO NOT ignore this message!

HDFC Bank Security Team
''',
        'sender': 'security-alerts@hdfc-bank-verify.xyz',
        'subject': 'URGENT: HDFC Account Suspended - Verify Within 24 Hours',
        'expected': {
            'label': 'phishing',
            'risk_score': 'HIGH (85-95)',
            'reasons': [
                'Suspicious TLD (.tk, .xyz)',
                'IP or suspicious domain in URL',
                'Multiple urgency triggers (URGENT, 24 HOURS, IMMEDIATELY)',
                'Threats of account closure/fund seizure',
                'Brand mismatch (claims HDFC but sender domain is not hdfcbank.com)',
                'Free/suspicious email provider'
            ]
        }
    },

    {
        'id': 2,
        'category': 'PHISHING - UPI Scam',
        'text': '''Dear Customer,

Your UPI transaction of ₹25,000 to merchant "ONLINE STORE" has FAILED due to technical error.

To get instant refund credited to your account, please verify your UPI PIN and bank details:

Refund Amount: ₹25,000
Transaction ID: UPI202403241545

VERIFY NOW: http://192.168.45.120/upi-refund-claim

This link will expire in 2 HOURS. After that, you will need to visit branch physically to claim refund.

For assistance, call our toll-free number: 1800-XXX-XXXX

National Payments Corporation of India (NPCI)
''',
        'sender': 'refunds@npci-payments.ml',
        'subject': 'UPI Refund Pending ₹25,000 - Action Required',
        'expected': {
            'label': 'phishing',
            'risk_score': 'CRITICAL (90-98)',
            'reasons': [
                'IP address in URL (http://192.168.45.120)',
                'Suspicious TLD (.ml)',
                'Asks for UPI PIN (red flag - legitimate services never ask)',
                'Money-related urgency (₹25,000 refund)',
                'Time pressure (2 HOURS)',
                'Brand impersonation (NPCI)',
                'Sender domain mismatch'
            ]
        }
    },

    {
        'id': 3,
        'category': 'PHISHING - Aadhaar Fraud',
        'text': '''Government of India - UIDAI Notice

Your Aadhaar Card (XXXX-XXXX-5678) has been DEACTIVATED as per new regulations issued by Ministry of Electronics and IT.

Reason: KYC details not updated in last 12 months

To RE-ACTIVATE your Aadhaar immediately and avoid legal penalties (fine up to ₹10,000):

1. Click this secure link: http://uidai-gov-update.top/reactivate
2. Upload Aadhaar + PAN Card photo
3. Enter OTP sent to registered mobile

IMPORTANT: Failure to reactivate within 48 hours will result in:
- Bank account freeze
- SIM card deactivation
- Unable to file Income Tax returns
- Legal action under Aadhaar Act 2016

Act NOW to avoid inconvenience.

UIDAI Support Team
Email: support@uidai-helpdesk.tk
''',
        'sender': 'noreply_uidai123@gov-india.xyz',
        'subject': 'UIDAI: Aadhaar Deactivation Notice - Reactivate Now',
        'expected': {
            'label': 'phishing',
            'risk_score': 'CRITICAL (92-98)',
            'reasons': [
                'Multiple suspicious TLDs (.top, .tk, .xyz)',
                'Sender has numbers (noreply_uidai123)',
                'Government impersonation (UIDAI)',
                'Extreme urgency (48 hours, legal penalties)',
                'Asks for document uploads (Aadhaar + PAN)',
                'Multiple threats (account freeze, SIM deactivation, legal action)',
                'Sender domain not official (gov.in expected)'
            ]
        }
    },

    # ========================================================================
    # HINDI PHISHING EMAILS (2)
    # ========================================================================
    {
        'id': 4,
        'category': 'PHISHING - Hindi/Hinglish',
        'text': '''प्रिय ग्राहक,

आपका SBI Bank खाता BLOCK हो गया है!

कारण: Suspicious activity detect हुई है आपके account में।

तुरंत VERIFY करें नहीं तो account PERMANENTLY बंद हो जाएगा:

👉 यहाँ क्लिक करें: http://sbi-verify.tk/hindi-support

आपके पास केवल 6 घंटे हैं!

अगर आप verify नहीं करेंगे तो:
❌ ATM card block
❌ Net banking band
❌ सभी FD और savings freeze

URGENT ACTION जरूरी है!

State Bank Customer Care
Mobile: +91-98765-XXXXX
''',
        'sender': 'sbi-alert999@sbibank-customercare.ml',
        'subject': '🚨 SBI Alert: खाता Block - तुरंत Verify करें',
        'expected': {
            'label': 'phishing',
            'risk_score': 'HIGH (88-96)',
            'reasons': [
                'Hindi + English mix (Hinglish - common phishing tactic)',
                'Suspicious TLD (.tk, .ml)',
                'Sender has numbers (alert999)',
                'Multiple urgency words (तुरंत, URGENT, 6 घंटे)',
                'Emojis used (👉, ❌, 🚨 - unprofessional for bank)',
                'Brand mismatch (claims SBI)',
                'Threats in Hindi (खाता बंद, block, freeze)'
            ]
        }
    },

    {
        'id': 5,
        'category': 'PHISHING - Hindi Job Scam',
        'text': '''नमस्ते,

बधाई हो! 🎉

आपको HDFC Bank में Manager पद के लिए select किया गया है।

Salary: ₹45,000 per month
Location: Mumbai, Delhi, Bangalore (आप choose करें)
Joining: Immediately

बस registration fees जमा करें: ₹5,000 (one time only)

Payment करने के लिए:
- PhonePe/Google Pay: 98XXXXXX321
- या यहाँ click करें: http://bit.ly/hdfc-job-2024

Registration के बाद आपको:
✅ Appointment letter email में मिलेगा
✅ 15 दिन में joining
✅ सभी benefits included

जल्दी करें! केवल 50 positions available हैं।

HDFC HR Department
Contact: +91-7777888899
''',
        'sender': 'hr.recruitment@yahoo.com',
        'subject': 'HDFC Bank Job Offer - Manager Position ₹45K',
        'expected': {
            'label': 'phishing',
            'risk_score': 'HIGH (85-93)',
            'reasons': [
                'Job scam asking for registration fee (₹5,000)',
                'Free email provider (yahoo.com) for company recruitment',
                'Hindi + English mix',
                'URL shortener (bit.ly)',
                'UPI number provided directly',
                'Too good to be true (immediate joining, choose location)',
                'Brand impersonation (HDFC)',
                'Urgency (only 50 positions)',
                'Emoji usage (unprofessional)'
            ]
        }
    },

    # ========================================================================
    # LEGITIMATE EMAILS (3)
    # ========================================================================
    {
        'id': 6,
        'category': 'LEGITIMATE - Bank Statement',
        'text': '''Dear Customer,

Your ICICI Bank Credit Card statement for March 2024 is now available.

Account Summary:
- Previous Balance: ₹12,450.00
- Payments Received: ₹12,450.00
- New Purchases: ₹8,320.00
- Current Balance: ₹8,320.00

Minimum Amount Due: ₹832.00
Payment Due Date: 15 April 2024

You can view your detailed statement by logging into:
- ICICI Bank Mobile App (iMobile Pay)
- Internet Banking at www.icicibank.com
- Visit nearest ICICI Bank branch

For any queries, contact our 24x7 Customer Care at 1860 120 7777.

Thank you for banking with us.

ICICI Bank Ltd.
This is an auto-generated email. Please do not reply.
''',
        'sender': 'credit.cards@icicibank.com',
        'subject': 'ICICI Credit Card Statement - March 2024',
        'expected': {
            'label': 'legitimate',
            'risk_score': 'LOW (5-15)',
            'reasons': [
                'Official bank domain (icicibank.com)',
                'No suspicious URLs or links',
                'Standard banking language',
                'No urgency or threats',
                'Provides official customer care number',
                'Auto-generated disclaimer',
                'No request for personal information',
                'Professional tone'
            ]
        }
    },

    {
        'id': 7,
        'category': 'LEGITIMATE - OTP Verification',
        'text': '''Dear Customer,

Your One Time Password (OTP) for HDFC NetBanking login is:

483726

This OTP is valid for 10 minutes.

If you did not request this OTP, please ignore this message or contact customer care immediately.

DO NOT share this OTP with anyone, including bank staff.

HDFC Bank never asks for OTP, password, or card details over phone/email.

Thank you,
HDFC Bank
''',
        'sender': 'alerts@hdfcbank.com',
        'subject': 'OTP for HDFC NetBanking Login - 483726',
        'expected': {
            'label': 'legitimate',
            'risk_score': 'LOW (8-18)',
            'reasons': [
                'Official bank domain (hdfcbank.com)',
                'Standard OTP message format',
                'Includes security warning (DO NOT share)',
                'Short and specific (OTP only)',
                'No links or attachments',
                'Professional language',
                'Security disclaimer about not asking for details',
                'Valid timeframe mentioned (10 minutes)'
            ]
        }
    },

    {
        'id': 8,
        'category': 'LEGITIMATE - Meeting Reminder',
        'text': '''Hi Team,

Reminder: Our quarterly review meeting is scheduled for tomorrow.

Date: March 25, 2024
Time: 3:00 PM IST
Location: Conference Room B, 5th Floor
Virtual Link: teams.microsoft.com/meet/abc123xyz

Agenda:
1. Q4 Performance Review (30 mins)
2. Budget Discussion for Q1 2025 (20 mins)
3. Team Updates (15 mins)
4. Open Discussion (10 mins)

Please come prepared with your team reports. Documents are available in the shared drive.

Looking forward to seeing everyone.

Best regards,
Priya Sharma
Project Manager
priya.sharma@company.com
+91-98765-43210
''',
        'sender': 'priya.sharma@company.com',
        'subject': 'Reminder: Quarterly Review Meeting - Tomorrow 3 PM',
        'expected': {
            'label': 'legitimate',
            'risk_score': 'LOW (2-10)',
            'reasons': [
                'Corporate email domain',
                'Professional meeting invitation',
                'Clear context and agenda',
                'No urgency or threats',
                'No money requests',
                'Standard business communication',
                'Proper signature with contact info',
                'Official meeting platform (Microsoft Teams)'
            ]
        }
    },

    # ========================================================================
    # TRICKY/BORDERLINE EMAILS (2)
    # ========================================================================
    {
        'id': 9,
        'category': 'BORDERLINE - Legitimate Marketing with Urgency',
        'text': '''Dear Valued Customer,

LAST DAY! Amazon Great Indian Sale ends TONIGHT at 11:59 PM!

Don't miss out on these limited-time offers:
🔥 Up to 80% OFF on Electronics
🔥 Extra 10% Instant Discount with HDFC Credit Cards
🔥 No Cost EMI on select products

Shop now: https://www.amazon.in/sale/great-indian-sale

Offer valid till: March 24, 2024 | 11:59 PM

Hurry! Limited stock available.

Download the Amazon app for exclusive app-only deals.

Happy Shopping!
Amazon.in
''',
        'sender': 'marketing@amazon.in',
        'subject': 'LAST DAY! Amazon Great Indian Sale - Up to 80% OFF',
        'expected': {
            'label': 'legitimate',
            'risk_score': 'MEDIUM (25-40)',
            'reasons_legitimate': [
                'Official Amazon domain (amazon.in)',
                'Standard marketing email',
                'Legitimate URL (www.amazon.in)',
                'Real promotional event',
                'Professional formatting'
            ],
            'reasons_suspicious': [
                'Heavy urgency language (LAST DAY, TONIGHT)',
                'Multiple urgency triggers (Hurry, Limited stock)',
                'Uses emojis',
                'Time pressure tactics',
                'Could trigger false positive due to urgency'
            ],
            'note': 'Legitimate marketing but uses phishing-like urgency tactics. Good test for false positive rate.'
        }
    },

    {
        'id': 10,
        'category': 'BORDERLINE - Legitimate Password Reset',
        'text': '''Hello,

We received a request to reset your Paytm password.

If you made this request, click the link below to reset your password:
https://paytm.com/password-reset?token=abc123xyz789

This link will expire in 1 hour for security reasons.

If you didn't request this password reset, please ignore this email. Your password will remain unchanged.

For security:
- Never share your password or OTP with anyone
- Paytm will never call asking for password
- Enable 2-factor authentication for added security

Need help? Contact us: support@paytm.com

Thanks,
Team Paytm
''',
        'sender': 'noreply@paytm.com',
        'subject': 'Reset Your Paytm Password',
        'expected': {
            'label': 'legitimate',
            'risk_score': 'MEDIUM-LOW (20-35)',
            'reasons_legitimate': [
                'Official Paytm domain (paytm.com)',
                'Standard password reset flow',
                'Includes "ignore if not requested" option',
                'Security tips provided',
                'Professional language',
                'Legitimate Paytm URL'
            ],
            'reasons_suspicious': [
                'Contains clickable link (password reset)',
                'Time pressure (1 hour expiry)',
                'Could be mistaken for phishing if domain not verified',
                'Password-related (sensitive topic)'
            ],
            'note': 'Legitimate password reset but has characteristics that overlap with phishing (link, urgency). Tests model ability to distinguish legitimate security emails from phishing.'
        }
    }
]


# ============================================================================
# TEST RUNNER
# ============================================================================

def run_tests(classify_email_function):
    """
    Run all test cases through the classification model.

    Args:
        classify_email_function: Your classify_email() function

    Returns:
        Results dictionary with pass/fail for each test
    """
    results = {
        'passed': 0,
        'failed': 0,
        'borderline': 0,
        'details': []
    }

    print("="*70)
    print("RUNNING PHISHING DETECTION TEST SUITE")
    print("="*70)

    for test in TEST_EMAILS:
        print(f"\n{'='*70}")
        print(f"TEST {test['id']}: {test['category']}")
        print(f"{'='*70}")
        print(f"Subject: {test['subject']}")
        print(f"Sender: {test['sender']}")
        print(f"Text Preview: {test['text'][:100]}...")

        # Run classification
        result = classify_email_function(
            test['text'],
            test['sender'],
            test['subject']
        )

        print(f"\n--- ACTUAL OUTPUT ---")
        print(f"Label: {result['label']}")
        print(f"Risk Score: {result['risk_score']}/100")
        print(f"Confidence: {result.get('confidence', 0):.2%}")

        # Check if result matches expected
        expected_label = test['expected']['label']
        actual_label = result['label']

        if 'BORDERLINE' in test['category']:
            # For borderline cases, we accept either outcome
            status = 'BORDERLINE (ACCEPTABLE)'
            results['borderline'] += 1
            passed = True
        else:
            passed = (expected_label == actual_label)
            if passed:
                results['passed'] += 1
                status = '✅ PASSED'
            else:
                results['failed'] += 1
                status = '❌ FAILED'

        print(f"\nExpected: {expected_label}")
        print(f"Got: {actual_label}")
        print(f"Status: {status}")

        results['details'].append({
            'test_id': test['id'],
            'category': test['category'],
            'expected': expected_label,
            'actual': actual_label,
            'risk_score': result['risk_score'],
            'passed': passed
        })

    # Print summary
    print("\n" + "="*70)
    print("TEST SUMMARY")
    print("="*70)
    print(f"Total Tests: {len(TEST_EMAILS)}")
    print(f"Passed: {results['passed']}")
    print(f"Failed: {results['failed']}")
    print(f"Borderline: {results['borderline']}")

    success_rate = (results['passed'] / (len(TEST_EMAILS) - results['borderline'])) * 100
    print(f"\nSuccess Rate: {success_rate:.1f}% (excluding borderline)")

    if results['failed'] > 0:
        print("\n⚠️ Failed Tests:")
        for detail in results['details']:
            if not detail['passed'] and 'BORDERLINE' not in detail['category']:
                print(f"  - Test {detail['test_id']}: {detail['category']}")
                print(f"    Expected: {detail['expected']}, Got: {detail['actual']}")

    return results


def print_test_summary():
    """Print summary of all test cases."""
    print("="*70)
    print("TEST CASE SUMMARY")
    print("="*70)

    categories = {
        'PHISHING': 0,
        'HINDI PHISHING': 0,
        'LEGITIMATE': 0,
        'BORDERLINE': 0
    }

    for test in TEST_EMAILS:
        if 'PHISHING' in test['category'] and 'Hindi' not in test['category']:
            categories['PHISHING'] += 1
        elif 'Hindi' in test['category']:
            categories['HINDI PHISHING'] += 1
        elif 'LEGITIMATE' in test['category']:
            categories['LEGITIMATE'] += 1
        elif 'BORDERLINE' in test['category']:
            categories['BORDERLINE'] += 1

    for category, count in categories.items():
        print(f"{category}: {count} emails")

    print(f"\nTotal: {len(TEST_EMAILS)} test emails")
    print("\nKey Test Scenarios:")
    print("  ✓ Bank fraud (HDFC, SBI)")
    print("  ✓ UPI scams")
    print("  ✓ Aadhaar fraud")
    print("  ✓ Hindi/Hinglish phishing")
    print("  ✓ Job scams")
    print("  ✓ Legitimate banking emails")
    print("  ✓ Marketing emails (borderline)")
    print("  ✓ Password resets (borderline)")


# ============================================================================
# USAGE
# ============================================================================

if __name__ == "__main__":
    print("="*70)
    print("PHISHING DETECTION TEST SUITE - INDIAN SCENARIOS")
    print("="*70)

    print_test_summary()

    print("\n" + "="*70)
    print("HOW TO USE THIS TEST SUITE")
    print("="*70)
    print("""
1. Import your classification function:

   from train_email_model import classify_email
   from test_emails import run_tests, TEST_EMAILS

2. Run the test suite:

   results = run_tests(classify_email)

3. Or test individual emails:

   for test in TEST_EMAILS:
       result = classify_email(test['text'], test['sender'], test['subject'])
       print(f"{test['id']}: {result['label']} - {result['risk_score']}/100")

4. Access specific test cases:

   phishing_tests = [t for t in TEST_EMAILS if 'PHISHING' in t['category']]
   hindi_tests = [t for t in TEST_EMAILS if 'Hindi' in t['category']]
   legit_tests = [t for t in TEST_EMAILS if 'LEGITIMATE' in t['category']]
   borderline_tests = [t for t in TEST_EMAILS if 'BORDERLINE' in t['category']]
""")

    print("\n✅ Test suite loaded successfully!")
    print(f"   {len(TEST_EMAILS)} test emails ready to use.")
