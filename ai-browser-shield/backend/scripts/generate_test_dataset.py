"""
Quick Dataset Generator for Testing Email ML Model
===================================================
Generates a small synthetic phishing email dataset for testing.
"""

import pandas as pd
import random

# Sample legitimate emails
LEGITIMATE_EMAILS = [
    {
        'text': 'Hi team, the meeting is scheduled for tomorrow at 3 PM. Please review the attached documents beforehand. Thanks!',
        'sender': 'john.smith@company.com',
        'subject': 'Meeting Reminder - Project Review',
        'label': 0
    },
    {
        'text': 'Your order #12345 has been shipped and will arrive in 3-5 business days. Track your package using the link below.',
        'sender': 'orders@amazon.com',
        'subject': 'Your Amazon Order Has Shipped',
        'label': 0
    },
    {
        'text': 'Thank you for your subscription to our newsletter. You will receive weekly updates about new features and tips.',
        'sender': 'newsletter@linkedin.com',
        'subject': 'Welcome to LinkedIn Newsletter',
        'label': 0
    },
    {
        'text': 'Your monthly statement is ready. You can view it in your account dashboard. No action needed.',
        'sender': 'statements@chase.com',
        'subject': 'Your Monthly Statement is Available',
        'label': 0
    },
    {
        'text': 'Reminder: Your appointment with Dr. Johnson is scheduled for Friday, March 25 at 2:00 PM.',
        'sender': 'appointments@healthcare.org',
        'subject': 'Appointment Reminder',
        'label': 0
    },
]

# Sample phishing emails
PHISHING_EMAILS = [
    {
        'text': 'URGENT! Your account has been SUSPENDED due to suspicious activity. Click here IMMEDIATELY to verify: http://192.168.1.100/verify or your account will be PERMANENTLY DELETED in 24 hours!',
        'sender': 'security123@amaz0n-verify.xyz',
        'subject': 'URGENT: Account Suspended - Immediate Action Required!',
        'label': 1
    },
    {
        'text': 'Congratulations! You have won $5000 in our lottery! Click this link to claim your prize now: http://bit.ly/win5k Limited time offer!',
        'sender': 'winner@lottery-claim.tk',
        'subject': 'You Won $5000! Claim Now!!!',
        'label': 1
    },
    {
        'text': 'Dear valued customer, your HDFC Bank account requires verification. Please update your details here: http://hdfc-secure.ml/update to avoid account closure.',
        'sender': 'noreply99@hdfc-security.com',
        'subject': 'HDFC Bank - Urgent: Verify Your Account',
        'label': 1
    },
    {
        'text': 'Hello! I am Prince from Nigeria. I need your help transferring $10,000,000. I will give you 20% commission. Reply with your bank details immediately!',
        'sender': 'prince_abdul@yahoo.com',
        'subject': 'Urgent Business Proposal - $2 Million for You',
        'label': 1
    },
    {
        'text': 'Your package could not be delivered. Download the attached invoice.exe to reschedule delivery. Act now or package will be returned!',
        'sender': 'delivery@fedex-support.xyz',
        'subject': 'Failed Delivery - Action Required',
        'label': 1
    },
    {
        'text': 'ALERT: Your Microsoft account was accessed from Russia. Click here ASAP to secure: http://microsoft-security.top/secure Password will expire in 6 hours!',
        'sender': 'alerts@micro-soft.com',
        'subject': 'Security Alert: Unusual Sign-In Activity',
        'label': 1
    },
    {
        'text': 'Your Aadhaar card has been suspended by UIDAI. Verify your details immediately: http://uidai-verify.ml/update Failure to verify will result in legal action.',
        'sender': 'uidai-support123@gov-india.tk',
        'subject': 'Aadhaar Verification Required - Urgent',
        'label': 1
    },
]


def generate_variations(base_emails, n_variations=50):
    """Generate variations of base emails to create larger dataset."""
    variations = []

    urgency_words = ['URGENT', 'IMMEDIATELY', 'NOW', 'QUICKLY', 'ASAP', 'HURRY']
    money_amounts = ['$500', '$1000', '₹5000', '₹10000', '$5000', '$10000']

    for _ in range(n_variations):
        email = random.choice(base_emails).copy()

        # Add random variations to phishing emails
        if email['label'] == 1:
            # Randomly add urgency words
            if random.random() > 0.5:
                email['text'] = random.choice(urgency_words) + '! ' + email['text']

            # Randomly change money amounts
            if random.random() > 0.6:
                for old_amount in money_amounts:
                    if old_amount in email['text']:
                        new_amount = random.choice(money_amounts)
                        email['text'] = email['text'].replace(old_amount, new_amount)

        variations.append(email)

    return variations


def create_test_dataset(output_path='test_phishing_dataset.csv', size=200):
    """
    Create a test dataset for email phishing detection.

    Args:
        output_path: Path to save CSV file
        size: Total number of emails (will be split 50/50)
    """
    print(f"Generating test dataset with {size} emails...")

    # Generate variations
    n_per_class = size // 2

    legit_variations = generate_variations(LEGITIMATE_EMAILS, n_per_class)
    phish_variations = generate_variations(PHISHING_EMAILS, n_per_class)

    # Combine and shuffle
    all_emails = legit_variations + phish_variations
    random.shuffle(all_emails)

    # Create DataFrame
    df = pd.DataFrame(all_emails)

    # Save to CSV
    df.to_csv(output_path, index=False)

    print(f"✓ Dataset created: {output_path}")
    print(f"  - Total emails: {len(df)}")
    print(f"  - Legitimate: {sum(df['label'] == 0)}")
    print(f"  - Phishing: {sum(df['label'] == 1)}")
    print(f"\nYou can now train your model with:")
    print(f"  python email_ml_model.py {output_path}")

    return output_path


if __name__ == "__main__":
    import sys

    size = int(sys.argv[1]) if len(sys.argv) > 1 else 200
    output = sys.argv[2] if len(sys.argv) > 2 else 'test_phishing_dataset.csv'

    create_test_dataset(output, size)
