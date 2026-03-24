"""
AI Explanation System - Phishing Detection
==========================================
Generates clear, actionable explanations for phishing detection results
"""

def generate_explanation_prompt(risk_score, detected_features, email_content):
    """
    Create a prompt for AI to generate phishing explanation.

    Args:
        risk_score: 0-100 integer
        detected_features: list of detected signals (e.g., ['suspicious_tld', 'urgency_score'])
        email_content: dict with 'text', 'sender', 'subject'

    Returns:
        Formatted prompt string for AI (Gemini/GPT)
    """

    # Map feature names to human-readable descriptions
    FEATURE_DESCRIPTIONS = {
        'suspicious_tld': 'suspicious website address (.xyz, .tk domain)',
        'has_ip_url': 'direct IP address link (not a real website)',
        'has_shortened_url': 'hidden shortened link (bit.ly, tinyurl)',
        'url_domain_mismatch': 'link text doesn\'t match actual destination',
        'brand_mismatch': 'claims to be from a company but email address doesn\'t match',
        'sender_has_numbers': 'sender email contains random numbers',
        'sender_display_mismatch': 'display name doesn\'t match email address',
        'free_email_provider': 'uses free email (Gmail/Yahoo) for official communication',
        'urgency_score': 'creates false urgency (URGENT, IMMEDIATE, expires soon)',
        'money_signal': 'mentions money/prizes/refunds to lure you',
        'attachment_suspicious': 'dangerous file type attached (.exe, .zip)',
        'capital_ratio': 'excessive UPPERCASE text',
        'special_char_ratio': 'excessive special characters (!!!, $$$)',
    }

    # Convert detected features to readable list
    readable_features = [FEATURE_DESCRIPTIONS.get(f, f) for f in detected_features if f in FEATURE_DESCRIPTIONS]

    # Determine risk level
    if risk_score >= 80:
        risk_level = "🔴 CRITICAL THREAT"
    elif risk_score >= 60:
        risk_level = "🟠 HIGH RISK"
    elif risk_score >= 30:
        risk_level = "🟡 SUSPICIOUS"
    else:
        risk_level = "🟢 LOW RISK"

    prompt = f"""You are a cybersecurity assistant explaining phishing threats to non-technical users.

EMAIL DETAILS:
Subject: {email_content.get('subject', 'N/A')}
Sender: {email_content.get('sender', 'N/A')}
Content Preview: {email_content.get('text', '')[:200]}...

DETECTED SIGNALS:
{chr(10).join(f'- {feat}' for feat in readable_features) if readable_features else '- No specific red flags detected'}

RISK SCORE: {risk_score}/100

INSTRUCTIONS:
Generate a SHORT, CLEAR explanation in this EXACT format:

⚠️ Risk Level: {risk_level}

Why This Is Suspicious:
• [1 sentence explaining main red flag]
• [1 sentence explaining second red flag if applicable]
• [Maximum 3 bullet points, each under 15 words]

What Could Happen If You Click:
• [1 specific consequence]
• [1 specific consequence]
• [Maximum 3 bullets, be specific to this email type]

What You Should Do:
✓ [1 specific action]
✓ [1 specific action if needed]
✗ [1 thing NOT to do]

RULES:
- Use simple, everyday language
- NO technical jargon (avoid: IP address, TLD, domain, phishing)
- Each bullet point: maximum 15 words
- Be specific to THIS email, not generic
- Focus on real consequences (money loss, account theft, identity fraud)
- If risk is LOW, be reassuring but still cautious

Generate the explanation now:"""

    return prompt


# ============================================================================
# PRE-BUILT TEMPLATES FOR COMMON SCENARIOS (FASTER ALTERNATIVE)
# ============================================================================

def get_quick_explanation(risk_score, detected_features, email_type='generic'):
    """
    Get instant explanation without AI call (faster for demo).

    Args:
        risk_score: 0-100
        detected_features: list of feature names
        email_type: 'bank', 'package', 'prize', 'job', 'generic'

    Returns:
        Formatted explanation dict
    """

    # Determine risk level
    if risk_score >= 80:
        risk_level = "🔴 CRITICAL THREAT"
        action_verb = "Block"
    elif risk_score >= 60:
        risk_level = "🟠 HIGH RISK"
        action_verb = "Avoid"
    elif risk_score >= 30:
        risk_level = "🟡 SUSPICIOUS"
        action_verb = "Be Careful"
    else:
        risk_level = "🟢 SAFE"
        action_verb = "Looks OK"

    # Build explanation based on detected features
    reasons = []
    if 'suspicious_tld' in detected_features or 'has_ip_url' in detected_features:
        reasons.append("Website link looks fake or untrustworthy")
    if 'brand_mismatch' in detected_features:
        reasons.append("Claims to be from a company but sender doesn't match")
    if 'urgency_score' in detected_features:
        reasons.append("Creates fake urgency to make you panic and click quickly")
    if 'has_shortened_url' in detected_features:
        reasons.append("Uses hidden links to disguise real destination")
    if 'sender_display_mismatch' in detected_features or 'sender_has_numbers' in detected_features:
        reasons.append("Sender email address looks suspicious or fake")
    if 'money_signal' in detected_features:
        reasons.append("Promises money or prizes that seem too good to be true")
    if 'attachment_suspicious' in detected_features:
        reasons.append("Contains dangerous file types that could harm your computer")

    # Default reason if none detected
    if not reasons:
        reasons = ["Multiple warning signs detected in this email"]

    # Consequences based on email type
    consequences_map = {
        'bank': [
            "Criminals could steal money from your bank account",
            "Your personal banking details could be stolen",
            "Identity theft - criminals could take loans in your name"
        ],
        'package': [
            "Malware could be installed on your device",
            "Your personal information could be stolen",
            "You could be charged for services you didn't order"
        ],
        'prize': [
            "You'll lose money paying fake \"processing fees\"",
            "Your credit card details will be stolen",
            "Your identity could be used for fraud"
        ],
        'job': [
            "You'll lose money paying fake registration fees",
            "Your personal documents (Aadhaar, PAN) could be misused",
            "Your identity could be used for illegal activities"
        ],
        'generic': [
            "Your passwords and personal data could be stolen",
            "Malware could infect your device",
            "Your identity could be stolen for fraud"
        ]
    }

    consequences = consequences_map.get(email_type, consequences_map['generic'])

    # Actions based on risk level
    if risk_score >= 60:
        actions = [
            "✓ Delete this email immediately without clicking anything",
            "✓ Report as spam/phishing to protect others",
            "✗ Never share OTP, password, or card details"
        ]
    elif risk_score >= 30:
        actions = [
            "✓ Verify sender by contacting company directly using official number",
            "✓ Don't click links - type website address manually instead",
            "✗ Don't respond or engage with this email"
        ]
    else:
        actions = [
            "✓ This appears safe but remain cautious",
            "✓ Verify sender if asking for sensitive information",
            "✗ Never share passwords or OTPs even if email looks real"
        ]

    return {
        'risk_level': risk_level,
        'reasons': reasons[:3],  # Max 3 reasons
        'consequences': consequences[:3],  # Max 3 consequences
        'actions': actions
    }


def format_explanation(explanation_dict):
    """
    Format explanation dict into readable text.

    Args:
        explanation_dict: Output from get_quick_explanation()

    Returns:
        Formatted string
    """
    output = f"""⚠️ Risk Level: {explanation_dict['risk_level']}

Why This Is Suspicious:
{chr(10).join(f'• {reason}' for reason in explanation_dict['reasons'])}

What Could Happen If You Click:
{chr(10).join(f'• {cons}' for cons in explanation_dict['consequences'])}

What You Should Do:
{chr(10).join(action for action in explanation_dict['actions'])}
"""
    return output


# ============================================================================
# USAGE EXAMPLES
# ============================================================================

if __name__ == "__main__":
    print("="*70)
    print("AI EXPLANATION SYSTEM - EXAMPLES")
    print("="*70)

    # Example 1: High-risk phishing
    print("\n" + "="*70)
    print("EXAMPLE 1: High-Risk Phishing (Bank Scam)")
    print("="*70)

    explanation1 = get_quick_explanation(
        risk_score=92,
        detected_features=['suspicious_tld', 'brand_mismatch', 'urgency_score', 'has_ip_url'],
        email_type='bank'
    )
    print(format_explanation(explanation1))

    # Example 2: Medium-risk suspicious
    print("\n" + "="*70)
    print("EXAMPLE 2: Suspicious Email (Prize Scam)")
    print("="*70)

    explanation2 = get_quick_explanation(
        risk_score=68,
        detected_features=['money_signal', 'sender_has_numbers', 'has_shortened_url'],
        email_type='prize'
    )
    print(format_explanation(explanation2))

    # Example 3: Low-risk
    print("\n" + "="*70)
    print("EXAMPLE 3: Low Risk (Legitimate Email)")
    print("="*70)

    explanation3 = get_quick_explanation(
        risk_score=15,
        detected_features=[],
        email_type='generic'
    )
    print(format_explanation(explanation3))

    # Show how to use with AI
    print("\n" + "="*70)
    print("HOW TO USE WITH AI (Gemini/GPT)")
    print("="*70)
    print("""
# Option 1: Quick Template (No AI needed - faster)
from explain_phishing import get_quick_explanation, format_explanation

explanation = get_quick_explanation(
    risk_score=85,
    detected_features=['suspicious_tld', 'urgency_score'],
    email_type='bank'
)
print(format_explanation(explanation))

# Option 2: AI-Generated (More contextual)
from explain_phishing import generate_explanation_prompt
from your_ai_client import call_gemini  # Your AI client

prompt = generate_explanation_prompt(
    risk_score=85,
    detected_features=['suspicious_tld', 'urgency_score'],
    email_content={
        'text': 'URGENT! Your account...',
        'sender': 'security@bank-xyz.tk',
        'subject': 'Account Suspended'
    }
)

# Send to AI
ai_explanation = call_gemini(prompt)
print(ai_explanation)
""")

    print("\n" + "="*70)
    print("✅ EXPLANATION SYSTEM READY")
    print("="*70)
    print("\nFeatures:")
    print("  ✓ Quick template mode (no AI, instant)")
    print("  ✓ AI prompt mode (contextual, dynamic)")
    print("  ✓ Risk-based explanations (critical/high/low)")
    print("  ✓ Email-type specific consequences (bank/job/prize)")
    print("  ✓ Non-technical language")
    print("  ✓ Actionable recommendations")
