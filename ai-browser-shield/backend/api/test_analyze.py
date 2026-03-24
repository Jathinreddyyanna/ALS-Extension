#!/usr/bin/env python
"""Test /analyze-email endpoint"""
from app import app
import json

client = app.test_client()

# Sample phishing email
test_payload = {
    "email_text": "Your account has been temporarily suspended due to suspicious activity. Click here to verify: http://amazon-verify-secure.info/login",
    "sender_email": "noreply@amazon-security-verify.com"
}

try:
    print('Testing /analyze-email endpoint with phishing example...\n')
    resp = client.post('/analyze-email', json=test_payload)
    print(f'Status: {resp.status_code}')
    
    data = resp.get_json()
    if data:
        print('\n✓ Response received:')
        for key, value in data.items():
            if isinstance(value, dict):
                print(f'\n  {key}:')
                for k, v in value.items():
                    print(f'    {k}: {v}')
            elif isinstance(value, list) and key == 'detected_signals':
                print(f'  {key}: {len(value)} signals detected')
                for signal in value[:3]:  # Show first 3
                    print(f'    - {signal}')
                if len(value) > 3:
                    print(f'    ... and {len(value) - 3} more')
            else:
                print(f'  {key}: {value}')
        
        # Verify response has required fields from refactored code
        required_fields = ['risk_score', 'risk_level', 'intent', 'reasons', 'analysis_source', 'analysis_note']
        missing = [f for f in required_fields if f not in data]
        if missing:
            print(f'\n⚠ Missing fields: {missing}')
        else:
            print(f'\n✓ All required response fields present!')
    else:
        print('Error: No JSON response')
    
except Exception as e:
    print(f'✗ Error: {type(e).__name__}: {e}')
    import traceback
    traceback.print_exc()
