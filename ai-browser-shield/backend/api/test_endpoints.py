#!/usr/bin/env python
"""Test /warmup endpoint"""
from app import app
import json

client = app.test_client()

try:
    # Test /health first (no external calls)
    resp = client.get('/health')
    print(f'✓ /health: {resp.status_code}')
    if resp.status_code == 200:
        print(f'  Response: {resp.get_json()}')
    
    print()
    
    # Test /warmup (checks LLM config)
    print('Testing /warmup endpoint...')
    resp = client.get('/warmup')
    print(f'Status: {resp.status_code}')
    data = resp.get_json()
    if data:
        print('Response fields:')
        for key, value in data.items():
            if key == 'key_model_map' and isinstance(value, dict):
                print(f'  {key}: {len(value)} keys with model info')
            else:
                print(f'  {key}: {value}')
    else:
        print(f'  Error: No JSON response')
        
except Exception as e:
    print(f'✗ Error: {type(e).__name__}: {e}')
    import traceback
    traceback.print_exc()
