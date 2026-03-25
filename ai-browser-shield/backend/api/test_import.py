#!/usr/bin/env python
"""Quick test to verify app.py imports successfully"""
try:
    from app import app
    print('✓ App imported successfully')
    print('\nAvailable endpoints:')
    for rule in app.url_map.iter_rules():
        print(f'  {rule.rule} -> {rule.endpoint}')
    print('\n✓ Flask app is ready to use')
except Exception as e:
    print(f'✗ Error: {type(e).__name__}: {e}')
    import traceback
    traceback.print_exc()
