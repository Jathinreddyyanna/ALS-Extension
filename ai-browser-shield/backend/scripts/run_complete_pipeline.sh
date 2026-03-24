#!/bin/bash
# Complete Email ML Pipeline - One Command Setup
# ==============================================

set -e  # Exit on any error

echo "=========================================================="
echo "EMAIL PHISHING ML MODEL - COMPLETE PIPELINE"
echo "=========================================================="
echo ""

# Check if we're in the right directory
if [ ! -f "email_ml_model.py" ]; then
    echo "❌ Error: Please run this from the backend/scripts directory"
    echo "   cd ai-browser-shield/backend/scripts"
    exit 1
fi

# Check Python
echo "Checking Python installation..."
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 not found. Please install Python 3.8+"
    exit 1
fi

python_version=$(python3 --version 2>&1 | awk '{print $2}')
echo "✓ Python $python_version found"

# Check dependencies
echo ""
echo "Checking dependencies..."
python3 -c "import pandas, numpy, sklearn" 2>/dev/null
if [ $? -eq 0 ]; then
    echo "✓ All dependencies installed"
else
    echo "Installing dependencies..."
    pip install pandas numpy scikit-learn
fi

echo ""
echo "=========================================================="
echo "STEP 1: PREPARE DATASET"
echo "=========================================================="

if [ ! -f "../data/cleaned_emails.csv" ]; then
    echo "Cleaning and preparing email dataset..."
    python3 prepare_email_dataset.py

    if [ $? -ne 0 ]; then
        echo "❌ Dataset preparation failed"
        exit 1
    fi
else
    echo "✓ Cleaned dataset already exists: $(ls -lh ../data/cleaned_emails.csv | awk '{print $5}')"
    read -p "Re-run dataset preparation? (y/N): " response
    if [[ "$response" =~ ^[Yy]$ ]]; then
        python3 prepare_email_dataset.py
    fi
fi

echo ""
echo "=========================================================="
echo "STEP 2: VALIDATE DATASET"
echo "=========================================================="

python3 validate_cleaned_dataset.py
if [ $? -ne 0 ]; then
    echo "⚠ Dataset validation found issues"
    read -p "Continue anyway? (y/N): " response
    if [[ ! "$response" =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

echo ""
echo "=========================================================="
echo "STEP 3: TRAIN ML MODEL"
echo "=========================================================="

if [ -f "../models/email_phishing_model.pkl" ]; then
    echo "⚠ Model already exists"
    read -p "Re-train model? This will take 5-10 minutes. (y/N): " response
    if [[ ! "$response" =~ ^[Yy]$ ]]; then
        echo "Skipping training. Using existing model."
    else
        python3 email_ml_model.py ../data/cleaned_emails.csv
    fi
else
    echo "Training model (this will take 5-10 minutes)..."
    python3 email_ml_model.py ../data/cleaned_emails.csv
fi

if [ $? -ne 0 ]; then
    echo "❌ Model training failed"
    exit 1
fi

echo ""
echo "=========================================================="
echo "STEP 4: TEST MODEL"
echo "=========================================================="

echo "Testing classification with sample phishing email..."
python3 << 'EOF'
from email_ml_model import classify_email

# Test 1: Obvious phishing
result = classify_email(
    "URGENT! Your account has been SUSPENDED. Click here: http://192.168.1.1/verify",
    "security123@amaz0n-verify.xyz",
    "URGENT: Account Suspended"
)

print("\nTest 1: Phishing Email")
print(f"  Label: {result['label']}")
print(f"  Risk Score: {result['risk_score']}/100")
print(f"  Confidence: {result['confidence']:.2%}")
print(f"  Expected: phishing with high risk score (>80)")

# Test 2: Legitimate email
result2 = classify_email(
    "Hi team, the project meeting is scheduled for tomorrow at 3 PM. Please review the documents.",
    "colleague@company.com",
    "Project Meeting Tomorrow"
)

print("\nTest 2: Legitimate Email")
print(f"  Label: {result2['label']}")
print(f"  Risk Score: {result2['risk_score']}/100")
print(f"  Confidence: {result2['confidence']:.2%}")
print(f"  Expected: legitimate with low risk score (<30)")

# Test 3: Hindi phishing
result3 = classify_email(
    "आपका account suspend हो गया है! तुरंत verify करें: http://bit.ly/verify",
    "support@hdfc-secure.tk",
    "खाता निलंबित"
)

print("\nTest 3: Hindi Phishing")
print(f"  Label: {result3['label']}")
print(f"  Risk Score: {result3['risk_score']}/100")
print(f"  Confidence: {result3['confidence']:.2%}")
print(f"  Expected: phishing with medium-high risk score (>60)")

print("\n" + "="*60)
if result['label'] == 'phishing' and result2['label'] == 'legitimate':
    print("✅ ALL TESTS PASSED!")
else:
    print("⚠ Some tests failed - review results above")
EOF

echo ""
echo "=========================================================="
echo "✅ SETUP COMPLETE!"
echo "=========================================================="
echo ""
echo "Files Created:"
echo "  - $(ls -lh ../data/cleaned_emails.csv 2>/dev/null | awk '{print "../data/cleaned_emails.csv (" $5 ")"}')"
echo "  - $(ls -lh ../models/email_phishing_model.pkl 2>/dev/null | awk '{print "../models/email_phishing_model.pkl (" $5 ")"}')"
echo "  - $(ls -lh ../models/email_model_metadata.json 2>/dev/null | awk '{print "../models/email_model_metadata.json (" $5 ")"}')"
echo ""
echo "Model Performance:"
if [ -f "../models/email_model_metadata.json" ]; then
    python3 -c "
import json
with open('../models/email_model_metadata.json') as f:
    m = json.load(f)['metrics']
print(f\"  Accuracy:  {m['accuracy']:.2%}\")
print(f\"  Precision: {m['precision']:.2%}\")
print(f\"  Recall:    {m['recall']:.2%}\")
print(f\"  F1-Score:  {m['f1_score']:.2%}\")
print(f\"  FPR:       {m['fpr']:.2%}\")
"
fi
echo ""
echo "Next Steps:"
echo "  1. Review metrics: cat ../models/email_model_metadata.json"
echo "  2. Test classification: python3 email_ml_model.py"
echo "  3. Integrate with backend API"
echo ""
echo "Usage in Python:"
echo "  from email_ml_model import classify_email"
echo "  result = classify_email(text, sender, subject)"
echo ""
echo "🎉 Your email phishing ML model is ready for demo!"
echo ""
