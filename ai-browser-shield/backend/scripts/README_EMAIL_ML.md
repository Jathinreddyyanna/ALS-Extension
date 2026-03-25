# Email Phishing ML Model - Quick Start Guide

## 📋 Requirements

```bash
pip install pandas numpy scikit-learn
```

## 🚀 Usage

### 1. Training the Model

```bash
python email_ml_model.py path/to/your/dataset.csv
```

**Expected CSV Format:**
```csv
text,sender,subject,label
"Dear customer...",scammer@evil.com,"Urgent Action Required",1
"Meeting tomorrow at 3pm",colleague@company.com,"Re: Project Update",0
```

- `text`: Email body content
- `sender`: Sender email address
- `subject`: Email subject (optional, can be empty)
- `label`: 0 = legitimate, 1 = phishing

### 2. Using the Classifier

```python
from email_ml_model import classify_email

result = classify_email(
    email_text="Your account has been suspended. Click here: http://phish.com",
    sender="noreply@suspicious-domain.xyz",
    subject="URGENT: Account Verification"
)

print(result['label'])        # "phishing" or "legitimate"
print(result['risk_score'])   # 0-100
print(result['confidence'])   # 0.0-1.0
```

## 📊 Output Format

```python
{
    "label": "phishing",              # Classification result
    "confidence": 0.92,               # Model confidence
    "probability": {
        "legitimate": 0.08,
        "phishing": 0.92
    },
    "risk_score": 92,                 # 0-100 scale
    "risk_level": "CRITICAL",         # LOW/MEDIUM/HIGH/CRITICAL
    "recommended_action": "block"     # allow/warn/block
}
```

## 🎯 Feature Set (19 features)

**Text Features (6):**
- email_length, word_count, capital_ratio, special_char_ratio
- urgency_score, money_signal

**URL Features (6):**
- url_count, has_url, has_ip_url, has_shortened_url
- suspicious_tld, url_domain_mismatch

**Sender Features (4):**
- sender_has_numbers, free_email_provider
- sender_display_mismatch, brand_mismatch

**Structural Features (3):**
- has_attachments, attachment_suspicious, html_to_text_ratio

## ⚡ Expected Performance

- **Accuracy:** 85-92%
- **Precision:** 88-93%
- **Recall:** 83-88%
- **F1-Score:** 85-89%
- **FPR:** 3-7%

## 📁 Output Files

After training:
- `../models/email_phishing_model.pkl` - Trained model
- `../models/email_model_metadata.json` - Metrics and configuration

## 🔧 Integration Example

```python
# In your backend API
from email_ml_model import classify_email

def analyze_email(email_data):
    ml_result = classify_email(
        email_text=email_data['body'],
        sender=email_data['from'],
        subject=email_data['subject']
    )

    # Combine with your existing heuristics
    final_score = combine_scores(ml_result, heuristic_score)

    return {
        'verdict': ml_result['label'],
        'riskScore': ml_result['risk_score'],
        'confidence': ml_result['confidence'],
        'explanation': generate_explanation(ml_result)
    }
```

## 🐛 Troubleshooting

**Q: Model file not found error?**
A: Make sure you've run training first and the model file exists at `../models/email_phishing_model.pkl`

**Q: Low accuracy on your dataset?**
A: Check if your dataset has balanced classes (similar # of phishing/legitimate emails)

**Q: Import errors?**
A: Install requirements: `pip install pandas numpy scikit-learn`

**Q: Training takes too long?**
A: Reduce `n_estimators` from 100 to 50 in `train_model()` function
