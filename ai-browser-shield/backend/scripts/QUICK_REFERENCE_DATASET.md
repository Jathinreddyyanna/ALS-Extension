# 🎯 QUICK REFERENCE - Dataset Preparation

## ✅ YOUR DATASET
**Located at:** `ai-browser-shield/backend/data/CEAS_08.csv`
- **Size:** 67 MB
- **Columns:** sender, receiver, date, subject, body, label, urls
- **Perfect for email phishing detection!** ✓

---

## 🚀 THREE COMMANDS TO RUN

### 1️⃣ Prepare Dataset (MUST DO FIRST)
```bash
cd ai-browser-shield/backend/scripts
python prepare_email_dataset.py
```

**What it does:**
- Loads CEAS_08.csv automatically
- Converts to standard format (text, sender, subject, label)
- Removes duplicates and nulls
- Saves to: `backend/data/cleaned_emails.csv`

**Expected time:** 2-3 minutes
**Expected output:** ~40-50MB CSV file with ~45,000+ emails

---

### 2️⃣ Validate Cleaned Dataset (OPTIONAL BUT RECOMMENDED)
```bash
python validate_cleaned_dataset.py
```

**What it checks:**
- File exists ✓
- Has correct columns ✓
- Labels are 0/1 ✓
- No missing values ✓
- Shows sample data

**Expected output:** "✅ Dataset is ready for training!"

---

### 3️⃣ Train ML Model (AFTER CLEANING)
```bash
python email_ml_model.py ../data/cleaned_emails.csv
```

**What it does:**
- Extracts 19 features from emails
- Trains RandomForest classifier
- Shows accuracy, precision, recall, F1, FPR
- Saves model to: `../models/email_phishing_model.pkl`

**Expected time:** 5-10 minutes for ~45,000 emails
**Expected accuracy:** 85-92%

---

## 📊 COMPLETE WORKFLOW

```bash
# Step 1: Navigate to scripts directory
cd ai-browser-shield/backend/scripts

# Step 2: Prepare dataset
python prepare_email_dataset.py

# Step 3: Validate (optional)
python validate_cleaned_dataset.py

# Step 4: Train model
python email_ml_model.py ../data/cleaned_emails.csv

# Done! Model saved at: ../models/email_phishing_model.pkl
```

---

## ⚠️ POSSIBLE ISSUES & SOLUTIONS

### Issue 1: "No module named 'pandas'"
**Solution:**
```bash
pip install pandas numpy scikit-learn
```

---

### Issue 2: "MemoryError" (System runs out of RAM)
**Solution:** Reduce dataset size
```bash
# Create smaller sample of CEAS_08.csv
head -10000 backend/data/CEAS_08.csv > backend/data/CEAS_08_sample.csv

# Then run prepare script (will auto-detect sample file)
python prepare_email_dataset.py
```

---

### Issue 3: Script takes too long (>10 minutes)
**Cause:** Large dataset or slow computer

**Solution:** Sample the cleaned dataset
```python
# After running prepare_email_dataset.py, reduce size:
import pandas as pd
df = pd.read_csv('../data/cleaned_emails.csv')
df_sample = df.sample(n=5000, random_state=42)
df_sample.to_csv('../data/cleaned_emails.csv', index=False)
```

---

### Issue 4: "UnicodeDecodeError"
**Cause:** Special characters in emails

**Status:** ✅ Already handled by script (tries multiple encodings)

---

### Issue 5: All labels are 0 or all are 1
**Cause:** Label column not detected properly

**Solution:** Check what labels exist in CEAS_08.csv
```bash
# Check unique label values
cut -d',' -f6 backend/data/CEAS_08.csv | sort | uniq -c
```

Then update `normalize_labels()` function in prepare_email_dataset.py

---

### Issue 6: "Too many duplicates removed"
**Normal:** CEAS dataset may have ~10-15% duplicates

**Concern:** If >40% removed, something may be wrong

**Check:**
```bash
python prepare_email_dataset.py
# Look for line: "✓ Removed X duplicate emails"
```

---

### Issue 7: Cleaned dataset is still too large (>100MB)
**Solution:** Sample after cleaning
```python
import pandas as pd
df = pd.read_csv('../data/cleaned_emails.csv')

# Keep balanced sample: 2500 phishing + 2500 legitimate
phish = df[df['label'] == 1].sample(n=2500, random_state=42)
legit = df[df['label'] == 0].sample(n=2500, random_state=42)
df_balanced = pd.concat([phish, legit]).sample(frac=1, random_state=42)

df_balanced.to_csv('../data/cleaned_emails.csv', index=False)
print(f"Reduced to {len(df_balanced)} emails")
```

---

## 🎯 EXPECTED OUTPUTS

### After Step 1 (Prepare Dataset)
```
DATASET EXPLORATION
Total rows: 52790
Columns: ['sender', 'receiver', 'date', 'subject', 'body', 'label', 'urls']

CLASS DISTRIBUTION
Legitimate: 26395 (50%)
Phishing: 26395 (50%)

CONVERTING TO STANDARD FORMAT
✓ Mapping 'body' -> 'text'
✓ Mapping 'sender' -> 'sender'
✓ Mapping 'subject' -> 'subject'
✓ Mapping 'label' -> 'label'

CLEANING DATASET
✓ Removed 412 rows with missing/empty text
✓ Removed 5234 duplicate emails
Final row count: 47144

SAVED: backend/data/cleaned_emails.csv
```

---

### After Step 2 (Validate Dataset)
```
DATASET VALIDATION
✓ File exists: ../data/cleaned_emails.csv
✓ Successfully loaded: 47144 rows
✓ Has all required columns: ['text', 'sender', 'subject', 'label']
✓ Labels are valid: [0, 1]
✓ No missing values
✓ No empty text fields

Legitimate (0): 23570 (50%)
Phishing (1):   23574 (50%)

✅ Dataset is ready for training!
```

---

### After Step 3 (Train Model)
```
MODEL PERFORMANCE METRICS
Accuracy:  0.8912 (89.12%)
Precision: 0.9145 (91.45%)
Recall:    0.8654 (86.54%)
F1-Score:  0.8893 (88.93%)
FPR:       0.0463 (4.63%)

Model saved to: ../models/email_phishing_model.pkl
Metadata saved to: ../models/email_model_metadata.json
```

---

## 📁 FILES CREATED

After running all steps, you'll have:

```
backend/
├── data/
│   ├── CEAS_08.csv (original - 67MB)
│   └── cleaned_emails.csv (cleaned - ~40MB) ✅
├── models/
│   ├── email_phishing_model.pkl (trained model - ~15MB) ✅
│   └── email_model_metadata.json (metrics) ✅
└── scripts/
    ├── prepare_email_dataset.py
    ├── validate_cleaned_dataset.py
    ├── email_ml_model.py
    └── (other scripts)
```

---

## 🚨 CRITICAL CHECKS BEFORE TRAINING

1. **Cleaned dataset exists:**
   ```bash
   ls -lh backend/data/cleaned_emails.csv
   # Should show ~30-50MB file
   ```

2. **Has correct format:**
   ```bash
   head -1 backend/data/cleaned_emails.csv
   # Should show: text,sender,subject,label
   ```

3. **Has data:**
   ```bash
   wc -l backend/data/cleaned_emails.csv
   # Should show 5,000+ lines
   ```

4. **Labels are balanced:**
   ```bash
   cut -d',' -f4 backend/data/cleaned_emails.csv | tail -n +2 | sort | uniq -c
   # Should show similar counts for 0 and 1
   ```

---

## ⏱️ TIME ESTIMATES

| Task | Time | RAM Needed |
|------|------|------------|
| Prepare dataset | 2-3 min | 2GB |
| Validate dataset | 10 sec | 1GB |
| Train model (5K emails) | 2-3 min | 2GB |
| Train model (50K emails) | 8-12 min | 4GB |

**Total time from zero to trained model: ~15 minutes**

---

## 🎓 UNDERSTANDING CEAS_08 LABELS

The CEAS_08 dataset uses these labels:
- **0** = Legitimate email (ham)
- **1** = Phishing/spam email

After cleaning, your dataset will have:
- ~50% legitimate emails
- ~50% phishing emails

**This is IDEAL for training!** ✅ Balanced dataset = better model performance

---

## ✅ SUCCESS CHECKLIST

Before demo day, verify:

- [ ] `cleaned_emails.csv` exists and is 30-50MB
- [ ] Dataset has 5,000+ emails
- [ ] Class distribution is roughly 50/50
- [ ] Model file `email_phishing_model.pkl` exists
- [ ] Model accuracy is >85%
- [ ] Can call `classify_email()` without errors
- [ ] False positive rate is <7%

---

## 🆘 EMERGENCY FALLBACK

If CEAS_08.csv causes problems, use synthetic data:

```bash
# Generate 500 synthetic emails
python generate_test_dataset.py 500

# This creates: test_phishing_dataset.csv
# Then train on that:
python email_ml_model.py test_phishing_dataset.csv
```

**Note:** Synthetic data will give ~70-80% accuracy (lower than real data)

---

## 📞 QUICK HELP

**Problem:** Script crashes or hangs
**Fix:** Kill process (Ctrl+C), reduce dataset size, try again

**Problem:** Can't find CSV file
**Fix:** Ensure you're in `backend/scripts/` directory

**Problem:** Model accuracy <80%
**Fix:** Check if labels are correct, try balancing dataset

**Problem:** Model takes >30 minutes to train
**Fix:** Reduce dataset to 10,000 emails max

---

## 🎯 YOU'RE READY WHEN...

You can run this test successfully:

```python
from email_ml_model import classify_email

result = classify_email(
    email_text="URGENT! Your account suspended. Click: http://192.168.1.1/verify",
    sender="security123@phishing.xyz",
    subject="Account Suspended"
)

print(result['label'])        # Should print: "phishing"
print(result['risk_score'])   # Should print: 85-95
```

---

**If that works, YOU'RE DONE! Model is ready for integration!** 🎉
