# 📊 Email Dataset Preparation Guide

## 🚀 Quick Start

### Run Command
```bash
cd ai-browser-shield/backend/scripts
python prepare_email_dataset.py
```

**Expected output:**
- Dataset exploration (columns, first 5 rows, class distribution)
- Conversion to standard format (text, sender, subject, label)
- Cleaning summary (removed rows, duplicates)
- Saved to: `../data/cleaned_emails.csv`

---

## 📋 What the Script Does

### STEP 1: Auto-Detect Dataset
- Searches for CSV files in `backend/data/`
- Ignores files with "cleaned" in name
- Prefers files with keywords: email, phish, CEAS, spam

**Detected file:** `CEAS_08.csv` (67MB)

### STEP 2: Load & Explore
- Prints column names
- Shows first 5 rows
- Displays class distribution
- Checks for missing values

### STEP 3: Convert to Standard Format
**Mapping:**
```
body    → text      (email content)
sender  → sender    (extract email address)
subject → subject   (email subject line)
label   → label     (normalized to 0/1)
```

### STEP 4: Clean Dataset
1. ✅ Remove rows with empty text
2. ✅ Fill missing sender/subject with placeholders
3. ✅ Convert all to proper data types (str, int)
4. ✅ Remove duplicate emails (based on text)
5. ✅ Validate labels are 0 or 1

### STEP 5: Save
**Output:** `backend/data/cleaned_emails.csv`

**Columns:**
- `text` - Email body content
- `sender` - Email address (extracted from sender field)
- `subject` - Email subject line
- `label` - 0 (legitimate) or 1 (phishing)

---

## ⚠️ Possible Issues & Solutions

### Issue 1: Encoding Errors
**Error:** `UnicodeDecodeError: 'utf-8' codec can't decode byte...`

**Solution:** Script tries multiple encodings automatically:
- utf-8
- latin-1
- iso-8859-1

If still fails, manually specify encoding:
```python
df = pd.read_csv(file_path, encoding='cp1252')
```

---

### Issue 2: Memory Error (Large File)
**Error:** `MemoryError` when loading 67MB file

**Solution:** Process in chunks:
```bash
# Reduce dataset size by sampling
head -50000 backend/data/CEAS_08.csv > backend/data/CEAS_08_sample.csv
python prepare_email_dataset.py
```

Or modify script to use chunks:
```python
df = pd.read_csv(file_path, chunksize=10000)
```

---

### Issue 3: Cannot Detect Label Column
**Error:** `ValueError: Could not detect label column`

**Possible cause:** Label column has unusual name

**Solution:** Check column names and add to detection:
```python
# In detect_label_column() function, add your label column name
possible_names = ['label', 'class', 'type', 'your_label_col_name']
```

---

### Issue 4: All Labels Mapped to Same Value
**Problem:** After cleaning, all labels are 0 or all are 1

**Cause:** Label normalization didn't recognize your label format

**Solution:** Check original label values:
```bash
# Check unique labels
cut -d',' -f6 backend/data/CEAS_08.csv | sort | uniq
```

Then update `normalize_labels()` function with your specific labels.

---

### Issue 5: Too Many Duplicates Removed
**Warning:** `Removed 50% rows as duplicates`

**Cause:** Either dataset has many identical emails, or text column is wrong

**Check:**
```python
# Print which column was used as text
# Look for this line in output:
# "✓ Mapping 'body' -> 'text'"
```

**Solution:** If wrong column used, manually specify:
```python
result['text'] = df['your_correct_column']
```

---

### Issue 6: Missing Sender/Subject Fields
**Warning:** `No sender column found, creating placeholder`

**Impact:** All senders will be "unknown@unknown.com"

**Solution:** This is OK for initial testing. Model can still work with text features.

For production, add proper sender extraction:
```python
# Check if your dataset has sender in different column
print(df.columns)
```

---

### Issue 7: Very Large Output File
**Problem:** cleaned_emails.csv is 60+ MB

**Impact:** Slow to load during training

**Solution:** Sample dataset:
```python
# After cleaning, before saving:
df_clean = df_clean.sample(n=10000, random_state=42)
```

Or use only suspicious emails:
```python
# Keep all phishing + sample of legitimate
phishing = df_clean[df_clean['label'] == 1]
legit = df_clean[df_clean['label'] == 0].sample(n=len(phishing), random_state=42)
df_clean = pd.concat([phishing, legit])
```

---

## 📊 Expected Output

### Dataset Info
```
Total rows: ~52,000 (after cleaning)
Total columns: 4 (text, sender, subject, label)
File size: ~40-50 MB
```

### Class Distribution (CEAS_08 dataset)
```
Legitimate (0): ~50%
Phishing (1):   ~50%
```
*(Actual distribution depends on original dataset)*

---

## ✅ Validation Checks

After script completes, verify:

1. **File exists:**
   ```bash
   ls -lh backend/data/cleaned_emails.csv
   ```

2. **Check columns:**
   ```bash
   head -1 backend/data/cleaned_emails.csv
   ```
   **Expected:** `text,sender,subject,label`

3. **Check sample rows:**
   ```bash
   head -5 backend/data/cleaned_emails.csv
   ```

4. **Count rows:**
   ```bash
   wc -l backend/data/cleaned_emails.csv
   ```

5. **Check label distribution:**
   ```bash
   cut -d',' -f4 backend/data/cleaned_emails.csv | sort | uniq -c
   ```

---

## 🔧 Manual Column Mapping (If Auto-Detection Fails)

If script can't detect columns automatically, modify the script:

```python
# In convert_to_standard_format(), add manual mapping:

result['text'] = df['your_body_column']
result['sender'] = df['your_sender_column']
result['subject'] = df['your_subject_column']
result['label'] = normalize_labels(df['your_label_column'])
```

---

## 🎯 Next Steps After Cleaning

1. **Verify cleaned dataset:**
   ```bash
   python
   >>> import pandas as pd
   >>> df = pd.read_csv('backend/data/cleaned_emails.csv')
   >>> print(df.shape)
   >>> print(df['label'].value_counts())
   >>> print(df.head())
   ```

2. **Train ML model:**
   ```bash
   python email_ml_model.py ../data/cleaned_emails.csv
   ```

3. **Expected training time:**
   - 5,000 emails: ~2 minutes
   - 50,000 emails: ~5-10 minutes
   - 100,000+ emails: ~15-30 minutes

---

## 🚨 Critical Warnings

1. **CEAS_08.csv is 67MB** - Make sure you have enough RAM (8GB+ recommended)
2. **Processing time:** 2-5 minutes for full dataset
3. **Duplicates:** Expect 10-20% duplicates to be removed
4. **Text encoding:** Some emails may have special characters (é, ñ, etc.) - handled automatically
5. **Long emails:** Some emails may be very long (>50KB) - consider truncating in training script

---

## 📝 Troubleshooting Checklist

- [ ] Python 3.8+ installed
- [ ] pandas library installed (`pip install pandas`)
- [ ] Dataset file exists in backend/data/
- [ ] Dataset has at least 4 columns (text, sender, subject, label)
- [ ] Free disk space >200MB
- [ ] RAM >4GB available
- [ ] Not running other memory-intensive programs

---

## 🎓 Understanding Your Dataset (CEAS_08)

**CEAS_08** is a well-known phishing email dataset from the 2008 CEAS (Conference on Email and Anti-Spam) challenge.

**Characteristics:**
- Real-world phishing emails
- Mix of spam and legitimate emails
- Contains HTML and plain text emails
- Multiple languages (mostly English)
- Various phishing techniques (bank fraud, lottery scams, etc.)

**Perfect for training hackathon ML models!** ✅

---

**If you encounter any other issues, check the error message carefully and adjust the script accordingly.**
