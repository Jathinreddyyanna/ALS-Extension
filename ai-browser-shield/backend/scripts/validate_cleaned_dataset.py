"""
Quick Dataset Validator
=======================
Validates cleaned email dataset before training ML model.
"""

import pandas as pd
import os


def validate_cleaned_dataset(file_path='../data/cleaned_emails.csv'):
    """
    Validate cleaned email dataset.

    Args:
        file_path: Path to cleaned dataset

    Returns:
        True if valid, False otherwise
    """
    print("="*60)
    print("DATASET VALIDATION")
    print("="*60)
    print("")

    # Check file exists
    if not os.path.exists(file_path):
        print(f"❌ File not found: {file_path}")
        print("Run: python prepare_email_dataset.py")
        return False

    print(f"✓ File exists: {file_path}")
    print(f"  File size: {os.path.getsize(file_path) / (1024*1024):.2f} MB")

    # Load dataset
    try:
        df = pd.read_csv(file_path)
        print(f"✓ Successfully loaded: {len(df)} rows")
    except Exception as e:
        print(f"❌ Failed to load: {e}")
        return False

    # Check columns
    required_cols = ['text', 'sender', 'subject', 'label']
    missing_cols = [col for col in required_cols if col not in df.columns]

    if missing_cols:
        print(f"❌ Missing required columns: {missing_cols}")
        print(f"   Found columns: {list(df.columns)}")
        return False

    print(f"✓ Has all required columns: {required_cols}")

    # Check data types
    if df['text'].dtype != 'object':
        print(f"⚠ Warning: 'text' column is not string type")

    if df['label'].dtype not in ['int64', 'int32']:
        print(f"⚠ Warning: 'label' column is not integer type")

    # Check for missing values
    missing = df.isnull().sum()
    if missing.sum() > 0:
        print(f"⚠ Warning: Found missing values:")
        for col, count in missing[missing > 0].items():
            print(f"   {col}: {count} missing ({count/len(df)*100:.2f}%)")
    else:
        print(f"✓ No missing values")

    # Check label values
    unique_labels = sorted(df['label'].unique())
    if set(unique_labels) != {0, 1}:
        print(f"❌ Invalid labels: {unique_labels}")
        print(f"   Expected: [0, 1]")
        return False

    print(f"✓ Labels are valid: {unique_labels}")

    # Class distribution
    counts = df['label'].value_counts().sort_index()
    print(f"\n  Legitimate (0): {counts[0]} ({counts[0]/len(df)*100:.2f}%)")
    print(f"  Phishing (1):   {counts[1]} ({counts[1]/len(df)*100:.2f}%)")

    # Check for empty text
    empty_text = df[df['text'].str.strip() == '']
    if len(empty_text) > 0:
        print(f"⚠ Warning: {len(empty_text)} rows have empty text")
    else:
        print(f"✓ No empty text fields")

    # Check duplicates
    duplicates = df.duplicated(subset=['text']).sum()
    if duplicates > 0:
        print(f"⚠ Warning: {duplicates} duplicate emails found")
    else:
        print(f"✓ No duplicate emails")

    # Sample data
    print("\n" + "="*60)
    print("SAMPLE DATA (First 2 rows)")
    print("="*60)

    for idx in range(min(2, len(df))):
        row = df.iloc[idx]
        print(f"\nRow {idx + 1}:")
        print(f"  Text (100 chars): {row['text'][:100]}...")
        print(f"  Sender: {row['sender']}")
        print(f"  Subject: {row['subject'][:60]}")
        print(f"  Label: {row['label']} ({'Phishing' if row['label'] == 1 else 'Legitimate'})")

    # Dataset stats
    print("\n" + "="*60)
    print("DATASET STATISTICS")
    print("="*60)

    avg_length = df['text'].str.len().mean()
    min_length = df['text'].str.len().min()
    max_length = df['text'].str.len().max()

    print(f"\nEmail length statistics:")
    print(f"  Average: {avg_length:.0f} characters")
    print(f"  Minimum: {min_length:.0f} characters")
    print(f"  Maximum: {max_length:.0f} characters")

    # Check if dataset is ready for training
    print("\n" + "="*60)
    print("READINESS CHECK")
    print("="*60)

    issues = []

    if len(df) < 500:
        issues.append(f"Dataset too small ({len(df)} rows). Recommend at least 500 rows.")

    if counts[0] / counts[1] > 10 or counts[1] / counts[0] > 10:
        issues.append(f"Highly imbalanced dataset. Consider balancing.")

    if duplicates > len(df) * 0.1:
        issues.append(f"Too many duplicates ({duplicates}). Re-run cleaning.")

    if issues:
        print("\n⚠ Issues found:")
        for issue in issues:
            print(f"  - {issue}")
    else:
        print("\n✅ Dataset is ready for training!")

    print("\n" + "="*60)
    return len(issues) == 0


if __name__ == "__main__":
    is_valid = validate_cleaned_dataset()

    if is_valid:
        print("\n🎯 Next step: Train your model")
        print("   python email_ml_model.py ../data/cleaned_emails.csv")
    else:
        print("\n⚠ Please fix issues above before training")
