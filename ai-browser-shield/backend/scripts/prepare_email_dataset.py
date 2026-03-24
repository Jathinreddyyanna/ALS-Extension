"""
Email Dataset Preparation Script
=================================
Loads raw phishing email dataset, cleans it, and converts to standard format.

Output Format:
- text (email body)
- sender (email address)
- subject (email subject)
- label (1=phishing, 0=legitimate)
"""

import pandas as pd
import os
import glob
import re


def find_dataset(data_dir='../data'):
    """
    Auto-detect CSV file in data directory.

    Args:
        data_dir: Path to data directory

    Returns:
        Path to dataset file or None
    """
    csv_files = glob.glob(os.path.join(data_dir, '*.csv'))

    # Filter out cleaned files
    csv_files = [f for f in csv_files if 'cleaned' not in f.lower()]

    if not csv_files:
        return None

    # Prefer files with 'email', 'phish', 'CEAS' in name
    for f in csv_files:
        basename = os.path.basename(f).lower()
        if any(keyword in basename for keyword in ['email', 'phish', 'ceas', 'spam']):
            return f

    # Otherwise return first CSV
    return csv_files[0]


def detect_label_column(df):
    """
    Detect which column contains labels.

    Args:
        df: DataFrame

    Returns:
        Column name or None
    """
    possible_names = ['label', 'class', 'type', 'category', 'spam', 'is_phishing', 'target']

    for col in df.columns:
        if col.lower() in possible_names:
            return col

    return None


def normalize_labels(series):
    """
    Normalize labels to 0 (legitimate) and 1 (phishing).

    Handles various formats:
    - 'spam'/'ham' or 'phishing'/'legitimate'
    - 1/0
    - True/False

    Args:
        series: Pandas Series with labels

    Returns:
        Series with normalized labels (0 or 1)
    """
    # If already numeric 0/1, return as is
    if series.dtype in ['int64', 'int32'] and set(series.unique()).issubset({0, 1}):
        return series.astype(int)

    # Convert to string for consistent handling
    series_str = series.astype(str).str.lower().str.strip()

    # Map various phishing labels to 1
    phishing_labels = ['spam', 'phishing', 'phish', 'malicious', '1', 'true', 'yes', 'malware']
    legitimate_labels = ['ham', 'legitimate', 'legit', 'safe', '0', 'false', 'no', 'good']

    def classify_label(value):
        if any(label in value for label in phishing_labels):
            return 1
        elif any(label in value for label in legitimate_labels):
            return 0
        else:
            # Default: if contains number 1, it's phishing, else legitimate
            return 1 if '1' in value else 0

    return series_str.apply(classify_label)


def extract_email_address(sender_str):
    """
    Extract email address from sender string.
    Examples:
    - "John Doe <john@example.com>" -> "john@example.com"
    - "john@example.com" -> "john@example.com"

    Args:
        sender_str: Sender string

    Returns:
        Email address or original string
    """
    if not isinstance(sender_str, str):
        return "unknown@unknown.com"

    # Try to extract email from angle brackets
    match = re.search(r'<([\w\.-]+@[\w\.-]+\.\w+)>', sender_str)
    if match:
        return match.group(1)

    # Try to find email pattern in string
    match = re.search(r'([\w\.-]+@[\w\.-]+\.\w+)', sender_str)
    if match:
        return match.group(1)

    # Return as is or placeholder
    return sender_str if '@' in sender_str else "unknown@unknown.com"


def load_and_explore_dataset(file_path):
    """
    Load dataset and print exploration info.

    Args:
        file_path: Path to CSV file

    Returns:
        DataFrame
    """
    print(f"Loading dataset from: {file_path}")
    print(f"File size: {os.path.getsize(file_path) / (1024*1024):.2f} MB")
    print("")

    # Try different encodings
    for encoding in ['utf-8', 'latin-1', 'iso-8859-1']:
        try:
            df = pd.read_csv(file_path, encoding=encoding)
            print(f"✓ Successfully loaded with encoding: {encoding}")
            break
        except Exception as e:
            continue
    else:
        raise ValueError("Could not load CSV with any common encoding")

    print("")
    print("="*60)
    print("DATASET EXPLORATION")
    print("="*60)

    # Dataset info
    print(f"\nTotal rows: {len(df)}")
    print(f"Total columns: {len(df.columns)}")

    # Column names
    print(f"\nColumn Names: {list(df.columns)}")

    # Show first 5 rows
    print("\n" + "="*60)
    print("FIRST 5 ROWS")
    print("="*60)
    print(df.head().to_string())

    # Detect label column
    label_col = detect_label_column(df)
    if label_col:
        print("\n" + "="*60)
        print("CLASS DISTRIBUTION")
        print("="*60)
        print(f"\nLabel column detected: '{label_col}'")
        print("\nValue counts:")
        print(df[label_col].value_counts())
        print("\nLabel distribution:")
        dist = df[label_col].value_counts(normalize=True) * 100
        for value, pct in dist.items():
            print(f"  {value}: {pct:.2f}%")
    else:
        print("\n⚠ Warning: Could not detect label column")

    # Check for missing values
    print("\n" + "="*60)
    print("MISSING VALUES")
    print("="*60)
    missing = df.isnull().sum()
    missing_pct = (missing / len(df)) * 100
    missing_df = pd.DataFrame({
        'Column': missing.index,
        'Missing': missing.values,
        'Percentage': missing_pct.values
    })
    print(missing_df[missing_df['Missing'] > 0].to_string(index=False))

    if missing.sum() == 0:
        print("✓ No missing values")

    return df


def convert_to_standard_format(df):
    """
    Convert dataset to standard format: text, sender, subject, label.

    Args:
        df: Input DataFrame

    Returns:
        DataFrame with standard columns
    """
    print("\n" + "="*60)
    print("CONVERTING TO STANDARD FORMAT")
    print("="*60)

    result = pd.DataFrame()

    # 1. TEXT (email body)
    text_cols = ['body', 'text', 'message', 'content', 'email', 'email_body']
    text_col = None
    for col in df.columns:
        if col.lower() in text_cols:
            text_col = col
            break

    if text_col:
        print(f"✓ Mapping '{text_col}' -> 'text'")
        result['text'] = df[text_col]
    else:
        print("⚠ No text/body column found, using empty strings")
        result['text'] = ""

    # 2. SENDER
    sender_cols = ['sender', 'from', 'from_address', 'email_from']
    sender_col = None
    for col in df.columns:
        if col.lower() in sender_cols:
            sender_col = col
            break

    if sender_col:
        print(f"✓ Mapping '{sender_col}' -> 'sender'")
        result['sender'] = df[sender_col].apply(extract_email_address)
    else:
        print("⚠ No sender column found, creating placeholder")
        result['sender'] = "unknown@unknown.com"

    # 3. SUBJECT
    subject_cols = ['subject', 'title', 'subject_line']
    subject_col = None
    for col in df.columns:
        if col.lower() in subject_cols:
            subject_col = col
            break

    if subject_col:
        print(f"✓ Mapping '{subject_col}' -> 'subject'")
        result['subject'] = df[subject_col]
    else:
        print("⚠ No subject column found, extracting from text or creating placeholder")
        # Try to extract first line as subject
        if text_col:
            result['subject'] = df[text_col].str.split('\n').str[0].str[:100]
        else:
            result['subject'] = "No subject"

    # 4. LABEL
    label_col = detect_label_column(df)
    if label_col:
        print(f"✓ Mapping '{label_col}' -> 'label'")
        result['label'] = normalize_labels(df[label_col])
    else:
        raise ValueError("Could not detect label column. Please specify manually.")

    return result


def clean_dataset(df):
    """
    Clean dataset: remove nulls, duplicates, normalize data types.

    Args:
        df: DataFrame to clean

    Returns:
        Cleaned DataFrame
    """
    print("\n" + "="*60)
    print("CLEANING DATASET")
    print("="*60)

    initial_count = len(df)
    print(f"\nInitial row count: {initial_count}")

    # 1. Remove rows with missing text
    before_null = len(df)
    df = df[df['text'].notna()]
    df = df[df['text'].astype(str).str.strip() != '']
    print(f"✓ Removed {before_null - len(df)} rows with missing/empty text")

    # 2. Fill missing sender/subject
    df['sender'] = df['sender'].fillna('unknown@unknown.com')
    df['subject'] = df['subject'].fillna('No subject')

    # 3. Ensure text is string
    df['text'] = df['text'].astype(str)
    df['sender'] = df['sender'].astype(str)
    df['subject'] = df['subject'].astype(str)
    df['label'] = df['label'].astype(int)
    print("✓ Normalized data types (text: str, label: int)")

    # 4. Remove duplicates based on text
    before_dup = len(df)
    df = df.drop_duplicates(subset=['text'], keep='first')
    print(f"✓ Removed {before_dup - len(df)} duplicate emails")

    # 5. Validate labels are 0 or 1
    invalid_labels = df[~df['label'].isin([0, 1])]
    if len(invalid_labels) > 0:
        print(f"⚠ Found {len(invalid_labels)} rows with invalid labels, removing...")
        df = df[df['label'].isin([0, 1])]

    final_count = len(df)
    print(f"\nFinal row count: {final_count}")
    print(f"Total rows removed: {initial_count - final_count} ({(initial_count - final_count)/initial_count*100:.2f}%)")

    # Show final class distribution
    print("\n" + "="*60)
    print("FINAL CLASS DISTRIBUTION")
    print("="*60)
    print("\nLabel counts:")
    print(df['label'].value_counts().sort_index())
    print("\nLabel distribution:")
    print(f"  Legitimate (0): {sum(df['label'] == 0)} ({sum(df['label'] == 0)/len(df)*100:.2f}%)")
    print(f"  Phishing (1):   {sum(df['label'] == 1)} ({sum(df['label'] == 1)/len(df)*100:.2f}%)")

    return df


def save_dataset(df, output_path='../data/cleaned_emails.csv'):
    """
    Save cleaned dataset to CSV.

    Args:
        df: DataFrame to save
        output_path: Output file path
    """
    print("\n" + "="*60)
    print("SAVING CLEANED DATASET")
    print("="*60)

    # Ensure output directory exists
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    # Save to CSV
    df.to_csv(output_path, index=False, encoding='utf-8')

    file_size = os.path.getsize(output_path) / (1024*1024)
    print(f"✓ Saved to: {output_path}")
    print(f"✓ File size: {file_size:.2f} MB")
    print(f"✓ Total rows: {len(df)}")
    print(f"✓ Columns: {list(df.columns)}")

    # Show sample of saved data
    print("\n" + "="*60)
    print("SAMPLE OF CLEANED DATASET (First 3 rows)")
    print("="*60)
    sample = df.head(3)
    for idx, row in sample.iterrows():
        print(f"\nRow {idx + 1}:")
        print(f"  Text (first 100 chars): {row['text'][:100]}...")
        print(f"  Sender: {row['sender']}")
        print(f"  Subject: {row['subject'][:80]}")
        print(f"  Label: {row['label']} ({'Phishing' if row['label'] == 1 else 'Legitimate'})")


def main():
    """Main execution function."""
    print("="*60)
    print("EMAIL DATASET PREPARATION")
    print("="*60)
    print("")

    # Step 1: Find dataset
    data_dir = '../data'
    dataset_path = find_dataset(data_dir)

    if not dataset_path:
        print(f"❌ Error: No CSV files found in {data_dir}")
        print("Please ensure your dataset is in the data/ directory")
        return

    # Step 2: Load and explore
    df = load_and_explore_dataset(dataset_path)

    # Step 3: Convert to standard format
    df_standard = convert_to_standard_format(df)

    # Step 4: Clean dataset
    df_clean = clean_dataset(df_standard)

    # Step 5: Save
    output_path = os.path.join(data_dir, 'cleaned_emails.csv')
    save_dataset(df_clean, output_path)

    print("\n" + "="*60)
    print("✅ DATASET PREPARATION COMPLETE!")
    print("="*60)
    print("\nYou can now train your model with:")
    print("  python email_ml_model.py ../data/cleaned_emails.csv")


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
        print("\nPlease check the error above and try again.")
