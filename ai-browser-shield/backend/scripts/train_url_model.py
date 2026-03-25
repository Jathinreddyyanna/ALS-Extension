#!/usr/bin/env python3
"""
URL Phishing Detection Model Training Pipeline (BALANCED)
Trains a RandomForest classifier on a balanced dataset from malicious_phish.csv

Dataset Handling:
- Loads 651K URLs from malicious_phish.csv
- Converts labels: benign=0, phishing/malware/defacement=1
- Balances dataset: samples 120k benign + 120k malicious = 240k total
- Trains RandomForest on balanced data
- Evaluates with accuracy, precision, recall, F1-score, confusion matrix
- Saves: url_phishing_model.pkl, model_metadata.json

Expected Performance (on balanced data):
- Accuracy: ~97%+
- Precision: ~96%+ (few false alarms)
- Recall: ~97%+ (catches most phishing)
- F1-score: ~96%+
"""

import pandas as pd  # type: ignore
import numpy as np  # type: ignore
import pickle
import json
import sys
from urllib.parse import urlparse
from sklearn.ensemble import RandomForestClassifier  # type: ignore
from sklearn.model_selection import train_test_split  # type: ignore
from sklearn.metrics import (  # type: ignore
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, classification_report, roc_auc_score
)
import warnings
warnings.filterwarnings('ignore')


# ═══════════════════════════════════════════════════════════════════════════
# FEATURE EXTRACTION
# ═══════════════════════════════════════════════════════════════════════════

class URLFeatureExtractor:
    """Extract features from URLs for classification"""
    
    SUSPICIOUS_TLDS = {'.xyz', '.tk', '.top', '.gq', '.ml', '.ga', '.cf', '.ru', '.ir', '.click'}
    SHORTENER_DOMAINS = {'bit.ly', 'tinyurl.com', 'goo.gl', 'ow.ly', 'short.link', 'is.gd'}
    
    @staticmethod
    def extract_features(url: str) -> dict:
        """Extract 8 core features from URL"""
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            
            # Feature 1: URL length
            url_length = len(url)
            
            # Feature 2: Number of dots
            num_dots = url.count('.')
            
            # Feature 3: Number of hyphens
            num_hyphens = url.count('-')
            
            # Feature 4: Number of slashes
            num_slashes = url.count('/')
            
            # Feature 5: IP address presence
            has_ip = 1 if URLFeatureExtractor._is_ip_address(domain) else 0
            
            # Feature 6: Suspicious TLD
            has_suspicious_tld = 1 if URLFeatureExtractor._has_suspicious_tld(domain) else 0
            
            # Feature 7: HTTPS usage
            uses_https = 1 if parsed.scheme == 'https' else 0
            
            # Feature 8: Number of subdomains
            num_subdomains = domain.count('.') if domain else 0
            
            return {
                'url_length': url_length,
                'num_dots': num_dots,
                'num_hyphens': num_hyphens,
                'num_slashes': num_slashes,
                'has_ip': has_ip,
                'has_suspicious_tld': has_suspicious_tld,
                'uses_https': uses_https,
                'num_subdomains': num_subdomains,
            }
        except Exception as e:
            print(f"[!] Error extracting features from {url}: {e}")
            return {k: 0 for k in ['url_length', 'num_dots', 'num_hyphens', 'num_slashes', 
                                   'has_ip', 'has_suspicious_tld', 'uses_https', 'num_subdomains']}
    
    @staticmethod
    def _is_ip_address(domain: str) -> bool:
        """Check if domain is an IP address"""
        import re
        pattern = r'^\d{1,3}(\.\d{1,3}){3}$'
        return bool(re.match(pattern, domain))
    
    @staticmethod
    def _has_suspicious_tld(domain: str) -> bool:
        """Check for suspicious TLDs"""
        return any(domain.endswith(tld) for tld in URLFeatureExtractor.SUSPICIOUS_TLDS)


# ═══════════════════════════════════════════════════════════════════════════
# TRAINING PIPELINE
# ═══════════════════════════════════════════════════════════════════════════

def train_model(dataset_path: str = None, 
                output_dir: str = None):
    """Train RandomForest classifier on URL phishing dataset"""
    import os
    
    # Resolve paths relative to this script's directory
    script_dir = os.path.dirname(os.path.abspath(__file__))
    backend_dir = os.path.dirname(script_dir)
    
    if dataset_path is None:
        dataset_path = os.path.join(backend_dir, 'data', 'malicious_phish.csv')
    if output_dir is None:
        output_dir = os.path.join(backend_dir, 'models')
    
    print("=" * 70)
    print("URL Phishing Detection Model Training (BALANCED DATASET)")
    print("=" * 70)
    
    # ─────────────────────────────────────────────────────────────────────
    # 1. LOAD DATASET
    # ─────────────────────────────────────────────────────────────────────
    print(f"\n[*] Loading dataset from: {dataset_path}")
    try:
        df = pd.read_csv(dataset_path)
    except FileNotFoundError:
        print(f"[!] Dataset not found at {dataset_path}")
        print("[!] Please ensure malicious_phish.csv exists in backend/data/")
        sys.exit(1)
    
    print(f"[✓] Loaded {len(df):,} URLs")
    print(f"[✓] Columns: {list(df.columns)}")
    print(f"\n[INITIAL] Class distribution (IMBALANCED):")
    for category, count in df['type'].value_counts().items():
        print(f"  {category:15} {count:>8,} ({count/len(df)*100:>5.1f}%)")
    
    # ─────────────────────────────────────────────────────────────────────
    # 2. LABEL ENCODING & BALANCING
    # ─────────────────────────────────────────────────────────────────────
    print("\n[*] Encoding labels (benign=0, phishing/malware/defacement=1)...")
    # Binary classification: benign=0, suspicious(phishing/malware/defacement)=1
    df['label'] = (df['type'] != 'benign').astype(int)
    
    # Separate benign and malicious
    benign_urls = df[df['label'] == 0]
    malicious_urls = df[df['label'] == 1]
    
    print(f"[✓] Benign URLs: {len(benign_urls):,}")
    print(f"[✓] Malicious URLs: {len(malicious_urls):,}")
    
    # ─────────────────────────────────────────────────────────────────────
    # 3. BALANCE DATASET
    # ─────────────────────────────────────────────────────────────────────
    print("\n[*] Balancing dataset (random sampling)...")
    SAMPLE_SIZE = 120000  # Sample 120k URLs per class
    
    # Sample benign URLs
    if len(benign_urls) > SAMPLE_SIZE:
        benign_sampled = benign_urls.sample(n=SAMPLE_SIZE, random_state=42)
        print(f"[✓] Sampled {len(benign_sampled):,} benign URLs (from {len(benign_urls):,})")
    else:
        benign_sampled = benign_urls
        print(f"[!] Only {len(benign_urls):,} benign URLs available (wanted {SAMPLE_SIZE:,})")
    
    # Sample malicious URLs
    if len(malicious_urls) > SAMPLE_SIZE:
        malicious_sampled = malicious_urls.sample(n=SAMPLE_SIZE, random_state=42)
        print(f"[✓] Sampled {len(malicious_sampled):,} malicious URLs (from {len(malicious_urls):,})")
    else:
        malicious_sampled = malicious_urls
        print(f"[!] Only {len(malicious_urls):,} malicious URLs available (wanted {SAMPLE_SIZE:,})")
    
    # Combine balanced dataset
    df_balanced = pd.concat([benign_sampled, malicious_sampled], ignore_index=True)
    df_balanced = df_balanced.sample(frac=1, random_state=42).reset_index(drop=True)
    
    total_balanced = len(df_balanced)
    benign_balanced = len(benign_sampled)
    malicious_balanced = len(malicious_sampled)
    
    print(f"\n[BALANCED] Final dataset composition:")
    print(f"  Benign:     {benign_balanced:>8,} ({benign_balanced/total_balanced*100:>5.1f}%)")
    print(f"  Malicious:  {malicious_balanced:>8,} ({malicious_balanced/total_balanced*100:>5.1f}%)")
    print(f"  Total:      {total_balanced:>8,}")
    
    # ─────────────────────────────────────────────────────────────────────
    # 3. FEATURE EXTRACTION
    # ─────────────────────────────────────────────────────────────────────
    print("\n[*] Extracting features from balanced dataset...")
    extractor = URLFeatureExtractor()
    
    features_list = []
    feature_names = ['url_length', 'num_dots', 'num_hyphens', 'num_slashes', 
                     'has_ip', 'has_suspicious_tld', 'uses_https', 'num_subdomains']
    
    for idx, url in enumerate(df_balanced['url']):
        if idx % 50000 == 0 and idx > 0:
            print(f"  → Processed {idx:,}/{len(df_balanced):,} URLs")
        features = extractor.extract_features(url)
        features_list.append([features[fname] for fname in feature_names])
    
    X = np.array(features_list)
    y = df_balanced['label'].values
    
    print(f"[✓] Feature matrix shape: {X.shape}")
    print(f"[✓] Features: {feature_names}")
    
    # ─────────────────────────────────────────────────────────────────────
    # 4. TRAIN/TEST SPLIT
    # ─────────────────────────────────────────────────────────────────────
    print("\n[*] Splitting balanced dataset (80% train, 20% test)...")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    print(f"[✓] Train set: {X_train.shape[0]:,} URLs")
    print(f"[✓] Test set: {X_test.shape[0]:,} URLs")
    print(f"[✓] Train class distribution: Benign={sum(y_train==0):,}, Malicious={sum(y_train==1):,}")
    print(f"[✓] Test class distribution: Benign={sum(y_test==0):,}, Malicious={sum(y_test==1):,}")
    
    # ─────────────────────────────────────────────────────────────────────
    # 5. TRAIN RANDOM FOREST
    # ─────────────────────────────────────────────────────────────────────
    print("\n[*] Training RandomForestClassifier on balanced data...")
    print("    Parameters:")
    print("    - n_estimators: 100")
    print("    - max_depth: 20")
    print("    - min_samples_split: 5")
    print("    - min_samples_leaf: 2")
    print("    - class_weight: balanced (handles remaining imbalance)")
    
    model = RandomForestClassifier(
        n_estimators=100,
        max_depth=20,
        min_samples_split=5,
        min_samples_leaf=2,
        random_state=42,
        n_jobs=-1,
        verbose=0,
        class_weight='balanced'  # Give weight to both classes equally
    )
    
    model.fit(X_train, y_train)
    print("[✓] Model training complete!")
    
    # ─────────────────────────────────────────────────────────────────────
    # 6. EVALUATION
    # ─────────────────────────────────────────────────────────────────────
    print("\n" + "=" * 70)
    print("MODEL EVALUATION (MAIN METRICS)")
    print("=" * 70)
    
    # Predictions
    y_train_pred = model.predict(X_train)
    y_test_pred = model.predict(X_test)
    y_test_proba = model.predict_proba(X_test)[:, 1]
    
    # Calculate all metrics
    train_accuracy = accuracy_score(y_train, y_train_pred)
    test_accuracy = accuracy_score(y_test, y_test_pred)
    precision = precision_score(y_test, y_test_pred)
    recall = recall_score(y_test, y_test_pred)
    f1 = f1_score(y_test, y_test_pred)
    roc_auc = roc_auc_score(y_test, y_test_proba)
    
    print(f"\n[ACCURACY]")
    print(f"  Train: {train_accuracy:.4f} ({train_accuracy*100:>5.1f}%)")
    print(f"  Test:  {test_accuracy:.4f} ({test_accuracy*100:>5.1f}%)")
    
    print(f"\n[⭐ KEY METRICS - CHECK THESE]")
    print(f"  Precision: {precision:.4f} ({precision*100:>5.1f}%) - False alarm rate")
    print(f"  Recall:    {recall:.4f} ({recall*100:>5.1f}%) - Detection rate")
    print(f"  F1-score:  {f1:.4f} ({f1*100:>5.1f}%) - Balanced performance")
    print(f"  ROC-AUC:   {roc_auc:.4f} ({roc_auc*100:>5.1f}%) - Discrimination ability")
    
    # Check if metrics meet target thresholds
    TARGET_PRECISION = 0.95
    TARGET_RECALL = 0.95
    TARGET_F1 = 0.95
    
    print(f"\n[THRESHOLD CHECK]")
    print(f"  Precision >= {TARGET_PRECISION}: {'✅ PASS' if precision >= TARGET_PRECISION else '❌ FAIL'}")
    print(f"  Recall >= {TARGET_RECALL}:    {'✅ PASS' if recall >= TARGET_RECALL else '❌ FAIL'}")
    print(f"  F1-score >= {TARGET_F1}:     {'✅ PASS' if f1 >= TARGET_F1 else '❌ FAIL'}")
    
    # Confusion Matrix
    tn, fp, fn, tp = confusion_matrix(y_test, y_test_pred).ravel()
    
    print(f"\n[CONFUSION MATRIX]")
    print(f"  True Negatives (TN):   {tn} (benign correctly identified)")
    print(f"  False Positives (FP):  {fp} (benign wrongly flagged) ⚠️ False alarm")
    print(f"  False Negatives (FN):  {fn} (malicious missed) 🚨 SECURITY RISK")
    print(f"  True Positives (TP):   {tp} (malicious caught)")
    
    # False Positive / False Negative Rates
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
    fnr = fn / (fn + tp) if (fn + tp) > 0 else 0
    
    print(f"\n[ERROR RATES]")
    print(f"  False Positive Rate: {fpr:.4f} ({int(fpr*100)}%) - User frustration")
    print(f"  False Negative Rate: {fnr:.4f} ({int(fnr*100)}%) - Security risk")
    
    # ROC-AUC
    auc = roc_auc_score(y_test, y_test_proba)
    print(f"\n[ROC-AUC Score] {auc:.4f} (higher is better, 1.0 is perfect)")
    
    # Classification Report
    print(f"\n[DETAILED REPORT]")
    print(classification_report(
        y_test, y_test_pred,
        target_names=['Benign', 'Malicious'],
        digits=4
    ))
    
    # ─────────────────────────────────────────────────────────────────────
    # 7. FEATURE IMPORTANCE
    # ─────────────────────────────────────────────────────────────────────
    print("\n" + "=" * 70)
    print("FEATURE IMPORTANCE (signals that matter most for detection)")
    print("=" * 70)
    
    importance_df = pd.DataFrame({
        'Feature': feature_names,
        'Importance': model.feature_importances_,
        'Importance %': (model.feature_importances_ * 100).round(2)
    }).sort_values('Importance', ascending=False)
    
    print("\n" + importance_df.to_string(index=False))
    
    # ─────────────────────────────────────────────────────────────────────
    # 8. SAVE MODEL & METADATA
    # ─────────────────────────────────────────────────────────────────────
    print("\n" + "=" * 70)
    print("SAVING MODEL & METADATA")
    print("=" * 70)
    
    import os
    os.makedirs(output_dir, exist_ok=True)
    
    # Save model
    model_path = os.path.join(output_dir, 'url_phishing_model.pkl')
    with open(model_path, 'wb') as f:
        pickle.dump(model, f)
    print(f"\n[✓] Model saved: {model_path}")
    
    # Save metadata
    metadata = {
        'model_type': 'RandomForestClassifier',
        'n_estimators': 100,
        'max_depth': 20,
        'feature_names': feature_names,
        'feature_importance': dict(zip(feature_names, model.feature_importances_.tolist())),
        'train_accuracy': float(train_accuracy),
        'test_accuracy': float(test_accuracy),
        'precision': float(precision),
        'recall': float(recall),
        'auc_score': float(auc),
        'false_positive_rate': float(fpr),
        'false_negative_rate': float(fnr),
        'f1_score': float(f1),
        'roc_auc': float(roc_auc),
        'confusion_matrix': {
            'true_negatives': int(tn),
            'false_positives': int(fp),
            'false_negatives': int(fn),
            'true_positives': int(tp),
        },
        'dataset_info': {
            'total_urls_loaded': len(df),
            'balanced_dataset_size': len(df_balanced),
            'benign_used': int(benign_balanced),
            'malicious_used': int(malicious_balanced),
            'sample_size_per_class': int(SAMPLE_SIZE),
        },
        'training_info': {
            'train_set_size': int(X_train.shape[0]),
            'test_set_size': int(X_test.shape[0]),
            'train_benign': int(sum(y_train==0)),
            'train_malicious': int(sum(y_train==1)),
            'test_benign': int(sum(y_test==0)),
            'test_malicious': int(sum(y_test==1)),
        },
    }
    
    metadata_path = os.path.join(output_dir, 'model_metadata.json')
    with open(metadata_path, 'w') as f:
        json.dump(metadata, f, indent=2)
    print(f"[✓] Metadata saved: {metadata_path}")
    
    # ─────────────────────────────────────────────────────────────────────
    # 9. SUMMARY
    # ─────────────────────────────────────────────────────────────────────
    print("\n" + "=" * 70)
    print("✅ TRAINING COMPLETE (BALANCED DATASET)")
    print("=" * 70)
    print(f"\n[📊 DATASET]")
    print(f"  • Original size: {len(df):,} URLs")
    print(f"  • Balanced size: {len(df_balanced):,} URLs (sampling 120k from each class)")
    print(f"  • Benign:   {int(benign_balanced):,} ({benign_balanced/total_balanced*100:.1f}%)")
    print(f"  • Malicious: {int(malicious_balanced):,} ({malicious_balanced/total_balanced*100:.1f}%)")
    
    print(f"\n[🎯 MODEL PERFORMANCE]")
    print(f"  • Accuracy: {test_accuracy*100:>6.2f}%")
    print(f"  • Precision: {precision*100:>6.2f}% (false alarm rate)")
    print(f"  • Recall:    {recall*100:>6.2f}% (detection rate)")
    print(f"  • F1-score:  {f1*100:>6.2f}% (balanced metric)")
    print(f"  • ROC-AUC:   {roc_auc*100:>6.2f}%")
    
    print(f"\n[⚠️ ERROR ANALYSIS]")
    print(f"  • False Positive Rate: {fpr*100:.2f}% (legitimate URLs wrongly flagged)")
    print(f"  • False Negative Rate: {fnr*100:.2f}% (malicious URLs missed)")
    print(f"  • Confusion Matrix: TN={tn}, FP={fp}, FN={fn}, TP={tp}")
    
    print(f"\n[⭐ TOP 3 IMPORTANT FEATURES]")
    for idx, (i, row) in enumerate(importance_df.head(3).iterrows(), 1):
        print(f"  {idx}. {row['Feature']:20} {row['Importance %']:>6.2f}%")
    
    print(f"\n[📁 FILES CREATED]")
    print(f"  - Model:    {model_path}")
    print(f"  - Metadata: {metadata_path}")
    print(f"\n✨ Ready for integration in extension/src/detection/urlScorer.ts")


if __name__ == '__main__':
    train_model()
