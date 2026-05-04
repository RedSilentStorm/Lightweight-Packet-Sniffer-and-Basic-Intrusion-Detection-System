#!/usr/bin/env python3
"""
Cross-validation for V3 supervised model using day-aware stratified splits.
Ensures no data leakage from same day/source between train and validation.
Uses numpy for efficient data loading.
"""

import json
import numpy as np
from collections import defaultdict
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import precision_score, recall_score, f1_score, roc_auc_score, confusion_matrix
import pickle
import sys

# Constants
TRAIN_CSV = 'data/processed/train.csv'
TEST_CSV = 'data/processed/test.csv'
CV_REPORT = 'reports/cic_ai_report_v3_cv.json'

def load_data_with_source_numpy(csv_path, max_rows=None):
    """Load CSV using numpy for speed, extract source_file for day-aware splitting."""
    print(f"[*] Loading {csv_path} with numpy...", file=sys.stderr)
    
    # Read with numpy to get column names
    data = np.genfromtxt(csv_path, delimiter=',', dtype=str, max_rows=1)
    feature_names = [col.strip() for col in data if col.strip() not in ['label', 'label_bin', 'source_file']]
    
    # Find indices of label and source columns
    all_cols = data
    label_idx = None
    source_idx = None
    feature_indices = []
    
    for i, col in enumerate(all_cols):
        col = col.strip()
        if col == 'label_bin' or col == 'label':
            label_idx = i
        elif col == 'source_file':
            source_idx = i
        elif col not in ['label', 'label_bin', 'source_file']:
            feature_indices.append(i)
    
    print(f"    Header parsed. Features: {len(feature_indices)}, label_idx: {label_idx}, source_idx: {source_idx}", file=sys.stderr)
    
    # Load data more efficiently with skiprows
    if max_rows:
        data_rows = np.genfromtxt(csv_path, delimiter=',', dtype=str, skip_header=1, max_rows=max_rows)
    else:
        data_rows = np.genfromtxt(csv_path, delimiter=',', dtype=str, skip_header=1)
    
    n_rows = len(data_rows)
    print(f"    Loaded {n_rows:,} rows", file=sys.stderr)
    
    # Extract features, labels, sources
    features = []
    labels = []
    sources = []
    
    for i, row in enumerate(data_rows):
        if (i + 1) % 500000 == 0:
            print(f"    Processed {i + 1:,} rows", file=sys.stderr)
        
        # Extract features
        feature_vals = []
        for idx in feature_indices:
            try:
                val = float(row[idx])
            except (ValueError, IndexError):
                val = 0.0
            feature_vals.append(val)
        
        # Extract label
        try:
            label = int(float(row[label_idx])) if label_idx is not None else 0
        except (ValueError, IndexError):
            label = 0
        
        # Extract source
        source = row[source_idx].strip() if source_idx is not None and source_idx < len(row) else 'unknown'
        
        features.append(feature_vals)
        labels.append(label)
        sources.append(source)
    
    print(f"    Total: {len(features):,} rows processed", file=sys.stderr)
    return features, labels, sources, feature_names

def get_day_aware_splits(labels, sources, n_splits=5):
    """
    Create day-aware k-fold splits ensuring same day/source not in train+val.
    Returns list of (train_indices, val_indices) tuples.
    """
    print(f"[*] Creating day-aware {n_splits}-fold splits...", file=sys.stderr)
    
    # Group indices by source (day)
    source_to_indices = defaultdict(list)
    for i, source in enumerate(sources):
        source_to_indices[source].append(i)
    
    unique_sources = sorted(source_to_indices.keys())
    n_sources = len(unique_sources)
    print(f"    Found {n_sources} unique days/sources", file=sys.stderr)
    
    # Distribute sources across folds (stratified)
    folds = [[] for _ in range(n_splits)]
    attack_counts = [0] * n_splits
    benign_counts = [0] * n_splits
    
    # Sort sources by attack ratio to balance folds
    source_stats = []
    for source in unique_sources:
        indices = source_to_indices[source]
        attack_cnt = sum(1 for i in indices if labels[i] == 1)
        benign_cnt = len(indices) - attack_cnt
        source_stats.append((source, indices, attack_cnt, benign_cnt))
    
    # Assign sources to folds (round-robin, balanced)
    for source, indices, attack_cnt, benign_cnt in sorted(source_stats, key=lambda x: x[2], reverse=True):
        best_fold = min(range(n_splits), key=lambda f: attack_counts[f])
        folds[best_fold].extend(indices)
        attack_counts[best_fold] += attack_cnt
        benign_counts[best_fold] += benign_cnt
    
    # Create train/val splits
    splits = []
    for val_fold_idx in range(n_splits):
        val_indices = folds[val_fold_idx]
        train_indices = []
        for fold_idx in range(n_splits):
            if fold_idx != val_fold_idx:
                train_indices.extend(folds[fold_idx])
        
        attack_val = sum(1 for i in val_indices if labels[i] == 1)
        benign_val = len(val_indices) - attack_val
        attack_train = sum(1 for i in train_indices if labels[i] == 1)
        benign_train = len(train_indices) - attack_train
        
        print(f"    Fold {val_fold_idx + 1}: train={len(train_indices):,} (A:{attack_train:,}/B:{benign_train:,}), val={len(val_indices):,} (A:{attack_val:,}/B:{benign_val:,})", file=sys.stderr)
        splits.append((train_indices, val_indices))
    
    return splits

def train_and_evaluate_fold(features, labels, train_indices, val_indices, fold_num, max_depth=8, n_estimators=200, min_recall=0.40):
    """Train RF on fold and find optimal threshold on validation set."""
    print(f"[*] Fold {fold_num}: Training RandomForest...", file=sys.stderr)
    
    X_train = [features[i] for i in train_indices]
    y_train = [labels[i] for i in train_indices]
    X_val = [features[i] for i in val_indices]
    y_val = [labels[i] for i in val_indices]
    
    model = RandomForestClassifier(
        n_estimators=n_estimators,
        max_depth=max_depth,
        class_weight='balanced',
        random_state=42,
        n_jobs=-1,
        verbose=0
    )
    model.fit(X_train, y_train)
    
    # Get validation probabilities
    val_probs = model.predict_proba(X_val)[:, 1]
    
    # Find optimal threshold (precision-first with min_recall constraint)
    print(f"[*] Fold {fold_num}: Finding optimal threshold...", file=sys.stderr)
    best_threshold = 0.5
    best_metrics = {'precision': 0, 'recall': 0, 'f1': 0, 'auc': 0, 'tp': 0, 'fp': 0, 'fn': 0, 'tn': 0}
    
    for threshold in sorted(set(val_probs)):
        val_pred = [1 if p >= threshold else 0 for p in val_probs]
        
        tn, fp, fn, tp = confusion_matrix(y_val, val_pred, labels=[0, 1]).ravel()
        
        if tp + fp == 0:
            continue
        
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0
        
        # Precision-first: if recall >= min_recall, maximize precision
        if recall >= min_recall:
            if precision > best_metrics['precision']:
                best_threshold = threshold
                best_metrics = {
                    'precision': precision,
                    'recall': recall,
                    'f1': 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0,
                    'auc': roc_auc_score(y_val, val_probs),
                    'tp': tp,
                    'fp': fp,
                    'fn': fn,
                    'tn': tn,
                }
    
    # Fallback if no threshold meets min_recall: use best F-beta(0.5)
    if best_metrics['recall'] < min_recall - 0.01:
        print(f"    Warning: min_recall not met, using best F-beta(0.5)", file=sys.stderr)
        best_f05 = 0
        for threshold in sorted(set(val_probs)):
            val_pred = [1 if p >= threshold else 0 for p in val_probs]
            tn, fp, fn, tp = confusion_matrix(y_val, val_pred, labels=[0, 1]).ravel()
            
            if tp + fp == 0:
                continue
            
            precision = tp / (tp + fp) if (tp + fp) > 0 else 0
            recall = tp / (tp + fn) if (tp + fn) > 0 else 0
            f05 = (1.25 * precision * recall) / (0.25 * precision + recall) if (precision + recall) > 0 else 0
            
            if f05 > best_f05:
                best_f05 = f05
                best_threshold = threshold
                best_metrics = {
                    'precision': precision,
                    'recall': recall,
                    'f1': 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0,
                    'auc': roc_auc_score(y_val, val_probs),
                    'tp': tp,
                    'fp': fp,
                    'fn': fn,
                    'tn': tn,
                }
    
    return model, best_threshold, best_metrics

def evaluate_on_test(model, threshold, features, labels):
    """Evaluate trained model on full test set."""
    X_test = features
    y_test = labels
    
    test_probs = model.predict_proba(X_test)[:, 1]
    test_pred = [1 if p >= threshold else 0 for p in test_probs]
    
    tn, fp, fn, tp = confusion_matrix(y_test, test_pred, labels=[0, 1]).ravel()
    
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
    auc = roc_auc_score(y_test, test_probs)
    
    return {
        'precision': precision,
        'recall': recall,
        'f1': f1,
        'auc': auc,
        'tp': tp,
        'fp': fp,
        'fn': fn,
        'tn': tn,
    }

def main():
    print("[*] V3 Cross-Validation: Day-Aware Stratified K-Fold", file=sys.stderr)
    
    # Load training data
    X_train, y_train, sources_train, feature_names = load_data_with_source_numpy(TRAIN_CSV)
    
    # Load test data
    X_test, y_test, sources_test, _ = load_data_with_source_numpy(TEST_CSV)
    
    # Create day-aware splits on training data
    splits = get_day_aware_splits(y_train, sources_train, n_splits=5)
    
    # Cross-validation results
    cv_results = []
    all_test_metrics = []
    
    for fold_num, (train_indices, val_indices) in enumerate(splits, 1):
        print(f"\n[*] ========== FOLD {fold_num}/5 ==========", file=sys.stderr)
        
        # Train and evaluate on this fold
        model, threshold, val_metrics = train_and_evaluate_fold(
            X_train, y_train, train_indices, val_indices,
            fold_num=fold_num,
            max_depth=8,
            n_estimators=200,
            min_recall=0.40
        )
        
        print(f"[*] Fold {fold_num}: Validation metrics:", file=sys.stderr)
        print(f"    Precision: {val_metrics['precision']:.4f}, Recall: {val_metrics['recall']:.4f}, F1: {val_metrics['f1']:.4f}, AUC: {val_metrics['auc']:.4f}", file=sys.stderr)
        print(f"    Threshold: {threshold:.4f}, TP: {val_metrics['tp']}, FP: {val_metrics['fp']}, FN: {val_metrics['fn']}, TN: {val_metrics['tn']}", file=sys.stderr)
        
        # Evaluate on full test set
        test_metrics = evaluate_on_test(model, threshold, X_test, y_test)
        
        print(f"[*] Fold {fold_num}: Test set metrics:", file=sys.stderr)
        print(f"    Precision: {test_metrics['precision']:.4f}, Recall: {test_metrics['recall']:.4f}, F1: {test_metrics['f1']:.4f}, AUC: {test_metrics['auc']:.4f}", file=sys.stderr)
        print(f"    TP: {test_metrics['tp']}, FP: {test_metrics['fp']}, FN: {test_metrics['fn']}, TN: {test_metrics['tn']}", file=sys.stderr)
        
        cv_results.append({
            'fold': fold_num,
            'threshold': float(threshold),
            'validation_metrics': {
                'precision': float(val_metrics['precision']),
                'recall': float(val_metrics['recall']),
                'f1': float(val_metrics['f1']),
                'auc': float(val_metrics['auc']),
                'tp': int(val_metrics['tp']),
                'fp': int(val_metrics['fp']),
                'fn': int(val_metrics['fn']),
                'tn': int(val_metrics['tn']),
            },
            'test_metrics': {
                'precision': float(test_metrics['precision']),
                'recall': float(test_metrics['recall']),
                'f1': float(test_metrics['f1']),
                'auc': float(test_metrics['auc']),
                'tp': int(test_metrics['tp']),
                'fp': int(test_metrics['fp']),
                'fn': int(test_metrics['fn']),
                'tn': int(test_metrics['tn']),
            }
        })
        
        all_test_metrics.append(test_metrics)
    
    # Compute cross-validation statistics
    print("\n[*] ========== CROSS-VALIDATION SUMMARY ==========", file=sys.stderr)
    
    avg_val_p = sum(r['validation_metrics']['precision'] for r in cv_results) / len(cv_results)
    avg_val_r = sum(r['validation_metrics']['recall'] for r in cv_results) / len(cv_results)
    avg_val_f1 = sum(r['validation_metrics']['f1'] for r in cv_results) / len(cv_results)
    avg_val_auc = sum(r['validation_metrics']['auc'] for r in cv_results) / len(cv_results)
    
    avg_test_p = sum(r['precision'] for r in all_test_metrics) / len(all_test_metrics)
    avg_test_r = sum(r['recall'] for r in all_test_metrics) / len(all_test_metrics)
    avg_test_f1 = sum(r['f1'] for r in all_test_metrics) / len(all_test_metrics)
    avg_test_auc = sum(r['auc'] for r in all_test_metrics) / len(all_test_metrics)
    
    std_test_p = (sum((r['precision'] - avg_test_p) ** 2 for r in all_test_metrics) / len(all_test_metrics)) ** 0.5
    std_test_r = (sum((r['recall'] - avg_test_r) ** 2 for r in all_test_metrics) / len(all_test_metrics)) ** 0.5
    std_test_f1 = (sum((r['f1'] - avg_test_f1) ** 2 for r in all_test_metrics) / len(all_test_metrics)) ** 0.5
    std_test_auc = (sum((r['auc'] - avg_test_auc) ** 2 for r in all_test_metrics) / len(all_test_metrics)) ** 0.5
    
    print(f"Validation (avg across folds):", file=sys.stderr)
    print(f"  Precision: {avg_val_p:.4f}, Recall: {avg_val_r:.4f}, F1: {avg_val_f1:.4f}, AUC: {avg_val_auc:.4f}", file=sys.stderr)
    
    print(f"\nTest Set (avg ± std across folds):", file=sys.stderr)
    print(f"  Precision: {avg_test_p:.4f} ± {std_test_p:.4f}", file=sys.stderr)
    print(f"  Recall:    {avg_test_r:.4f} ± {std_test_r:.4f}", file=sys.stderr)
    print(f"  F1-Score:  {avg_test_f1:.4f} ± {std_test_f1:.4f}", file=sys.stderr)
    print(f"  ROC-AUC:   {avg_test_auc:.4f} ± {std_test_auc:.4f}", file=sys.stderr)
    
    # Write report
    report = {
        'method': 'day-aware-stratified-k-fold',
        'n_splits': 5,
        'model_params': {
            'max_depth': 8,
            'n_estimators': 200,
            'class_weight': 'balanced',
        },
        'cv_results': cv_results,
        'summary': {
            'validation_avg': {
                'precision': float(avg_val_p),
                'recall': float(avg_val_r),
                'f1': float(avg_val_f1),
                'auc': float(avg_val_auc),
            },
            'test_avg': {
                'precision': float(avg_test_p),
                'recall': float(avg_test_r),
                'f1': float(avg_test_f1),
                'auc': float(avg_test_auc),
            },
            'test_std': {
                'precision': float(std_test_p),
                'recall': float(std_test_r),
                'f1': float(std_test_f1),
                'auc': float(std_test_auc),
            },
        },
    }
    
    with open(CV_REPORT, 'w') as f:
        json.dump(report, f, indent=2)
    
    print(f"\n[+] Cross-validation report saved to {CV_REPORT}", file=sys.stderr)

if __name__ == '__main__':
    main()
