#!/usr/bin/env python3
"""
Fast cross-validation for V3 model using day-aware stratified splits.
Loads data efficiently and runs 3-fold CV to validate generalization.
"""

import json
import sys
from collections import defaultdict
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import confusion_matrix, roc_auc_score

# Constants
TRAIN_CSV = 'data/processed/train.csv'
TEST_CSV = 'data/processed/test.csv'
CV_REPORT = 'reports/cic_ai_report_v3_cv.json'

def quick_parse_csv(csv_path, max_rows=None):
    """Quick line-by-line CSV parsing to identify day groups and extract indices."""
    print(f"[*] Quick scan of {csv_path}...", file=sys.stderr)
    
    features = []
    labels = []
    sources = []
    feature_names = None
    
    row_count = 0
    with open(csv_path, 'r') as f:
        for line_idx, line in enumerate(f):
            if line_idx % 500000 == 0 and line_idx > 0:
                print(f"    Scanned {line_idx:,} lines", file=sys.stderr)
            
            if line_idx == 0:
                # Parse header
                header = [col.strip() for col in line.strip().split(',')]
                feature_names = [col for col in header if col not in ['label', 'label_bin', 'source_file']]
                label_idx = header.index('label_bin') if 'label_bin' in header else (header.index('label') if 'label' in header else -1)
                source_idx = header.index('source_file') if 'source_file' in header else -1
                feature_indices = [header.index(f) for f in feature_names if f in header]
                continue
            
            if max_rows and row_count >= max_rows:
                break
            
            # Parse data row
            cols = line.strip().split(',')
            
            # Extract features
            try:
                feature_vals = [float(cols[i]) if i < len(cols) else 0.0 for i in feature_indices]
            except:
                feature_vals = [0.0] * len(feature_indices)
            
            # Extract label
            try:
                label = int(float(cols[label_idx])) if label_idx >= 0 and label_idx < len(cols) else 0
            except:
                label = 0
            
            # Extract source
            source = cols[source_idx].strip() if source_idx >= 0 and source_idx < len(cols) else 'unknown'
            
            features.append(feature_vals)
            labels.append(label)
            sources.append(source)
            row_count += 1
    
    print(f"    Total: {len(features):,} rows", file=sys.stderr)
    return features, labels, sources, feature_names

def stratify_by_source(labels, sources, n_splits=3):
    """Create day-aware stratified splits ensuring source groups stay in one fold."""
    print(f"[*] Creating {n_splits}-fold stratified splits by day/source...", file=sys.stderr)
    
    # Group indices by source
    source_to_indices = defaultdict(list)
    for i, source in enumerate(sources):
        source_to_indices[source].append(i)
    
    unique_sources = sorted(source_to_indices.keys())
    print(f"    Found {len(unique_sources)} unique days/sources", file=sys.stderr)
    
    # Distribute sources across folds (minimize class imbalance)
    folds = [[] for _ in range(n_splits)]
    attack_counts = [0] * n_splits
    benign_counts = [0] * n_splits
    
    # Sort sources by attack ratio
    source_stats = []
    for source in unique_sources:
        indices = source_to_indices[source]
        attack_cnt = sum(1 for i in indices if labels[i] == 1)
        benign_cnt = len(indices) - attack_cnt
        source_stats.append((source, indices, attack_cnt, benign_cnt))
    
    # Assign to folds
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

def train_and_evaluate_fold(features, labels, train_indices, val_indices, fold_num, test_features, test_labels, max_depth=8, n_estimators=200, min_recall=0.40):
    """Train RF on fold and evaluate on both val and test."""
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
    
    # Find optimal threshold on validation set
    val_probs = model.predict_proba(X_val)[:, 1]
    best_threshold = 0.5
    best_val_metrics = {'precision': 0, 'recall': 0, 'f1': 0, 'auc': 0}
    
    print(f"[*] Fold {fold_num}: Finding optimal threshold on validation set...", file=sys.stderr)
    for threshold in sorted(set(val_probs))[::len(set(val_probs))//50 + 1]:  # Sample every 50th threshold
        val_pred = [1 if p >= threshold else 0 for p in val_probs]
        tn, fp, fn, tp = confusion_matrix(y_val, val_pred, labels=[0, 1]).ravel()
        
        if tp + fp == 0:
            continue
        
        precision = tp / (tp + fp)
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0
        
        if recall >= min_recall and precision > best_val_metrics['precision']:
            best_threshold = threshold
            best_val_metrics = {
                'precision': precision,
                'recall': recall,
                'f1': 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0,
                'auc': roc_auc_score(y_val, val_probs),
            }
    
    # Evaluate on test set with this threshold
    test_probs = model.predict_proba(test_features)[:, 1]
    test_pred = [1 if p >= best_threshold else 0 for p in test_probs]
    
    tn, fp, fn, tp = confusion_matrix(test_labels, test_pred, labels=[0, 1]).ravel()
    
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
    auc = roc_auc_score(test_labels, test_probs)
    
    test_metrics = {'precision': precision, 'recall': recall, 'f1': f1, 'auc': auc, 'tp': tp, 'fp': fp, 'fn': fn, 'tn': tn}
    
    print(f"[*] Fold {fold_num}: Val P={best_val_metrics['precision']:.4f} R={best_val_metrics['recall']:.4f}, Test P={precision:.4f} R={recall:.4f} F1={f1:.4f} AUC={auc:.4f}", file=sys.stderr)
    
    return {
        'fold': fold_num,
        'threshold': float(best_threshold),
        'validation_metrics': best_val_metrics,
        'test_metrics': {
            'precision': float(precision),
            'recall': float(recall),
            'f1': float(f1),
            'auc': float(auc),
            'tp': int(tp),
            'fp': int(fp),
            'fn': int(fn),
            'tn': int(tn),
        }
    }

def main():
    print("[*] V3 Cross-Validation: Day-Aware Stratified K-Fold (Fast)", file=sys.stderr)
    
    # Load training data
    X_train, y_train, sources_train, feature_names = quick_parse_csv(TRAIN_CSV)
    
    # Load test data
    X_test, y_test, sources_test, _ = quick_parse_csv(TEST_CSV)
    
    # Create day-aware stratified splits
    splits = stratify_by_source(y_train, sources_train, n_splits=3)
    
    # Cross-validation
    cv_results = []
    all_test_metrics = []
    
    for fold_num, (train_indices, val_indices) in enumerate(splits, 1):
        print(f"\n[*] ========== FOLD {fold_num}/3 ==========", file=sys.stderr)
        
        result = train_and_evaluate_fold(
            X_train, y_train, train_indices, val_indices,
            fold_num=fold_num,
            test_features=X_test,
            test_labels=y_test,
            max_depth=8,
            n_estimators=200,
            min_recall=0.40
        )
        
        cv_results.append(result)
        all_test_metrics.append(result['test_metrics'])
    
    # Summary statistics
    print("\n[*] ========== CROSS-VALIDATION SUMMARY ==========", file=sys.stderr)
    
    avg_test_p = sum(m['precision'] for m in all_test_metrics) / len(all_test_metrics)
    avg_test_r = sum(m['recall'] for m in all_test_metrics) / len(all_test_metrics)
    avg_test_f1 = sum(m['f1'] for m in all_test_metrics) / len(all_test_metrics)
    avg_test_auc = sum(m['auc'] for m in all_test_metrics) / len(all_test_metrics)
    
    std_test_p = (sum((m['precision'] - avg_test_p) ** 2 for m in all_test_metrics) / len(all_test_metrics)) ** 0.5
    std_test_r = (sum((m['recall'] - avg_test_r) ** 2 for m in all_test_metrics) / len(all_test_metrics)) ** 0.5
    std_test_f1 = (sum((m['f1'] - avg_test_f1) ** 2 for m in all_test_metrics) / len(all_test_metrics)) ** 0.5
    std_test_auc = (sum((m['auc'] - avg_test_auc) ** 2 for m in all_test_metrics) / len(all_test_metrics)) ** 0.5
    
    print(f"Test Set (avg ± std across folds):", file=sys.stderr)
    print(f"  Precision: {avg_test_p:.4f} ± {std_test_p:.4f}", file=sys.stderr)
    print(f"  Recall:    {avg_test_r:.4f} ± {std_test_r:.4f}", file=sys.stderr)
    print(f"  F1-Score:  {avg_test_f1:.4f} ± {std_test_f1:.4f}", file=sys.stderr)
    print(f"  ROC-AUC:   {avg_test_auc:.4f} ± {std_test_auc:.4f}", file=sys.stderr)
    
    # Write report
    report = {
        'method': 'day-aware-stratified-k-fold',
        'n_splits': 3,
        'model_params': {
            'max_depth': 8,
            'n_estimators': 200,
            'class_weight': 'balanced',
        },
        'cv_results': cv_results,
        'summary': {
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
