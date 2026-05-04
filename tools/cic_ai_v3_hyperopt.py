#!/usr/bin/env python3
"""
Hyperparameter optimization for V3 model using GridSearchCV on sampled data.
Fast optimization to find optimal max_depth and n_estimators.
"""

import sys
import json
import random
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import GridSearchCV
from sklearn.metrics import confusion_matrix, precision_score, recall_score, f1_score, roc_auc_score

# Constants
TRAIN_CSV = 'data/processed/train.csv'
TEST_CSV = 'data/processed/test.csv'
REPORT = 'reports/cic_ai_report_v3_hyperopt.json'

def load_sampled_data(csv_path, benign_sample=20000, attack_sample=20000):
    """Load balanced sample of data for fast hyperparameter tuning."""
    print(f"[*] Loading sampled data from {csv_path}...", file=sys.stderr)
    
    benign = []
    attack = []
    
    with open(csv_path, 'r') as f:
        header = f.readline().strip().split(',')
        label_idx = header.index('label_bin') if 'label_bin' in header else header.index('label')
        feature_indices = [i for i, col in enumerate(header) if col not in ['label', 'label_bin', 'source_file']]
        
        for line_num, line in enumerate(f):
            if line_num % 500000 == 0:
                print(f"    Scanned {line_num:,} rows...", file=sys.stderr)
            
            if len(benign) >= benign_sample and len(attack) >= attack_sample:
                break
            
            cols = line.strip().split(',')
            
            # Extract label and features
            try:
                label = int(float(cols[label_idx]))
            except:
                continue
            
            try:
                features = [float(cols[i]) if i < len(cols) else 0.0 for i in feature_indices]
            except:
                continue
            
            if label == 0 and len(benign) < benign_sample:
                benign.append(features)
            elif label == 1 and len(attack) < attack_sample:
                attack.append(features)
    
    X = benign + attack
    y = [0] * len(benign) + [1] * len(attack)
    
    print(f"[+] Loaded {len(benign)} benign + {len(attack)} attack = {len(X)} total samples", file=sys.stderr)
    return X, y

def load_test_data(csv_path):
    """Load full test set for evaluation."""
    print(f"[*] Loading test data from {csv_path}...", file=sys.stderr)
    
    X_test = []
    y_test = []
    
    with open(csv_path, 'r') as f:
        header = f.readline().strip().split(',')
        label_idx = header.index('label_bin') if 'label_bin' in header else header.index('label')
        feature_indices = [i for i, col in enumerate(header) if col not in ['label', 'label_bin', 'source_file']]
        
        for line_num, line in enumerate(f):
            if line_num % 500000 == 0:
                print(f"    Loaded {line_num:,} rows...", file=sys.stderr)
            
            cols = line.strip().split(',')
            
            try:
                label = int(float(cols[label_idx]))
                features = [float(cols[i]) if i < len(cols) else 0.0 for i in feature_indices]
            except:
                continue
            
            X_test.append(features)
            y_test.append(label)
    
    print(f"[+] Loaded {len(X_test)} test samples", file=sys.stderr)
    return X_test, y_test

def evaluate_model(model, threshold, X_test, y_test):
    """Evaluate model on test set with given threshold."""
    probs = model.predict_proba(X_test)[:, 1]
    preds = [1 if p >= threshold else 0 for p in probs]
    
    tn, fp, fn, tp = confusion_matrix(y_test, preds, labels=[0, 1]).ravel()
    
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
    auc = roc_auc_score(y_test, probs)
    
    return {
        'precision': precision,
        'recall': recall,
        'f1': f1,
        'auc': auc,
        'tp': int(tp),
        'fp': int(fp),
        'fn': int(fn),
        'tn': int(tn),
    }

def find_optimal_threshold(model, X_val, y_val, min_recall=0.40):
    """Find optimal threshold on validation set (precision-first with min_recall constraint)."""
    val_probs = model.predict_proba(X_val)[:, 1]
    
    best_threshold = 0.5
    best_precision = 0
    
    for threshold in sorted(set(val_probs))[::max(1, len(set(val_probs))//100)]:
        val_pred = [1 if p >= threshold else 0 for p in val_probs]
        tn, fp, fn, tp = confusion_matrix(y_val, val_pred, labels=[0, 1]).ravel()
        
        if tp + fp == 0:
            continue
        
        precision = tp / (tp + fp)
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0
        
        if recall >= min_recall and precision > best_precision:
            best_threshold = threshold
            best_precision = precision
    
    return best_threshold

def main():
    print("[*] V3 Hyperparameter Optimization via GridSearchCV", file=sys.stderr)
    
    # Load training data (sampled for speed)
    X_train, y_train = load_sampled_data(TRAIN_CSV, benign_sample=30000, attack_sample=15000)
    
    # Load test data
    X_test, y_test = load_test_data(TEST_CSV)
    
    # Define hyperparameter grid
    param_grid = {
        'max_depth': [6, 8, 10, 12],
        'n_estimators': [100, 150, 200, 250],
    }
    
    print(f"\n[*] GridSearchCV: Testing {len(param_grid['max_depth']) * len(param_grid['n_estimators'])} combinations", file=sys.stderr)
    
    # GridSearchCV
    base_model = RandomForestClassifier(class_weight='balanced', random_state=42, n_jobs=-1)
    
    grid_search = GridSearchCV(
        base_model,
        param_grid,
        cv=3,
        scoring='roc_auc',
        n_jobs=-1,
        verbose=1
    )
    
    print(f"[*] Training GridSearchCV...", file=sys.stderr)
    grid_search.fit(X_train, y_train)
    
    # Get best model
    best_model = grid_search.best_estimator_
    best_params = grid_search.best_params_
    
    print(f"\n[+] Best parameters: {best_params}", file=sys.stderr)
    print(f"[+] Best CV score (ROC-AUC): {grid_search.best_score_:.4f}", file=sys.stderr)
    
    # Find optimal threshold using test set (validate on a split)
    split_idx = len(X_test) // 2
    X_val = X_test[:split_idx]
    y_val = y_test[:split_idx]
    X_eval = X_test[split_idx:]
    y_eval = y_test[split_idx:]
    
    threshold = find_optimal_threshold(best_model, X_val, y_val, min_recall=0.40)
    print(f"[+] Optimal threshold (on validation split): {threshold:.6f}", file=sys.stderr)
    
    # Evaluate on test split
    eval_metrics = evaluate_model(best_model, threshold, X_eval, y_eval)
    
    print(f"\n[*] ========== HYPEROPT RESULTS ==========", file=sys.stderr)
    print(f"Test Split Metrics (after hyperopt):", file=sys.stderr)
    print(f"  Precision: {eval_metrics['precision']:.4f}", file=sys.stderr)
    print(f"  Recall:    {eval_metrics['recall']:.4f}", file=sys.stderr)
    print(f"  F1-Score:  {eval_metrics['f1']:.4f}", file=sys.stderr)
    print(f"  ROC-AUC:   {eval_metrics['auc']:.4f}", file=sys.stderr)
    print(f"  TP: {eval_metrics['tp']}, FP: {eval_metrics['fp']}, FN: {eval_metrics['fn']}, TN: {eval_metrics['tn']}", file=sys.stderr)
    
    # Compare with current V3 baseline
    print(f"\n[*] Comparison with current V3 (max_depth=8, n_estimators=200):", file=sys.stderr)
    baseline_metrics = {
        'precision': 0.9998,
        'recall': 0.5543,
        'f1': 0.7132,
        'auc': 0.9998,
    }
    print(f"  Baseline Precision: {baseline_metrics['precision']:.4f} vs Hyperopt: {eval_metrics['precision']:.4f}", file=sys.stderr)
    print(f"  Baseline Recall: {baseline_metrics['recall']:.4f} vs Hyperopt: {eval_metrics['recall']:.4f}", file=sys.stderr)
    print(f"  Baseline F1: {baseline_metrics['f1']:.4f} vs Hyperopt: {eval_metrics['f1']:.4f}", file=sys.stderr)
    print(f"  Baseline AUC: {baseline_metrics['auc']:.4f} vs Hyperopt: {eval_metrics['auc']:.4f}", file=sys.stderr)
    
    # Write report
    report = {
        'method': 'GridSearchCV',
        'train_samples': len(X_train),
        'test_samples': len(X_test),
        'param_grid': {
            'max_depth': param_grid['max_depth'],
            'n_estimators': param_grid['n_estimators'],
        },
        'best_parameters': {
            'max_depth': int(best_params['max_depth']),
            'n_estimators': int(best_params['n_estimators']),
        },
        'best_cv_score_roc_auc': float(grid_search.best_score_),
        'optimal_threshold': float(threshold),
        'test_metrics': {
            'precision': float(eval_metrics['precision']),
            'recall': float(eval_metrics['recall']),
            'f1': float(eval_metrics['f1']),
            'auc': float(eval_metrics['auc']),
            'tp': eval_metrics['tp'],
            'fp': eval_metrics['fp'],
            'fn': eval_metrics['fn'],
            'tn': eval_metrics['tn'],
        },
        'cv_results': grid_search.cv_results_,
    }
    
    with open(REPORT, 'w') as f:
        json.dump(report, f, indent=2, default=str)
    
    print(f"\n[+] Hyperopt report saved to {REPORT}", file=sys.stderr)

if __name__ == '__main__':
    main()
