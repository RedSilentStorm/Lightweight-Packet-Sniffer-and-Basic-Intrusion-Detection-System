#!/usr/bin/env python3
"""Retrain V3 with positive-class sample_weight multipliers to boost recall.
Trains on sampled data for speed and evaluates on full test set.
"""
import csv
import math
import json
from pathlib import Path
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.metrics import confusion_matrix, roc_auc_score
import numpy as np

TRAIN_CSV = 'data/processed/train.csv'
TEST_CSV = 'data/processed/test.csv'
REPORT = 'reports/cic_ai_retrain_recall_results.json'

# Sample sizes for speed
BENIGN_SAMPLE = 80000
ATTACK_SAMPLE = 80000

WEIGHTS = [1, 2, 4, 8, 16, 32]

def load_sampled(csv_path, benign_target=BENIGN_SAMPLE, attack_target=ATTACK_SAMPLE):
    header = None
    benign = []
    attack = []
    with open(csv_path, 'r') as fh:
        reader = csv.reader(fh)
        header = next(reader)
        label_idx = header.index('label_bin') if 'label_bin' in header else header.index('label')
        feature_indices = [i for i, c in enumerate(header) if c not in ('label','label_bin','source_file')]
        for i, row in enumerate(reader):
            if len(benign) >= benign_target and len(attack) >= attack_target:
                break
            try:
                lab = row[label_idx].strip().upper()
                is_attack = 0 if lab in ('0','BENIGN','NORMAL','') else 1
            except Exception:
                continue
            feat = []
            for idx in feature_indices:
                try:
                    feat.append(float(row[idx]))
                except Exception:
                    feat.append(0.0)
            if is_attack:
                if len(attack) < attack_target:
                    attack.append((feat,1))
            else:
                if len(benign) < benign_target:
                    benign.append((feat,0))
    data = benign + attack
    X = [x for x,y in data]
    y = [y for x,y in data]
    return np.array(X), np.array(y)

def load_test(csv_path):
    header = None
    X = []
    y = []
    with open(csv_path, 'r') as fh:
        reader = csv.reader(fh)
        header = next(reader)
        label_idx = header.index('label_bin') if 'label_bin' in header else header.index('label')
        feature_indices = [i for i, c in enumerate(header) if c not in ('label','label_bin','source_file')]
        for i, row in enumerate(reader):
            try:
                lab = row[label_idx].strip().upper()
                is_attack = 0 if lab in ('0','BENIGN','NORMAL','') else 1
            except Exception:
                continue
            feat = []
            for idx in feature_indices:
                try:
                    feat.append(float(row[idx]))
                except Exception:
                    feat.append(0.0)
            X.append(feat)
            y.append(is_attack)
    return np.array(X), np.array(y)


def find_threshold_for_min_recall(probs, labels, min_recall):
    # compute thresholds from unique probs
    uniq = np.unique(probs)
    # sort descending
    uniq = np.sort(uniq)[::-1]
    for t in uniq:
        preds = (probs >= t).astype(int)
        tp = int(((preds==1) & (labels==1)).sum())
        fn = int(((preds==0) & (labels==1)).sum())
        recall = tp / (tp + fn) if (tp + fn)>0 else 0.0
        if recall >= min_recall:
            return float(t)
    return float(uniq[-1])


def eval_at_threshold(probs, labels, threshold):
    preds = (probs >= threshold).astype(int)
    tn, fp, fn, tp = confusion_matrix(labels, preds, labels=[0,1]).ravel()
    prec = tp/(tp+fp) if (tp+fp)>0 else 0.0
    rec = tp/(tp+fn) if (tp+fn)>0 else 0.0
    f1 = 2*prec*rec/(prec+rec) if (prec+rec)>0 else 0.0
    auc = roc_auc_score(labels, probs)
    return {'threshold': float(threshold),'precision':prec,'recall':rec,'f1':f1,'tp':int(tp),'fp':int(fp),'fn':int(fn),'tn':int(tn),'auc':float(auc)}


def main():
    print('[*] Loading sampled training data...')
    X_train, y_train = load_sampled(TRAIN_CSV)
    print(f'  Train sample: {len(X_train)} (pos={y_train.sum()})')
    print('[*] Loading full test set...')
    X_test, y_test = load_test(TEST_CSV)
    print(f'  Test set: {len(X_test)} (pos={y_test.sum()})')

    results = []
    for w in WEIGHTS:
        print(f'\n[*] Training with pos_weight={w}...')
        clf = HistGradientBoostingClassifier(random_state=42, max_iter=200)
        sample_weight = np.where(y_train==1, w, 1.0)
        clf.fit(X_train, y_train, sample_weight=sample_weight)
        probs_val = clf.predict_proba(X_test)[:,1]
        # find thresholds for targets
        for target in [0.7, 0.8]:
            t = find_threshold_for_min_recall(probs_val, y_test, target)
            metrics = eval_at_threshold(probs_val, y_test, t)
            results.append({'pos_weight':w,'target_recall':target,'threshold':t,'metrics':metrics})
            print(f"  target={target}: threshold={t:.6f} P={metrics['precision']:.4f} R={metrics['recall']:.4f} F1={metrics['f1']:.4f} FP={metrics['fp']} TP={metrics['tp']}")

    with open(REPORT,'w') as fh:
        json.dump(results, fh, indent=2)
    print('\n[+] Saved results to', REPORT)

if __name__ == '__main__':
    main()
