#!/usr/bin/env python3
"""Analyze `reports/cic_predictions_v3.csv` to find thresholds achieving target recall.
Outputs precision/recall/F1/FP/TP for thresholds that reach R>=0.70 and R>=0.80, and saves suggested thresholds.
"""
import csv
import math
from collections import Counter

PRED_CSV = 'reports/cic_predictions_v3.csv'

def iter_rows(path):
    with open(path, newline='') as fh:
        r = csv.DictReader(fh)
        for row in r:
            yield row

def main():
    total = 0
    probs = []
    labels = []
    # detect column names
    with open(PRED_CSV, newline='') as fh:
        r = csv.DictReader(fh)
        cols = r.fieldnames
        # guess probability column
        prob_col = None
        for c in cols:
            if c.lower() in ('prob','probability','score','anomaly_score','probability_score','anomaly_probability'):
                prob_col = c
                break
        if prob_col is None:
            # fallback pick a numeric column that's not label
            for c in cols:
                if c.lower() not in ('label','label_bin'):
                    prob_col = c
                    break
        label_col = None
        for c in cols:
            if c.lower() in ('label_bin','label'):
                label_col = c
                break
        if label_col is None:
            raise SystemExit('Cannot find label column in predictions CSV')

        for row in r:
            total += 1
            try:
                p = float(row.get(prob_col, row.get('anomaly_score', 0)))
            except:
                p = 0.0
            lab_raw = row.get(label_col, '0')
            lab = 0
            if str(lab_raw).strip().upper() not in ('0','BENIGN','NORMAL','FALSE','NONE',''):
                lab = 1
            probs.append(p)
            labels.append(lab)

    if total == 0:
        print('No rows found in', PRED_CSV)
        return

    # build sorted unique thresholds from probs
    paired = list(zip(probs, labels))
    paired.sort(key=lambda x: x[0], reverse=True)

    # prefix sums to compute TP/FP quickly
    cum_TP = []
    cum_FP = []
    tp = 0
    fp = 0
    total_pos = sum(labels)
    total_neg = total - total_pos

    thresholds = []
    last_p = None
    for p, l in paired:
        if last_p is None or p != last_p:
            thresholds.append(p)
            last_p = p

    # compute metrics for sampled thresholds (avoid 500k points)
    sample_every = max(1, len(thresholds)//1000)
    sampled_thresholds = thresholds[::sample_every]
    if thresholds[-1] not in sampled_thresholds:
        sampled_thresholds.append(thresholds[-1])

    results = []
    for t in sampled_thresholds:
        tp = sum(1 for p,l in paired if p>=t and l==1)
        fp = sum(1 for p,l in paired if p>=t and l==0)
        fn = total_pos - tp
        tn = total_neg - fp
        prec = tp/(tp+fp) if (tp+fp)>0 else 0.0
        rec = tp/(tp+fn) if (tp+fn)>0 else 0.0
        f1 = 2*prec*rec/(prec+rec) if (prec+rec)>0 else 0.0
        results.append((t, prec, rec, f1, tp, fp))

    # find thresholds achieving recall targets
    targets = [0.70, 0.80]
    out = {}
    for target in targets:
        candidates = [r for r in results if r[2] >= target]
        if not candidates:
            out[target] = None
            continue
        # pick candidate with highest precision among those
        best = max(candidates, key=lambda x: x[1])
        out[target] = best

    print(f'Total rows: {total}, positives: {total_pos}, negatives: {total_neg}')
    for target in targets:
        v = out[target]
        if v is None:
            print(f'No threshold achieves recall >= {int(target*100)}%')
        else:
            t, prec, rec, f1, tp, fp = v
            print(f'Recall >= {int(target*100)}%  -> Threshold={t:.6f}, Precision={prec:.4f}, Recall={rec:.4f}, F1={f1:.4f}, TP={tp}, FP={fp}')

    # also print best F1
    best = max(results, key=lambda x: x[3])
    t, prec, rec, f1, tp, fp = best
    print(f'Best F1 -> Threshold={t:.6f}, Precision={prec:.4f}, Recall={rec:.4f}, F1={f1:.4f}, TP={tp}, FP={fp}')

if __name__ == '__main__':
    main()
