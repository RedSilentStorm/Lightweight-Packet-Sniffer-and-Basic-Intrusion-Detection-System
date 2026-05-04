#!/usr/bin/env python3
"""
Analyze CIC-IDS2017 processed data to find optimization opportunities.
- Check feature distributions (mean, std, zero ratio)
- Compare benign vs attack feature statistics
- Identify problematic features
"""

import csv
import math
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TEST_CSV = ROOT / "data" / "processed" / "test.csv"

def analyze_features(csv_path: Path):
    """Compute per-feature statistics for benign vs attack samples."""
    
    benign_stats = defaultdict(lambda: {"values": [], "zeros": 0, "count": 0})
    attack_stats = defaultdict(lambda: {"values": [], "zeros": 0, "count": 0})
    
    with csv_path.open(newline="") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            label = row.get("label_bin", "0").strip()
            is_attack = label == "1"
            stats = attack_stats if is_attack else benign_stats
            
            for col, val_str in row.items():
                if col in {"Label", "label_bin", "source_file"}:
                    continue
                
                try:
                    val = float(val_str or "0")
                except:
                    continue
                
                stats[col]["count"] += 1
                if val == 0:
                    stats[col]["zeros"] += 1
                else:
                    stats[col]["values"].append(val)
    
    # Print statistics
    print("\n" + "="*90)
    print("FEATURE ANALYSIS: Benign vs Attack")
    print("="*90)
    print(f"{'Feature':<40} {'B_Mean':>10} {'A_Mean':>10} {'Delta%':>8} {'B_Zero%':>8} {'A_Zero%':>8}")
    print("-"*90)
    
    all_features = sorted(set(benign_stats.keys()) | set(attack_stats.keys()))
    
    separability_score = []
    
    for feat in all_features:
        b = benign_stats[feat]
        a = attack_stats[feat]
        
        b_vals = b["values"]
        a_vals = a["values"]
        
        b_mean = sum(b_vals) / len(b_vals) if b_vals else 0
        a_mean = sum(a_vals) / len(a_vals) if a_vals else 0
        
        b_zero_pct = 100 * b["zeros"] / b["count"] if b["count"] else 0
        a_zero_pct = 100 * a["zeros"] / a["count"] if a["count"] else 0
        
        delta_pct = 0
        if b_mean != 0:
            delta_pct = 100 * abs(a_mean - b_mean) / b_mean
        
        # Separability: bigger delta and different zero rates = better
        sep = delta_pct + abs(b_zero_pct - a_zero_pct)
        separability_score.append((feat, sep, delta_pct, b_mean, a_mean, b_zero_pct, a_zero_pct))
        
        print(f"{feat:<40} {b_mean:>10.2f} {a_mean:>10.2f} {delta_pct:>7.1f}% {b_zero_pct:>7.1f}% {a_zero_pct:>7.1f}%")
    
    print("\n" + "="*90)
    print("TOP 15 MOST SEPARABLE FEATURES (by Δ% + Δ zero%)")
    print("="*90)
    separability_score.sort(key=lambda x: x[1], reverse=True)
    for i, (feat, sep, delta, b_mean, a_mean, b_zero, a_zero) in enumerate(separability_score[:15], 1):
        print(f"{i:2d}. {feat:<38} sep={sep:7.2f}  Δ={delta:6.1f}%  B_mean={b_mean:8.1f}  A_mean={a_mean:8.1f}")
    
    print("\n" + "="*90)
    print("BOTTOM 5 LEAST SEPARABLE FEATURES (poor discriminators)")
    print("="*90)
    for i, (feat, sep, delta, b_mean, a_mean, b_zero, a_zero) in enumerate(separability_score[-5:], 1):
        print(f"{feat:<40} sep={sep:7.2f}  Δ={delta:6.1f}%  B_mean={b_mean:8.1f}  A_mean={a_mean:8.1f}")

if __name__ == "__main__":
    analyze_features(TEST_CSV)
