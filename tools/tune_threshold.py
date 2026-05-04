#!/usr/bin/env python3
"""Threshold optimizer for CIC AI v2.

Optimization priorities:
1) Maximize precision
2) Minimize false positives
3) Keep recall above a configurable floor
4) Use F-beta as fallback if no candidate satisfies recall floor
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# Add tools directory to path for direct script execution.
sys.path.insert(0, str(Path(__file__).parent))

from cic_ai_v2 import evaluate_scores, load_model, load_rows_with_scores


def parse_args() -> argparse.Namespace:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description="Tune threshold for CIC AI v2 with precision-first objective.")
    parser.add_argument("--model", type=Path, default=root / "data" / "models" / "cic_anomaly_model_v2.json")
    parser.add_argument("--input-csv", type=Path, default=root / "data" / "processed" / "test.csv")
    parser.add_argument("--start-percentile", type=float, default=85.0)
    parser.add_argument("--end-percentile", type=float, default=98.0)
    parser.add_argument("--step", type=float, default=1.0)
    parser.add_argument(
        "--min-recall",
        type=float,
        default=0.30,
        help="Minimum acceptable recall while optimizing for precision.",
    )
    parser.add_argument(
        "--fallback-beta",
        type=float,
        default=0.5,
        help="F-beta used only when no candidate satisfies min-recall.",
    )
    return parser.parse_args()


def percentile_threshold(sorted_scores: list[float], percentile: float) -> float:
    idx = int(len(sorted_scores) * (percentile / 100.0))
    return sorted_scores[min(max(idx, 0), len(sorted_scores) - 1)]


def fbeta(precision: float, recall: float, beta: float) -> float:
    beta_sq = beta * beta
    denom = (beta_sq * precision) + recall
    if denom == 0:
        return 0.0
    return (1 + beta_sq) * precision * recall / denom


def main() -> int:
    args = parse_args()
    if args.step <= 0:
        raise ValueError("--step must be > 0")

    model = load_model(args.model)
    if not args.input_csv.exists():
        raise FileNotFoundError(f"Input CSV not found: {args.input_csv}")

    scores, labels = load_rows_with_scores(model, args.input_csv, None)
    sorted_scores = sorted(scores)

    percentiles: list[float] = []
    cur = args.start_percentile
    while cur <= args.end_percentile + 1e-9:
        percentiles.append(round(cur, 6))
        cur += args.step

    constrained_candidates: list[tuple[float, float, dict]] = []
    all_candidates: list[tuple[float, float, dict]] = []

    for percentile in percentiles:
        threshold = percentile_threshold(sorted_scores, percentile)
        metrics = evaluate_scores(scores, labels, threshold)
        all_candidates.append((percentile, threshold, metrics))
        if metrics["recall"] >= args.min_recall:
            constrained_candidates.append((percentile, threshold, metrics))

    if constrained_candidates:
        # Priority: precision desc, FP asc, recall desc.
        best_percentile, best_threshold, best_metrics = sorted(
            constrained_candidates,
            key=lambda x: (
                x[2]["precision"],
                -x[2]["confusion_matrix"]["fp"],
                x[2]["recall"],
            ),
            reverse=True,
        )[0]
        selection_mode = "precision-first (with min-recall constraint)"
    else:
        # Fallback to F-beta optimization when recall floor is too strict.
        best_percentile, best_threshold, best_metrics = max(
            all_candidates,
            key=lambda x: fbeta(x[2]["precision"], x[2]["recall"], args.fallback_beta),
        )
        selection_mode = f"fallback F-beta (beta={args.fallback_beta})"

    model.threshold = best_threshold
    model.threshold_percentile = best_percentile
    with args.model.open("w") as fh:
        json.dump(model.to_dict(), fh, indent=2)

    cm = best_metrics["confusion_matrix"]
    print(f"Selected mode: {selection_mode}")
    print(f"Optimal percentile: {best_percentile:.2f}")
    print(f"Optimal threshold: {best_threshold:.6f}")
    print(
        "Metrics: "
        f"P={best_metrics['precision']:.4f}, "
        f"R={best_metrics['recall']:.4f}, "
        f"F1={best_metrics['f1']:.4f}, "
        f"AUC={best_metrics['roc_auc']:.4f}"
    )
    print(f"Confusion Matrix: TP={cm['tp']}, FP={cm['fp']}, TN={cm['tn']}, FN={cm['fn']}")
    print(f"Model updated: {args.model}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
