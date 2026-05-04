#!/usr/bin/env python3
"""
Enhanced CIC-IDS2017 anomaly detection with better preprocessing.

Improvements:
1. StandardScaler normalization instead of log transform (preserves feature scale)
2. Percentile-based threshold selection (more robust)
3. Better outlier handling
4. Feature importance weighting based on discriminatory power
"""

from __future__ import annotations

import argparse
import csv
import json
import math
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MODEL_PATH = ROOT / "data" / "models" / "cic_anomaly_model_v2.json"
DEFAULT_REPORT_PATH = ROOT / "reports" / "cic_ai_report_v2.json"
DEFAULT_PREDICTIONS_PATH = ROOT / "reports" / "cic_predictions_v2.csv"

NEGATIVE_LABELS = {"0", "BENIGN", "NORMAL"}

# Top discriminatory features with weights based on analysis
WEIGHTED_FEATURES = {
    # Ultra-high delta features (weight=1.5x)
    "Idle Std": 1.5,
    "Packet Length Variance": 1.5,
    "Active Std": 1.5,
    
    # Very high delta (weight=1.2x)
    "Bwd Packet Length Max": 1.2,
    "Bwd Packet Length Std": 1.2,
    "Packet Length Std": 1.2,
    "Fwd IAT Max": 1.2,
    "Max Packet Length": 1.2,
    "Flow IAT Max": 1.2,
    "Avg Bwd Segment Size": 1.2,
    "Fwd IAT Std": 1.2,
    "Idle Max": 1.2,
    
    # High delta (weight=1.0x)
    "Bwd Packet Length Mean": 1.0,
    "Packet Length Mean": 1.0,
    "Average Packet Size": 1.0,
    "Flow Duration": 1.0,
    "Total Backward Packets": 1.0,
    "Total Fwd Packets": 1.0,
    "Total Length of Fwd Packets": 1.0,
    "Total Length of Bwd Packets": 1.0,
    "Flow IAT Mean": 1.0,
    "Flow IAT Std": 1.0,
    "Fwd IAT Mean": 1.0,
    "Bwd IAT Max": 1.0,
    "Bwd Packets/s": 1.0,
    "Fwd Packets/s": 1.0,
    "Destination Port": 1.0,
    "Init_Win_bytes_backward": 1.0,
    "Subflow Fwd Bytes": 1.0,
    "Subflow Bwd Bytes": 1.0,
}


def canonical_label(value: str | None) -> str:
    if value is None:
        return "BENIGN"
    cleaned = value.strip().upper()
    return cleaned if cleaned else "BENIGN"


def parse_float(value: str | None) -> float:
    if value is None:
        return 0.0

    cleaned = value.strip()
    if cleaned == "" or cleaned.lower() in {"nan", "inf", "+inf", "-inf", "infinity", "+infinity", "-infinity"}:
        return 0.0

    try:
        parsed = float(cleaned)
    except ValueError:
        return 0.0

    if math.isnan(parsed) or math.isinf(parsed):
        return 0.0

    return parsed


@dataclass
class RunningStats:
    count: int = 0
    mean: float = 0.0
    m2: float = 0.0
    min_val: float = float('inf')
    max_val: float = float('-inf')

    def update(self, value: float) -> None:
        self.count += 1
        self.min_val = min(self.min_val, value)
        self.max_val = max(self.max_val, value)
        delta = value - self.mean
        self.mean += delta / self.count
        delta2 = value - self.mean
        self.m2 += delta * delta2

    @property
    def variance(self) -> float:
        if self.count <= 1:
            return 1.0
        return max(self.m2 / (self.count - 1), 1e-12)

    @property
    def stddev(self) -> float:
        return math.sqrt(self.variance)

    def normalize(self, value: float, clip_outliers: bool = True) -> float:
        """StandardScaler: (value - mean) / (std + 1e-8)"""
        std = self.stddev
        normalized = (value - self.mean) / (std + 1e-8)
        
        if clip_outliers:
            # Clip extreme outliers to [-5, 5] range
            normalized = max(-5.0, min(5.0, normalized))
        
        return normalized


class CICAnomalyModelV2:
    def __init__(
        self,
        feature_names: list[str],
        feature_weights: dict[str, float] | None = None,
        threshold_percentile: float = 93.0,
    ):
        self.feature_names = feature_names
        self.feature_weights = feature_weights or {name: 1.0 for name in feature_names}
        self.feature_means = [0.0 for _ in feature_names]
        self.feature_stds = [1.0 for _ in feature_names]
        self.threshold_percentile = threshold_percentile
        self.threshold = 1.0
        self.train_rows_seen = 0
        self.train_benign_rows_seen = 0

    @staticmethod
    def _row_label(row: dict[str, str]) -> str:
        if "label_bin" in row:
            return "BENIGN" if canonical_label(row.get("label_bin")) in NEGATIVE_LABELS else "ATTACK"
        return canonical_label(row.get("Label"))

    def _row_vector(self, row: dict[str, str]) -> list[float]:
        return [parse_float(row.get(name)) for name in self.feature_names]

    def score_vector(self, vector: list[float]) -> float:
        """Weighted Mahalanobis distance-like score"""
        total = 0.0
        weight_sum = 0.0
        
        for index, value in enumerate(vector):
            mean = self.feature_means[index]
            std = self.feature_stds[index]
            weight = self.feature_weights.get(self.feature_names[index], 1.0)
            
            # Normalize with clipping
            z = (value - mean) / (std + 1e-8)
            z = max(-5.0, min(5.0, z))
            
            total += weight * (z * z)
            weight_sum += weight
        
        return total / max(1.0, weight_sum) if weight_sum > 0 else 0.0

    def score_row(self, row: dict[str, str]) -> float:
        return self.score_vector(self._row_vector(row))

    def predict_row(self, row: dict[str, str]) -> tuple[float, int]:
        score = self.score_row(row)
        return score, int(score >= self.threshold)

    def fit(self, csv_path: Path, max_rows: int | None = None) -> None:
        """Learn feature statistics from benign samples only"""
        feature_stats = [RunningStats() for _ in self.feature_names]
        benign_count = 0
        total_count = 0

        # First pass: compute benign statistics
        with csv_path.open(newline="") as fh:
            reader = csv.DictReader(fh)
            for row in reader:
                total_count += 1
                if max_rows is not None and total_count > max_rows:
                    break

                if self._row_label(row) != "BENIGN":
                    continue

                vector = self._row_vector(row)
                for index, value in enumerate(vector):
                    feature_stats[index].update(value)
                benign_count += 1

        if benign_count == 0:
            raise RuntimeError("No BENIGN rows found while fitting the anomaly model.")

        self.feature_means = [stat.mean for stat in feature_stats]
        self.feature_stds = [stat.stddev for stat in feature_stats]

        # Second pass: score all rows and find threshold by percentile
        benign_scores = []
        total_count = 0

        with csv_path.open(newline="") as fh:
            reader = csv.DictReader(fh)
            for row in reader:
                total_count += 1
                if max_rows is not None and total_count > max_rows:
                    break

                if self._row_label(row) != "BENIGN":
                    continue

                score = self.score_row(row)
                benign_scores.append(score)

        # Set threshold to the 93rd percentile of benign scores.
        # This keeps precision high while avoiding the recall collapse we saw at 95th percentile.
        benign_scores.sort()
        percentile_idx = int(len(benign_scores) * (self.threshold_percentile / 100.0))
        self.threshold = benign_scores[min(percentile_idx, len(benign_scores) - 1)]

        self.train_rows_seen = total_count if max_rows is None else min(total_count, max_rows)
        self.train_benign_rows_seen = benign_count

    def to_dict(self) -> dict:
        return {
            "version": 2,
            "feature_names": self.feature_names,
            "feature_weights": self.feature_weights,
            "feature_means": self.feature_means,
            "feature_stds": self.feature_stds,
            "threshold": self.threshold,
            "threshold_percentile": self.threshold_percentile,
            "train_rows_seen": self.train_rows_seen,
            "train_benign_rows_seen": self.train_benign_rows_seen,
        }

    @classmethod
    def from_dict(cls, payload: dict) -> "CICAnomalyModelV2":
        feature_names = list(payload.get("feature_names", []))
        feature_weights = dict(payload.get("feature_weights", {}))
        threshold_percentile = float(payload.get("threshold_percentile", 93.0))
        model = cls(feature_names, feature_weights, threshold_percentile=threshold_percentile)
        model.feature_means = list(payload.get("feature_means", [0.0] * len(feature_names)))
        model.feature_stds = list(payload.get("feature_stds", [1.0] * len(feature_names)))
        model.threshold = float(payload.get("threshold", 1.0))
        model.threshold_percentile = threshold_percentile
        model.train_rows_seen = int(payload.get("train_rows_seen", 0))
        model.train_benign_rows_seen = int(payload.get("train_benign_rows_seen", 0))
        return model


def load_header(csv_path: Path) -> list[str]:
    with csv_path.open(newline="") as fh:
        reader = csv.reader(fh)
        header = next(reader)
    return [column.strip() for column in header]


def infer_feature_names(header: list[str]) -> list[str]:
    available = [name for name in WEIGHTED_FEATURES.keys() if name in header]
    if available:
        return available
    
    # Fallback: use all numeric columns
    ignore = {"Label", "label_bin", "source_file"}
    return [name for name in header if name not in ignore]


def load_model(model_path: Path) -> CICAnomalyModelV2:
    with model_path.open("r") as fh:
        payload = json.load(fh)
    return CICAnomalyModelV2.from_dict(payload)


def save_model(model: CICAnomalyModelV2, model_path: Path) -> None:
    model_path.parent.mkdir(parents=True, exist_ok=True)
    with model_path.open("w") as fh:
        json.dump(model.to_dict(), fh, indent=2)


def evaluate_scores(scores: list[float], labels: list[int], threshold: float) -> dict:
    if not scores:
        return {
            "total": 0,
            "accuracy": 0.0,
            "precision": 0.0,
            "recall": 0.0,
            "f1": 0.0,
            "roc_auc": 0.0,
            "confusion_matrix": {"tp": 0, "fp": 0, "tn": 0, "fn": 0},
        }

    tp = fp = tn = fn = 0
    for score, label in zip(scores, labels):
        predicted = 1 if score >= threshold else 0
        if label == 1 and predicted == 1:
            tp += 1
        elif label == 0 and predicted == 1:
            fp += 1
        elif label == 0 and predicted == 0:
            tn += 1
        else:
            fn += 1

    accuracy = (tp + tn) / len(scores)
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    roc_auc = calculate_auc(scores, labels)

    return {
        "total": len(scores),
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "roc_auc": roc_auc,
        "confusion_matrix": {"tp": tp, "fp": fp, "tn": tn, "fn": fn},
    }


def calculate_auc(scores: list[float], labels: list[int]) -> float:
    pos = sum(labels)
    neg = len(labels) - pos

    if pos == 0 or neg == 0:
        return 0.0

    sorted_pairs = sorted(zip(scores, labels), reverse=True)
    tp = 0
    fp = 0
    auc_sum = 0.0

    for score, label in sorted_pairs:
        if label == 1:
            tp += 1
        else:
            fp += 1
            auc_sum += tp

    auc = auc_sum / (tp * neg) if (tp * neg) else 0.0
    return max(0.0, min(1.0, auc))


def load_rows_with_scores(model: CICAnomalyModelV2, csv_path: Path, max_rows: int | None) -> tuple[list[float], list[int]]:
    scores: list[float] = []
    labels: list[int] = []
    seen = 0

    with csv_path.open(newline="") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            seen += 1
            if max_rows is not None and seen > max_rows:
                break

            label = 1 if model._row_label(row) != "BENIGN" else 0
            score = model.score_row(row)
            scores.append(score)
            labels.append(label)

    return scores, labels


def write_predictions(model: CICAnomalyModelV2, input_csv: Path, output_csv: Path, max_rows: int | None) -> int:
    output_csv.parent.mkdir(parents=True, exist_ok=True)
    written = 0
    seen = 0

    with input_csv.open(newline="") as in_fh, output_csv.open("w", newline="") as out_fh:
        reader = csv.DictReader(in_fh)
        fieldnames = list(reader.fieldnames or []) + ["anomaly_score", "predicted_label"]
        writer = csv.DictWriter(out_fh, fieldnames=fieldnames)
        writer.writeheader()

        for row in reader:
            seen += 1
            if max_rows is not None and seen > max_rows:
                break

            score, predicted = model.predict_row(row)
            row["anomaly_score"] = f"{score:.6f}"
            row["predicted_label"] = str(predicted)
            writer.writerow(row)
            written += 1

    return written


def print_report(model: CICAnomalyModelV2, metrics: dict, input_name: str) -> None:
    cm = metrics["confusion_matrix"]
    print("\n" + "=" * 60)
    print("CIC-IDS2017 AI ANOMALY REPORT (V2 - Enhanced)")
    print("=" * 60)
    print(f"Input: {input_name}")
    print(f"Features used: {len(model.feature_names)}")
    print(f"Threshold: {model.threshold:.6f} ({model.threshold_percentile:.1f}th percentile target)")
    print(f"Rows evaluated: {metrics['total']}")
    print("\n--- Confusion Matrix ---")
    print(f"TP: {cm['tp']}  FP: {cm['fp']}  TN: {cm['tn']}  FN: {cm['fn']}")
    print("\n--- Metrics ---")
    print(f"Accuracy:  {metrics['accuracy']:.4f}")
    print(f"Precision: {metrics['precision']:.4f}")
    print(f"Recall:    {metrics['recall']:.4f}")
    print(f"F1:        {metrics['f1']:.4f}")
    print(f"ROC-AUC:   {metrics['roc_auc']:.4f}")
    print("=" * 60 + "\n")


def write_report(report_path: Path, model: CICAnomalyModelV2, metrics: dict, input_path: Path, output_path: Path | None) -> None:
    report_path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "input": str(input_path),
        "output": str(output_path) if output_path else None,
        "model": {
            "features": model.feature_names,
            "threshold": model.threshold,
            "threshold_percentile": model.threshold_percentile,
            "version": 2,
        },
        "metrics": metrics,
    }
    with report_path.open("w") as fh:
        json.dump(payload, fh, indent=2)


def train_command(args: argparse.Namespace) -> int:
    train_csv = args.train_csv
    if not train_csv.exists():
        print(f"Train CSV not found: {train_csv}")
        return 1

    header = load_header(train_csv)
    feature_names = infer_feature_names(header)
    if not feature_names:
        print("No usable feature columns found in training CSV.")
        return 1

    feature_weights = {name: WEIGHTED_FEATURES.get(name, 1.0) for name in feature_names}
    
    model = CICAnomalyModelV2(feature_names, feature_weights, threshold_percentile=args.threshold_percentile)
    model.fit(train_csv, max_rows=args.max_train_rows)
    save_model(model, args.model)

    print(f"Trained AI anomaly model V2 on {train_csv}")
    print(f"Model saved to {args.model}")
    print(f"Features used: {len(model.feature_names)}")
    print(f"Threshold: {model.threshold:.6f} ({model.threshold_percentile:.1f}th percentile of benign samples)")
    print(f"Benign rows used: {model.train_benign_rows_seen}")
    return 0


def evaluate_command(args: argparse.Namespace) -> int:
    test_csv = args.test_csv
    if not test_csv.exists():
        print(f"Test CSV not found: {test_csv}")
        return 1

    model = load_model(args.model)
    scores, labels = load_rows_with_scores(model, test_csv, args.max_rows)
    metrics = evaluate_scores(scores, labels, model.threshold)
    print_report(model, metrics, str(test_csv))
    write_report(args.report, model, metrics, test_csv, None)
    print(f"Report written to {args.report}")
    return 0


def score_command(args: argparse.Namespace) -> int:
    input_csv = args.input_csv
    if not input_csv.exists():
        print(f"Input CSV not found: {input_csv}")
        return 1

    model = load_model(args.model)
    written = write_predictions(model, input_csv, args.output, args.max_rows)
    print(f"Wrote {written} scored rows to {args.output}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Enhanced lightweight CIC-IDS2017 AI anomaly detector (V2).")
    subparsers = parser.add_subparsers(dest="command", required=True)

    train = subparsers.add_parser("train", help="Train the anomaly detector from processed CIC data")
    train.add_argument("--train-csv", type=Path, default=ROOT / "data" / "processed" / "train.csv")
    train.add_argument("--model", type=Path, default=DEFAULT_MODEL_PATH)
    train.add_argument(
        "--threshold-percentile",
        type=float,
        default=93.0,
        help="Percentile of benign training scores used as initial threshold (e.g. 90-97)",
    )
    train.add_argument("--max-train-rows", type=int, default=None, help="Optional cap on rows read from the training CSV")
    train.set_defaults(func=train_command)

    evaluate = subparsers.add_parser("evaluate", help="Evaluate a trained model on processed CIC data")
    evaluate.add_argument("--test-csv", type=Path, default=ROOT / "data" / "processed" / "test.csv")
    evaluate.add_argument("--model", type=Path, default=DEFAULT_MODEL_PATH)
    evaluate.add_argument("--report", type=Path, default=DEFAULT_REPORT_PATH)
    evaluate.add_argument("--max-rows", type=int, default=None, help="Optional cap on rows read from the evaluation CSV")
    evaluate.set_defaults(func=evaluate_command)

    score = subparsers.add_parser("score", help="Write per-row anomaly scores and predictions")
    score.add_argument("--input-csv", type=Path, default=ROOT / "data" / "processed" / "test.csv")
    score.add_argument("--model", type=Path, default=DEFAULT_MODEL_PATH)
    score.add_argument("--output", type=Path, default=DEFAULT_PREDICTIONS_PATH)
    score.add_argument("--max-rows", type=int, default=None, help="Optional cap on rows read from the input CSV")
    score.set_defaults(func=score_command)

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
