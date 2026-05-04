#!/usr/bin/env python3
"""
Lightweight CIC-IDS2017 anomaly detection pipeline.

This script intentionally uses only the Python standard library so it can run
in a minimal environment. It learns a benign baseline from the processed CIC
CSV files and flags rows whose feature distribution deviates from that baseline.

Commands:
  python3 tools/cic_ai.py train --train-csv data/processed/train.csv --model data/models/cic_anomaly_model.json
  python3 tools/cic_ai.py evaluate --model data/models/cic_anomaly_model.json --test-csv data/processed/test.csv
  python3 tools/cic_ai.py score --model data/models/cic_anomaly_model.json --input data/processed/test.csv --output reports/cic_predictions.csv

The model uses a Gaussian-style anomaly score:
  score(row) = mean(((x_i - mean_i) / std_i) ^ 2)

Rows with score greater than the learned threshold are classified as attacks.
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
DEFAULT_MODEL_PATH = ROOT / "data" / "models" / "cic_anomaly_model.json"
DEFAULT_REPORT_PATH = ROOT / "reports" / "cic_ai_report.json"
DEFAULT_PREDICTIONS_PATH = ROOT / "reports" / "cic_predictions.csv"

NEGATIVE_LABELS = {"0", "BENIGN", "NORMAL"}

# Removed low-discriminatory features:
# - TCP Flag counts (SYN, ACK, FIN, etc.) - 0% delta benign vs attack
# - Bulk rate features (100% zero)
# - Weak features (Down/Up Ratio 4.4%, Init_Win_bytes_forward 3.7%)
# - Min Packet Length (high zero rate, 88.9% delta)
# Added high-impact features:
# - Idle Std (2558% delta)
# - Packet Length Variance (1523% delta)
# - Active Std (772% delta)
# - Fwd IAT Std (246% delta)
# - Idle Max (171% delta)

DEFAULT_FEATURES = [
    # Packet size features (high delta)
    "Bwd Packet Length Max",        # 542.7% delta
    "Bwd Packet Length Mean",       # 406.0% delta
    "Bwd Packet Length Std",        # 408.6% delta
    "Packet Length Max",            # 379.1% delta
    "Packet Length Mean",           # 225.6% delta
    "Packet Length Std",            # 399.0% delta
    "Packet Length Variance",       # 1523.9% delta - CRITICAL
    "Max Packet Length",            # 379.1% delta
    "Average Packet Size",          # 213.5% delta
    "Avg Bwd Segment Size",         # 406.0% delta
    "Avg Fwd Segment Size",         # 64.4% delta
    
    # Flow timing features (high delta)
    "Flow Duration",                # 86.5% delta
    "Flow IAT Max",                 # 351.0% delta
    "Flow IAT Mean",                # 166.6% delta
    "Flow IAT Min",                 # 80.1% delta
    "Flow IAT Std",                 # 343.4% delta
    "Fwd IAT Max",                  # 397.4% delta
    "Fwd IAT Mean",                 # 153.9% delta
    "Fwd IAT Std",                  # 246.3% delta
    "Bwd IAT Max",                  # 143.2% delta
    "Bwd IAT Mean",                 # 22.6% delta
    "Bwd IAT Std",                  # 41.5% delta
    
    # Activity pattern features (very high delta)
    "Idle Std",                     # 2558.6% delta - CRITICAL
    "Idle Max",                     # 171.7% delta
    "Idle Mean",                    # 165.5% delta
    "Active Std",                   # 772.4% delta - CRITICAL
    "Active Max",                   # 61.9% delta
    "Active Mean",                  # 23.2% delta
    
    # Traffic flow features
    "Total Fwd Packets",            # 67.2% delta
    "Total Backward Packets",       # 76.0% delta
    "Total Length of Fwd Packets",  # 77.0% delta
    "Total Length of Bwd Packets",  # 78.0% delta
    "Fwd Packets/s",                # 76.6% delta
    "Bwd Packets/s",                # 91.4% delta
    "Flow Bytes/s",                 # 73.2% delta
    "Flow Packets/s",               # 74.6% delta
    
    # Connection establishment
    "Destination Port",             # 72.0% delta
    "Subflow Fwd Packets",          # 67.2% delta
    "Subflow Bwd Packets",          # 76.0% delta
    "Subflow Fwd Bytes",            # 77.0% delta
    "Subflow Bwd Bytes",            # 78.0% delta
    "Fwd Header Length",            # 60.3% delta
    "Bwd Header Length",            # 69.8% delta
    "Init_Win_bytes_backward",      # 78.3% delta
    "Min Segment Size",             # 2.8% delta
    
    # Activity data
    "act_data_pkt_fwd",             # 77.8% delta
]


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


def transform_value(value: float) -> float:
    if value > 0:
        return math.log1p(value)
    if value < 0:
        return -math.log1p(-value)
    return 0.0


@dataclass
class RunningStats:
    count: int = 0
    mean: float = 0.0
    m2: float = 0.0

    def update(self, value: float) -> None:
        self.count += 1
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


class CICAnomalyModel:
    def __init__(self, feature_names: list[str]):
        self.feature_names = feature_names
        self.feature_means = [0.0 for _ in feature_names]
        self.feature_variances = [1.0 for _ in feature_names]
        self.score_mean = 0.0
        self.score_std = 1.0
        self.threshold = 1.0
        self.threshold_sigma = 4.0
        self.train_rows_seen = 0
        self.train_benign_rows_seen = 0

    @staticmethod
    def _row_label(row: dict[str, str]) -> str:
        if "label_bin" in row:
            return "BENIGN" if canonical_label(row.get("label_bin")) in NEGATIVE_LABELS else "ATTACK"
        return canonical_label(row.get("Label"))

    def _row_vector(self, row: dict[str, str]) -> list[float]:
        return [transform_value(parse_float(row.get(name))) for name in self.feature_names]

    def score_vector(self, vector: list[float]) -> float:
        total = 0.0
        for index, value in enumerate(vector):
            mean = self.feature_means[index]
            variance = self.feature_variances[index]
            z = (value - mean) / math.sqrt(variance) if variance > 0 else 0.0
            total += z * z
        return total / max(1, len(vector))

    def score_row(self, row: dict[str, str]) -> float:
        return self.score_vector(self._row_vector(row))

    def predict_row(self, row: dict[str, str]) -> tuple[float, int]:
        score = self.score_row(row)
        return score, int(score >= self.threshold)

    def fit(
        self,
        csv_path: Path,
        train_stride: int = 1,
        calibration_stride: int = 1,
        beta: float = 2.0,
        max_rows: int | None = None,
    ) -> None:
        feature_stats = [RunningStats() for _ in self.feature_names]
        benign_rows = 0
        total_rows = 0

        with csv_path.open(newline="") as fh:
            reader = csv.DictReader(fh)
            for row in reader:
                total_rows += 1
                if max_rows is not None and total_rows > max_rows:
                    break

                if self._row_label(row) != "BENIGN":
                    continue

                if train_stride > 1 and ((benign_rows + 1) % train_stride) != 0:
                    benign_rows += 1
                    continue

                vector = self._row_vector(row)
                for index, value in enumerate(vector):
                    feature_stats[index].update(value)
                benign_rows += 1

        if benign_rows == 0:
            raise RuntimeError("No BENIGN rows found while fitting the anomaly model.")

        self.feature_means = [stat.mean for stat in feature_stats]
        self.feature_variances = [stat.variance for stat in feature_stats]

        score_stats = RunningStats()
        benign_score_rows = 0
        with csv_path.open(newline="") as fh:
            reader = csv.DictReader(fh)
            for row in reader:
                if self._row_label(row) != "BENIGN":
                    continue

                benign_score_rows += 1
                if train_stride > 1 and (benign_score_rows % train_stride) != 0:
                    continue

                score_stats.update(self.score_row(row))

        self.score_mean = score_stats.mean
        self.score_std = score_stats.stddev
        calibration_scores, calibration_labels = self._collect_calibration_sample(csv_path, calibration_stride, max_rows)
        tuned_threshold = tune_threshold_for_fbeta(calibration_scores, calibration_labels, beta=beta)

        if tuned_threshold is None:
            self.threshold = self.score_mean + (self.threshold_sigma * self.score_std)
        else:
            self.threshold = tuned_threshold

        self.train_rows_seen = total_rows if max_rows is None else min(total_rows, max_rows)
        self.train_benign_rows_seen = benign_rows

    def _collect_calibration_sample(
        self,
        csv_path: Path,
        calibration_stride: int,
        max_rows: int | None,
    ) -> tuple[list[float], list[int]]:
        scores: list[float] = []
        labels: list[int] = []
        seen = 0

        with csv_path.open(newline="") as fh:
            reader = csv.DictReader(fh)
            for row in reader:
                seen += 1
                if max_rows is not None and seen > max_rows:
                    break
                if calibration_stride > 1 and (seen % calibration_stride) != 0:
                    continue

                labels.append(1 if self._row_label(row) != "BENIGN" else 0)
                scores.append(self.score_row(row))

        return scores, labels

    def to_dict(self) -> dict:
        return {
            "version": 1,
            "feature_names": self.feature_names,
            "feature_means": self.feature_means,
            "feature_variances": self.feature_variances,
            "score_mean": self.score_mean,
            "score_std": self.score_std,
            "threshold": self.threshold,
            "threshold_sigma": self.threshold_sigma,
            "train_rows_seen": self.train_rows_seen,
            "train_benign_rows_seen": self.train_benign_rows_seen,
        }

    @classmethod
    def from_dict(cls, payload: dict) -> "CICAnomalyModel":
        feature_names = list(payload.get("feature_names", []))
        model = cls(feature_names)
        model.feature_means = list(payload.get("feature_means", [0.0] * len(feature_names)))
        model.feature_variances = list(payload.get("feature_variances", [1.0] * len(feature_names)))
        model.score_mean = float(payload.get("score_mean", 0.0))
        model.score_std = float(payload.get("score_std", 1.0))
        model.threshold = float(payload.get("threshold", 1.0))
        model.threshold_sigma = float(payload.get("threshold_sigma", 4.0))
        model.train_rows_seen = int(payload.get("train_rows_seen", 0))
        model.train_benign_rows_seen = int(payload.get("train_benign_rows_seen", 0))
        return model


def load_header(csv_path: Path) -> list[str]:
    with csv_path.open(newline="") as fh:
        reader = csv.reader(fh)
        header = next(reader)
    return [column.strip() for column in header]


def infer_feature_names(header: list[str]) -> list[str]:
    available = [name for name in DEFAULT_FEATURES if name in header]
    if available:
        return available

    ignore = {"Label", "label_bin", "source_file"}
    return [name for name in header if name not in ignore]


def load_model(model_path: Path) -> CICAnomalyModel:
    with model_path.open("r") as fh:
        payload = json.load(fh)
    return CICAnomalyModel.from_dict(payload)


def save_model(model: CICAnomalyModel, model_path: Path) -> None:
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

    ranked = sorted(zip(scores, labels), key=lambda item: item[0])
    rank_sum_pos = 0.0
    index = 0
    rank = 1

    while index < len(ranked):
        tie_score = ranked[index][0]
        tie_start = index
        tie_pos = 0
        while index < len(ranked) and ranked[index][0] == tie_score:
            if ranked[index][1] == 1:
                tie_pos += 1
            index += 1

        tie_end = index
        avg_rank = (rank + (rank + (tie_end - tie_start) - 1)) / 2.0
        rank_sum_pos += tie_pos * avg_rank
        rank += tie_end - tie_start

    return (rank_sum_pos - (pos * (pos + 1) / 2.0)) / (pos * neg)


def tune_threshold_for_fbeta(scores: list[float], labels: list[int], beta: float = 2.0) -> float | None:
    if not scores or not labels or len(scores) != len(labels):
        return None

    total_pos = sum(labels)
    total_neg = len(labels) - total_pos
    if total_pos == 0 or total_neg == 0:
        return None

    ranked = sorted(zip(scores, labels), key=lambda item: item[0], reverse=True)
    tp = fp = 0
    best_threshold: float | None = None
    best_score = -1.0
    best_recall = -1.0
    beta_sq = beta * beta

    index = 0
    while index < len(ranked):
        current_score = ranked[index][0]
        while index < len(ranked) and ranked[index][0] == current_score:
            if ranked[index][1] == 1:
                tp += 1
            else:
                fp += 1
            index += 1

        fn = total_pos - tp
        precision = tp / (tp + fp) if (tp + fp) else 0.0
        recall = tp / (tp + fn) if (tp + fn) else 0.0
        fbeta = ((1 + beta_sq) * precision * recall / (beta_sq * precision + recall)) if (precision + recall) else 0.0

        if fbeta > best_score or (fbeta == best_score and recall > best_recall):
            best_score = fbeta
            best_recall = recall
            best_threshold = current_score

    return best_threshold


def load_rows_with_scores(model: CICAnomalyModel, csv_path: Path, max_rows: int | None, stride: int) -> tuple[list[float], list[int]]:
    scores: list[float] = []
    labels: list[int] = []
    seen = 0

    with csv_path.open(newline="") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            seen += 1
            if max_rows is not None and seen > max_rows:
                break

            if stride > 1 and (seen % stride) != 0:
                continue

            label = 1 if model._row_label(row) != "BENIGN" else 0
            score = model.score_row(row)
            scores.append(score)
            labels.append(label)

    return scores, labels


def write_predictions(model: CICAnomalyModel, input_csv: Path, output_csv: Path, max_rows: int | None, stride: int) -> int:
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
            if stride > 1 and (seen % stride) != 0:
                continue

            score, predicted = model.predict_row(row)
            row["anomaly_score"] = f"{score:.6f}"
            row["predicted_label"] = str(predicted)
            writer.writerow(row)
            written += 1

    return written


def print_report(model: CICAnomalyModel, metrics: dict, input_name: str) -> None:
    cm = metrics["confusion_matrix"]
    print("\n" + "=" * 60)
    print("CIC-IDS2017 AI ANOMALY REPORT")
    print("=" * 60)
    print(f"Input: {input_name}")
    print(f"Features used: {len(model.feature_names)}")
    print(f"Threshold: {model.threshold:.6f} (mean={model.score_mean:.6f}, std={model.score_std:.6f}, sigma={model.threshold_sigma:.2f})")
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


def write_report(report_path: Path, model: CICAnomalyModel, metrics: dict, input_path: Path, output_path: Path | None) -> None:
    report_path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "input": str(input_path),
        "output": str(output_path) if output_path else None,
        "model": {
            "features": model.feature_names,
            "threshold": model.threshold,
            "threshold_sigma": model.threshold_sigma,
            "score_mean": model.score_mean,
            "score_std": model.score_std,
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

    model = CICAnomalyModel(feature_names)
    model.threshold_sigma = args.threshold_sigma
    model.fit(
        train_csv,
        train_stride=args.train_stride,
        calibration_stride=args.calibration_stride,
        beta=args.calibration_beta,
        max_rows=args.max_train_rows,
    )
    save_model(model, args.model)

    print(f"Trained AI anomaly model on {train_csv}")
    print(f"Model saved to {args.model}")
    print(f"Features used: {len(model.feature_names)}")
    print(f"Threshold: {model.threshold:.6f}")
    print(f"Benign rows used: {model.train_benign_rows_seen}")
    return 0


def evaluate_command(args: argparse.Namespace) -> int:
    test_csv = args.test_csv
    if not test_csv.exists():
        print(f"Test CSV not found: {test_csv}")
        return 1

    model = load_model(args.model)
    scores, labels = load_rows_with_scores(model, test_csv, args.max_rows, args.eval_stride)
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
    written = write_predictions(model, input_csv, args.output, args.max_rows, args.eval_stride)
    print(f"Wrote {written} scored rows to {args.output}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Train and evaluate a lightweight CIC-IDS2017 AI anomaly detector.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    train = subparsers.add_parser("train", help="Train the anomaly detector from processed CIC data")
    train.add_argument("--train-csv", type=Path, default=ROOT / "data" / "processed" / "train.csv")
    train.add_argument("--model", type=Path, default=DEFAULT_MODEL_PATH)
    train.add_argument("--threshold-sigma", type=float, default=4.0)
    train.add_argument("--train-stride", type=int, default=5, help="Use every Nth benign row to speed up training")
    train.add_argument("--calibration-stride", type=int, default=5, help="Use every Nth row to tune the anomaly threshold")
    train.add_argument("--calibration-beta", type=float, default=2.0, help="F-beta score used when tuning the threshold")
    train.add_argument("--max-train-rows", type=int, default=None, help="Optional cap on rows read from the training CSV")
    train.set_defaults(func=train_command)

    evaluate = subparsers.add_parser("evaluate", help="Evaluate a trained model on processed CIC data")
    evaluate.add_argument("--test-csv", type=Path, default=ROOT / "data" / "processed" / "test.csv")
    evaluate.add_argument("--model", type=Path, default=DEFAULT_MODEL_PATH)
    evaluate.add_argument("--report", type=Path, default=DEFAULT_REPORT_PATH)
    evaluate.add_argument("--eval-stride", type=int, default=1, help="Use every Nth row during evaluation")
    evaluate.add_argument("--max-rows", type=int, default=None, help="Optional cap on rows read from the evaluation CSV")
    evaluate.set_defaults(func=evaluate_command)

    score = subparsers.add_parser("score", help="Write per-row anomaly scores and predictions")
    score.add_argument("--input-csv", type=Path, default=ROOT / "data" / "processed" / "test.csv")
    score.add_argument("--model", type=Path, default=DEFAULT_MODEL_PATH)
    score.add_argument("--output", type=Path, default=DEFAULT_PREDICTIONS_PATH)
    score.add_argument("--eval-stride", type=int, default=1, help="Use every Nth row while writing predictions")
    score.add_argument("--max-rows", type=int, default=None, help="Optional cap on rows read from the input CSV")
    score.set_defaults(func=score_command)

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())