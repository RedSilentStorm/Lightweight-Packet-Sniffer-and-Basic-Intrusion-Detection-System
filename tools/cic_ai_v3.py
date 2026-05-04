#!/usr/bin/env python3
"""CIC-IDS2017 supervised IDS model (V3).

This version uses a class-balanced supervised model to improve recall while
keeping precision high. It is designed to be run with the project virtualenv:
  .venv/bin/python tools/cic_ai_v3.py train
  .venv/bin/python tools/cic_ai_v3.py evaluate

Model:
- HistGradientBoostingClassifier
- Balanced sampling from training CSV
- Threshold tuning on a validation split with precision-first objective
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import pickle
import random
from pathlib import Path

import numpy as np
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.metrics import roc_auc_score


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MODEL_PATH = ROOT / "data" / "models" / "cic_supervised_model_v3.pkl"
DEFAULT_REPORT_PATH = ROOT / "reports" / "cic_ai_report_v3.json"
DEFAULT_PREDICTIONS_PATH = ROOT / "reports" / "cic_predictions_v3.csv"

NEGATIVE_LABELS = {"0", "BENIGN", "NORMAL"}

FEATURES_V3 = [
    "Idle Std",
    "Packet Length Variance",
    "Active Std",
    "Bwd Packet Length Max",
    "Bwd Packet Length Std",
    "Packet Length Std",
    "Fwd IAT Max",
    "Max Packet Length",
    "Flow IAT Max",
    "Avg Bwd Segment Size",
    "Fwd IAT Std",
    "Idle Max",
    "Bwd Packet Length Mean",
    "Packet Length Mean",
    "Average Packet Size",
    "Flow Duration",
    "Total Backward Packets",
    "Total Fwd Packets",
    "Total Length of Fwd Packets",
    "Total Length of Bwd Packets",
    "Flow IAT Mean",
    "Flow IAT Std",
    "Fwd IAT Mean",
    "Bwd IAT Max",
    "Bwd Packets/s",
    "Fwd Packets/s",
    "Destination Port",
    "Init_Win_bytes_backward",
    "Subflow Fwd Bytes",
    "Subflow Bwd Bytes",
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


def row_label(row: dict[str, str]) -> int:
    if "label_bin" in row:
        return 0 if canonical_label(row.get("label_bin")) in NEGATIVE_LABELS else 1
    return 0 if canonical_label(row.get("Label")) in NEGATIVE_LABELS else 1


def row_vector(row: dict[str, str], features: list[str]) -> list[float]:
    return [parse_float(row.get(name)) for name in features]


def sample_training_rows(
    csv_path: Path,
    features: list[str],
    max_attack_rows: int,
    max_benign_rows: int,
    seed: int,
) -> tuple[np.ndarray, np.ndarray]:
    rng = random.Random(seed)
    attacks: list[list[float]] = []
    benigns: list[list[float]] = []

    with csv_path.open(newline="") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            label = row_label(row)
            vec = row_vector(row, features)
            if label == 1:
                if len(attacks) < max_attack_rows:
                    attacks.append(vec)
                else:
                    j = rng.randint(0, len(attacks))
                    if j < max_attack_rows:
                        attacks[j] = vec
            else:
                if len(benigns) < max_benign_rows:
                    benigns.append(vec)
                else:
                    j = rng.randint(0, len(benigns))
                    if j < max_benign_rows:
                        benigns[j] = vec

    x = np.asarray(benigns + attacks, dtype=np.float32)
    y = np.asarray(([0] * len(benigns)) + ([1] * len(attacks)), dtype=np.int8)

    # Shuffle once.
    idx = np.arange(len(y))
    rng.shuffle(idx)
    x = x[idx]
    y = y[idx]
    return x, y


def train_val_split(x: np.ndarray, y: np.ndarray, val_ratio: float, seed: int) -> tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
    rng = np.random.default_rng(seed)
    idx = np.arange(len(y))
    rng.shuffle(idx)
    split = int(len(y) * (1.0 - val_ratio))
    train_idx = idx[:split]
    val_idx = idx[split:]
    return x[train_idx], y[train_idx], x[val_idx], y[val_idx]


def evaluate_scores(scores: np.ndarray, labels: np.ndarray, threshold: float) -> dict:
    preds = (scores >= threshold).astype(np.int8)

    tp = int(np.sum((preds == 1) & (labels == 1)))
    fp = int(np.sum((preds == 1) & (labels == 0)))
    tn = int(np.sum((preds == 0) & (labels == 0)))
    fn = int(np.sum((preds == 0) & (labels == 1)))

    total = len(labels)
    accuracy = (tp + tn) / total if total else 0.0
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    roc_auc = float(roc_auc_score(labels, scores)) if len(np.unique(labels)) > 1 else 0.0

    return {
        "total": total,
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "roc_auc": roc_auc,
        "confusion_matrix": {"tp": tp, "fp": fp, "tn": tn, "fn": fn},
    }


def tune_threshold(scores: np.ndarray, labels: np.ndarray, min_recall: float) -> tuple[float, dict, str]:
    percentiles = [p / 10.0 for p in range(700, 996, 5)]  # 70.0 .. 99.5
    cands: list[tuple[float, float, dict]] = []
    constrained: list[tuple[float, float, dict]] = []

    for p in percentiles:
        t = float(np.percentile(scores, p))
        m = evaluate_scores(scores, labels, t)
        cands.append((p, t, m))
        if m["recall"] >= min_recall:
            constrained.append((p, t, m))

    if constrained:
        best_p, best_t, best_m = sorted(
            constrained,
            key=lambda x: (x[2]["precision"], -x[2]["confusion_matrix"]["fp"], x[2]["f1"]),
            reverse=True,
        )[0]
        return best_t, best_m, f"precision-first (min_recall={min_recall:.2f}, percentile={best_p:.1f})"

    # Fallback: best F1.
    best_p, best_t, best_m = sorted(cands, key=lambda x: x[2]["f1"], reverse=True)[0]
    return best_t, best_m, f"fallback-f1 (percentile={best_p:.1f})"


def save_model(payload: dict, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as fh:
        pickle.dump(payload, fh)


def load_model(path: Path) -> dict:
    with path.open("rb") as fh:
        return pickle.load(fh)


def predict_scores_on_csv(model_obj: HistGradientBoostingClassifier, csv_path: Path, features: list[str]) -> tuple[np.ndarray, np.ndarray]:
    scores: list[float] = []
    labels: list[int] = []

    with csv_path.open(newline="") as fh:
        reader = csv.DictReader(fh)
        batch_x: list[list[float]] = []
        batch_y: list[int] = []

        for row in reader:
            batch_x.append(row_vector(row, features))
            batch_y.append(row_label(row))
            if len(batch_x) >= 8192:
                arr = np.asarray(batch_x, dtype=np.float32)
                prob = model_obj.predict_proba(arr)[:, 1]
                scores.extend(prob.tolist())
                labels.extend(batch_y)
                batch_x.clear()
                batch_y.clear()

        if batch_x:
            arr = np.asarray(batch_x, dtype=np.float32)
            prob = model_obj.predict_proba(arr)[:, 1]
            scores.extend(prob.tolist())
            labels.extend(batch_y)

    return np.asarray(scores, dtype=np.float32), np.asarray(labels, dtype=np.int8)


def write_report(report_path: Path, model_info: dict, metrics: dict, input_path: Path, output_path: Path | None) -> None:
    report_path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "input": str(input_path),
        "output": str(output_path) if output_path else None,
        "model": model_info,
        "metrics": metrics,
    }
    with report_path.open("w") as fh:
        json.dump(payload, fh, indent=2)


def write_predictions(model_payload: dict, input_csv: Path, output_csv: Path) -> int:
    features = model_payload["features"]
    model = model_payload["model"]
    threshold = model_payload["threshold"]

    output_csv.parent.mkdir(parents=True, exist_ok=True)
    written = 0

    with input_csv.open(newline="") as in_fh, output_csv.open("w", newline="") as out_fh:
        reader = csv.DictReader(in_fh)
        fieldnames = list(reader.fieldnames or []) + ["attack_probability", "predicted_label"]
        writer = csv.DictWriter(out_fh, fieldnames=fieldnames)
        writer.writeheader()

        batch_rows: list[dict[str, str]] = []
        batch_x: list[list[float]] = []

        def flush_batch() -> None:
            nonlocal written
            if not batch_rows:
                return
            probs = model.predict_proba(np.asarray(batch_x, dtype=np.float32))[:, 1]
            for r, p in zip(batch_rows, probs):
                r["attack_probability"] = f"{float(p):.6f}"
                r["predicted_label"] = "1" if float(p) >= threshold else "0"
                writer.writerow(r)
                written += 1
            batch_rows.clear()
            batch_x.clear()

        for row in reader:
            batch_rows.append(row)
            batch_x.append(row_vector(row, features))
            if len(batch_rows) >= 8192:
                flush_batch()

        flush_batch()

    return written


def train_command(args: argparse.Namespace) -> int:
    x, y = sample_training_rows(
        args.train_csv,
        FEATURES_V3,
        max_attack_rows=args.max_attack_rows,
        max_benign_rows=args.max_benign_rows,
        seed=args.seed,
    )

    if len(y) == 0:
        raise RuntimeError("No rows sampled for training.")

    x_train, y_train, x_val, y_val = train_val_split(x, y, val_ratio=args.val_ratio, seed=args.seed)

    # Inverse-frequency sample weights for class balance.
    pos = max(1, int(np.sum(y_train == 1)))
    neg = max(1, int(np.sum(y_train == 0)))
    w_pos = (len(y_train) / (2.0 * pos))
    w_neg = (len(y_train) / (2.0 * neg))
    sample_weight = np.where(y_train == 1, w_pos, w_neg).astype(np.float32)

    clf = HistGradientBoostingClassifier(
        learning_rate=args.learning_rate,
        max_iter=args.max_iter,
        max_depth=args.max_depth,
        min_samples_leaf=args.min_samples_leaf,
        l2_regularization=args.l2,
        random_state=args.seed,
    )
    clf.fit(x_train, y_train, sample_weight=sample_weight)

    val_scores = clf.predict_proba(x_val)[:, 1]
    threshold, val_metrics, selection_mode = tune_threshold(val_scores, y_val, min_recall=args.min_recall)

    model_payload = {
        "version": 3,
        "features": FEATURES_V3,
        "threshold": float(threshold),
        "selection_mode": selection_mode,
        "train_config": {
            "max_attack_rows": args.max_attack_rows,
            "max_benign_rows": args.max_benign_rows,
            "val_ratio": args.val_ratio,
            "learning_rate": args.learning_rate,
            "max_iter": args.max_iter,
            "max_depth": args.max_depth,
            "min_samples_leaf": args.min_samples_leaf,
            "l2": args.l2,
            "seed": args.seed,
            "min_recall": args.min_recall,
        },
        "validation_metrics": val_metrics,
        "model": clf,
    }

    save_model(model_payload, args.model)

    print(f"Trained supervised V3 model on sampled train data: {len(y)} rows")
    print(f"Model saved to {args.model}")
    print(f"Features used: {len(FEATURES_V3)}")
    print(f"Threshold: {threshold:.6f}")
    print(f"Selection mode: {selection_mode}")
    print(
        "Validation metrics: "
        f"P={val_metrics['precision']:.4f}, "
        f"R={val_metrics['recall']:.4f}, "
        f"F1={val_metrics['f1']:.4f}, "
        f"AUC={val_metrics['roc_auc']:.4f}"
    )
    return 0


def evaluate_command(args: argparse.Namespace) -> int:
    payload = load_model(args.model)
    features = payload["features"]
    threshold = float(payload["threshold"])
    clf = payload["model"]

    scores, labels = predict_scores_on_csv(clf, args.test_csv, features)
    metrics = evaluate_scores(scores, labels, threshold)

    cm = metrics["confusion_matrix"]
    print("\n" + "=" * 60)
    print("CIC-IDS2017 AI SUPERVISED REPORT (V3)")
    print("=" * 60)
    print(f"Input: {args.test_csv}")
    print(f"Features used: {len(features)}")
    print(f"Threshold: {threshold:.6f}")
    print(f"Selection mode: {payload.get('selection_mode', 'n/a')}")
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

    write_report(
        args.report,
        {
            "version": payload.get("version", 3),
            "features": features,
            "threshold": threshold,
            "selection_mode": payload.get("selection_mode"),
            "train_config": payload.get("train_config"),
            "validation_metrics": payload.get("validation_metrics"),
        },
        metrics,
        args.test_csv,
        None,
    )
    print(f"Report written to {args.report}")
    return 0


def score_command(args: argparse.Namespace) -> int:
    payload = load_model(args.model)
    written = write_predictions(payload, args.input_csv, args.output)
    print(f"Wrote {written} scored rows to {args.output}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Train/evaluate supervised CIC IDS model (V3)")
    sub = parser.add_subparsers(dest="command", required=True)

    train = sub.add_parser("train", help="Train supervised V3 model")
    train.add_argument("--train-csv", type=Path, default=ROOT / "data" / "processed" / "train.csv")
    train.add_argument("--model", type=Path, default=DEFAULT_MODEL_PATH)
    train.add_argument("--max-attack-rows", type=int, default=250_000)
    train.add_argument("--max-benign-rows", type=int, default=350_000)
    train.add_argument("--val-ratio", type=float, default=0.2)
    train.add_argument("--learning-rate", type=float, default=0.08)
    train.add_argument("--max-iter", type=int, default=250)
    train.add_argument("--max-depth", type=int, default=8)
    train.add_argument("--min-samples-leaf", type=int, default=60)
    train.add_argument("--l2", type=float, default=1.0)
    train.add_argument("--seed", type=int, default=42)
    train.add_argument("--min-recall", type=float, default=0.40)
    train.set_defaults(func=train_command)

    evaluate = sub.add_parser("evaluate", help="Evaluate supervised V3 model")
    evaluate.add_argument("--test-csv", type=Path, default=ROOT / "data" / "processed" / "test.csv")
    evaluate.add_argument("--model", type=Path, default=DEFAULT_MODEL_PATH)
    evaluate.add_argument("--report", type=Path, default=DEFAULT_REPORT_PATH)
    evaluate.set_defaults(func=evaluate_command)

    score = sub.add_parser("score", help="Score CSV rows with V3 model")
    score.add_argument("--input-csv", type=Path, default=ROOT / "data" / "processed" / "test.csv")
    score.add_argument("--model", type=Path, default=DEFAULT_MODEL_PATH)
    score.add_argument("--output", type=Path, default=DEFAULT_PREDICTIONS_PATH)
    score.set_defaults(func=score_command)

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
