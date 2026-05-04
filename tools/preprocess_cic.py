#!/usr/bin/env python3
"""
Preprocess CIC-IDS2017 day CSVs into clean combined/train/test files.

What it does:
- Reads `data/dataset/*.csv`
- Normalizes header spacing
- Cleans `NaN`, `Infinity`, and blank numeric fields to `0`
- Writes `data/processed/combined.csv`, `train.csv`, and `test.csv`
- Adds a binary `label_bin` column where `BENIGN = 0` and attacks = `1`
- Uses a deterministic stratified split by label without loading the full
  dataset into memory

Usage:
  python3 tools/preprocess_cic.py
  python3 tools/preprocess_cic.py --train-ratio 0.8 --output-dir data/processed
"""

from __future__ import annotations

import argparse
import csv
from collections import defaultdict
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DATASET_DIR = ROOT / "data" / "dataset"
DEFAULT_OUT_DIR = ROOT / "data" / "processed"

_BAD_NUMERIC_VALUES = {"", "nan", "NaN", "inf", "+inf", "-inf", "Infinity", "+Infinity", "-Infinity"}


def find_csv_files(dirpath: Path) -> list[Path]:
    return [p for p in sorted(dirpath.iterdir()) if p.is_file() and p.suffix.lower() == ".csv"]


def canonical_label(value: str | None) -> str:
    if value is None:
        return "BENIGN"
    cleaned = value.strip().upper()
    return cleaned if cleaned else "BENIGN"


def clean_value(value: str | None) -> str:
    if value is None:
        return "0"

    cleaned = value.strip()
    if cleaned in _BAD_NUMERIC_VALUES:
        return "0"

    # Keep labels and string fields readable, but normalize whitespace.
    return cleaned


def read_header(csv_path: Path) -> list[str] | None:
    with csv_path.open(newline="") as fh:
        reader = csv.reader(fh)
        try:
            header = next(reader)
        except StopIteration:
            return None

    normalized = [column.strip() for column in header]
    seen: dict[str, int] = {}
    unique_header: list[str] = []

    for column in normalized:
        count = seen.get(column, 0)
        if count == 0:
            unique_header.append(column)
        else:
            unique_header.append(f"{column}_{count + 1}")
        seen[column] = count + 1

    return unique_header


def build_header(files: list[Path]) -> list[str]:
    for csv_path in files:
        header = read_header(csv_path)
        if header:
            return header
    raise RuntimeError("No non-empty CSV headers found in dataset directory.")


def row_dict(header: list[str], row: list[str]) -> dict[str, str]:
    padded = row[: len(header)] + [""] * max(0, len(header) - len(row))
    return {column: clean_value(value) for column, value in zip(header, padded)}


def count_labels(files: list[Path], header: list[str]) -> dict[str, int]:
    counts: dict[str, int] = defaultdict(int)
    label_index = header.index("Label") if "Label" in header else -1

    for csv_path in files:
        with csv_path.open(newline="") as fh:
            reader = csv.reader(fh)
            try:
                next(reader)
            except StopIteration:
                continue

            for row in reader:
                if not row:
                    continue
                normalized = row_dict(header, row)
                label = canonical_label(normalized.get("Label") if label_index >= 0 else None)
                counts[label] += 1

    return counts


def write_clean_outputs(files: list[Path], header: list[str], out_dir: Path, train_ratio: float) -> tuple[int, int, int]:
    out_dir.mkdir(parents=True, exist_ok=True)

    combined_path = out_dir / "combined.csv"
    train_path = out_dir / "train.csv"
    test_path = out_dir / "test.csv"

    out_header = list(header)
    if "Label" in out_header and "label_bin" not in out_header:
        out_header.append("label_bin")
    if "source_file" not in out_header:
        out_header.append("source_file")

    label_counts = count_labels(files, header)
    train_targets = {label: int(count * train_ratio) for label, count in label_counts.items()}
    train_seen = defaultdict(int)

    combined_rows = 0
    train_rows = 0
    test_rows = 0

    with combined_path.open("w", newline="") as combined_fh, train_path.open("w", newline="") as train_fh, test_path.open(
        "w", newline=""
    ) as test_fh:
        combined_writer = csv.writer(combined_fh)
        train_writer = csv.writer(train_fh)
        test_writer = csv.writer(test_fh)

        combined_writer.writerow(out_header)
        train_writer.writerow(out_header)
        test_writer.writerow(out_header)

        for csv_path in files:
            with csv_path.open(newline="") as fh:
                reader = csv.reader(fh)
                try:
                    next(reader)
                except StopIteration:
                    continue

                for row in reader:
                    if not row:
                        continue

                    normalized = row_dict(header, row)
                    label = canonical_label(normalized.get("Label")) if "Label" in header else "BENIGN"
                    label_bin = "0" if label == "BENIGN" else "1"

                    out_row = [normalized.get(column, "") for column in header]
                    if "Label" in header:
                        out_row.append(label_bin)
                    out_row.append(csv_path.name)

                    combined_writer.writerow(out_row)
                    combined_rows += 1

                    target = train_targets.get(label, 0)
                    if train_seen[label] < target:
                        train_writer.writerow(out_row)
                        train_seen[label] += 1
                        train_rows += 1
                    else:
                        test_writer.writerow(out_row)
                        test_rows += 1

    return train_rows, test_rows, combined_rows


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Preprocess CIC-IDS2017 CSV files.")
    parser.add_argument("--dataset-dir", type=Path, default=DEFAULT_DATASET_DIR, help="Directory with raw CIC CSV files")
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUT_DIR, help="Where to write processed CSV files")
    parser.add_argument("--train-ratio", type=float, default=0.8, help="Fraction of each label to place in train split")
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    if not args.dataset_dir.exists():
        print(f"Dataset directory not found: {args.dataset_dir}")
        return 1

    files = find_csv_files(args.dataset_dir)
    if not files:
        print(f"No CSV files found in: {args.dataset_dir}")
        return 1

    header = build_header(files)
    if "Label" not in header:
        print("Warning: Label column was not found. Binary label output will be omitted.")

    train_rows, test_rows, combined_rows = write_clean_outputs(files, header, args.output_dir, args.train_ratio)

    print(f"Found {len(files)} CSV files in {args.dataset_dir}")
    print(f"Wrote combined dataset: {args.output_dir / 'combined.csv'} ({combined_rows} rows)")
    print(f"Wrote train split: {args.output_dir / 'train.csv'} ({train_rows} rows)")
    print(f"Wrote test split: {args.output_dir / 'test.csv'} ({test_rows} rows)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
