#!/usr/bin/env python3
"""
Run repeatable IDS experiments and generate summary reports.

Example:
  python3 tools/run_experiments.py
"""

import csv
import json
import subprocess
import sys
from datetime import datetime, UTC
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / "bin" / "packet_ids"
TRAFFIC_GEN = ROOT / "tools" / "traffic_generator.py"
EVAL_TOOL = ROOT / "tools" / "evaluation_metrics.py"
REPORT_DIR = ROOT / "reports"
LOG_DIR = ROOT / "logs"

ALERTS_CSV = LOG_DIR / "alerts.csv"
ALERTS_JSON = LOG_DIR / "alerts.json"
PERF_CSV = LOG_DIR / "perf_metrics.csv"


def run_cmd(cmd):
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(f"Command failed: {' '.join(str(x) for x in cmd)}\n{result.stderr}\n{result.stdout}")
    return result.stdout


def clean_logs():
    for p in (ALERTS_CSV, ALERTS_JSON, PERF_CSV):
        if p.exists():
            p.unlink()


def read_perf_metrics():
    metrics = {}
    if not PERF_CSV.exists():
        return metrics

    with PERF_CSV.open("r", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            key = row.get("metric", "").strip()
            value = row.get("value", "").strip()
            if key:
                metrics[key] = value

    return metrics


def load_eval_json(path):
    with path.open("r") as f:
        return json.load(f)


def run_case(case_name, pcap_file, threshold, window_seconds, packet_count, extra_args, scenario):
    clean_logs()

    cmd = [
        str(BIN),
        "replay",
        str(pcap_file),
        str(threshold),
        str(window_seconds),
        str(packet_count),
    ] + extra_args

    stdout = run_cmd(cmd)

    eval_output = REPORT_DIR / f"{case_name}_eval.json"
    run_cmd([
        sys.executable,
        str(EVAL_TOOL),
        str(ALERTS_CSV),
        "--scenario",
        scenario,
        "--output",
        str(eval_output),
    ])

    eval_report = load_eval_json(eval_output)
    perf = read_perf_metrics()

    return {
        "case": case_name,
        "threshold": threshold,
        "window_seconds": window_seconds,
        "extra_args": extra_args,
        "alerts": eval_report.get("total_alerts", 0),
        "tpr": eval_report.get("detection_rates", {}).get("tpr", 0.0),
        "fpr": eval_report.get("detection_rates", {}).get("fpr", 0.0),
        "fnr": eval_report.get("detection_rates", {}).get("fnr", 0.0),
        "packets_per_second": perf.get("packets_per_second", "0"),
        "throughput_mbps": perf.get("throughput_mbps", "0"),
        "avg_alert_latency_us": perf.get("avg_alert_latency_us", "0"),
        "stdout_tail": "\n".join(stdout.strip().splitlines()[-6:])
    }


def write_summary(results):
    summary_json = REPORT_DIR / "experiment_summary.json"
    summary_md = REPORT_DIR / "experiment_summary.md"

    payload = {
        "generated_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "results": results,
    }

    with summary_json.open("w") as f:
        json.dump(payload, f, indent=2)

    lines = []
    lines.append("# IDS Experiment Summary")
    lines.append("")
    lines.append(f"Generated at: {payload['generated_at']}")
    lines.append("")
    lines.append("| Case | Alerts | TPR | FPR | FNR | Pkts/s | Mbps | Avg Alert Latency (us) |")
    lines.append("|---|---:|---:|---:|---:|---:|---:|---:|")

    for r in results:
        lines.append(
            f"| {r['case']} | {r['alerts']} | {r['tpr']:.2f} | {r['fpr']:.2f} | {r['fnr']:.2f} | {r['packets_per_second']} | {r['throughput_mbps']} | {r['avg_alert_latency_us']} |"
        )

    lines.append("")
    lines.append("## Notes")
    lines.append("")
    lines.append("- `fixed_baseline`: default fixed-window detector")
    lines.append("- `sliding_baseline`: fixed threshold with `--sliding`")
    lines.append("- `rule_dns_override`: high global threshold + DNS-specific rule override")

    with summary_md.open("w") as f:
        f.write("\n".join(lines) + "\n")

    return summary_json, summary_md


def main():
    REPORT_DIR.mkdir(exist_ok=True)
    LOG_DIR.mkdir(exist_ok=True)

    if not BIN.exists():
        raise RuntimeError("bin/packet_ids not found. Build first with: make app")

    pcap_path = REPORT_DIR / "generated_high_rate.pcap"
    run_cmd([sys.executable, str(TRAFFIC_GEN), str(pcap_path), "--type", "high-rate"])

    cases = [
        {
            "name": "fixed_baseline",
            "threshold": 5,
            "window": 3,
            "count": 200,
            "extra": [],
            "scenario": "high-rate",
        },
        {
            "name": "sliding_baseline",
            "threshold": 5,
            "window": 3,
            "count": 200,
            "extra": ["--sliding"],
            "scenario": "high-rate",
        },
        {
            "name": "rule_dns_override",
            "threshold": 20,
            "window": 3,
            "count": 200,
            "extra": ["--rule", "udp:53:5"],
            "scenario": "high-rate",
        },
    ]

    results = []
    for case in cases:
        result = run_case(
            case_name=case["name"],
            pcap_file=pcap_path,
            threshold=case["threshold"],
            window_seconds=case["window"],
            packet_count=case["count"],
            extra_args=case["extra"],
            scenario=case["scenario"],
        )
        results.append(result)

    summary_json, summary_md = write_summary(results)

    print(f"Wrote summary JSON: {summary_json}")
    print(f"Wrote summary Markdown: {summary_md}")


if __name__ == "__main__":
    main()
