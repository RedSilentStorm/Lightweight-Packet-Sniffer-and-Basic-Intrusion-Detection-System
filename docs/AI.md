# AI pipeline and usage

This document describes how to run the offline AI preprocessing, training, calibration, scoring and evaluation included in this repository.

Key scripts:
- `tools/preprocess_cic.py` — streaming cleaning, header deduplication, stratified split → `data/processed/`
- `tools/cic_ai.py` — train, calibrate (F-beta), evaluate, and score commands (stdlib baseline)

Model and reports (outputs):
- [data/models/cic_anomaly_model.json](data/models/cic_anomaly_model.json)
- [reports/cic_ai_report.json](reports/cic_ai_report.json)
- [reports/cic_predictions.csv](reports/cic_predictions.csv)

Quick start (recommended inside a virtualenv):

```bash
# Create and activate a virtualenv (Debian/Ubuntu: install python3-venv first)
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

1) Preprocess CIC data (writes to `data/processed/`):

```bash
# Note: the script expects `--dataset-dir` and `--output-dir` flags
python3 tools/preprocess_cic.py --dataset-dir data/dataset --output-dir data/processed
```

2) Train + calibrate model (example hyperparams used in experiments):

```bash
# Note: use the `train` subcommand and the `--train-csv` flag
python3 tools/cic_ai.py train --train-csv data/processed/train.csv --train-stride 5 \
	--calibration-stride 10 --calibration-beta 2.0 --model data/models/cic_anomaly_model.json
```

This saves the trained model to `data/models/cic_anomaly_model.json` and calibration/metrics to `reports/`.

3) Evaluate using saved model (optional separate step):

```bash
# Note: use the `evaluate` subcommand and the `--test-csv` / `--report` flags
python3 tools/cic_ai.py evaluate --model data/models/cic_anomaly_model.json \
	--test-csv data/processed/test.csv --report reports/cic_ai_report.json
```

4) Score a CSV (produce per-row anomaly scores/predictions):

```bash
# Note: use the `score` subcommand and the `--input-csv` / `--output` flags
python3 tools/cic_ai.py score --model data/models/cic_anomaly_model.json \
	--input-csv data/processed/combined.csv --output reports/cic_predictions.csv
```

Troubleshooting & environment notes
- If creating a virtualenv fails with "ensurepip is not available", install the system package on Debian/Ubuntu: `sudo apt install python3-venv`.
- If `pip` is missing, install system `pip` via `sudo apt install python3-pip` or use `python3 -m pip install --user -r requirements.txt`.
- Alternative (no venv): install packages for your user:

```bash
python3 -m pip install --user -r requirements.txt
```

Then run the scripts with `python3 tools/...` as shown above.

Notes & next steps:
- The included `tools/cic_ai.py` baseline implementation uses only the Python stdlib for portability; installing the `requirements.txt` allows you to prototype stronger models using `pandas`/`scikit-learn`.
- If you want runtime integration (real-time scoring from the C binary), we can add a lightweight IPC server (Unix socket or HTTP) or a small C client to call into a Python scoring process. Ask if you want me to implement that integration.
