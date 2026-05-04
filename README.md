# Lightweight Packet Sniffer + Basic IDS (C + libpcap)

A modular C project that captures traffic, parses packet headers manually, and raises simple IDS alerts when a source IP exceeds a packet threshold within a time window.

## Features

- Live packet capture with libpcap
- Manual parsing of Ethernet, IPv4, IPv6, TCP, and UDP headers
- Source/destination IP extraction for IPv4 and IPv6
- TCP/UDP source/destination port extraction
- Per-source IP counters in a time window
- Rule-based IDS alert:
  - Trigger when source sends more than `X` packets in `Y` seconds
  - Window mode can be fixed (default) or sliding (`--sliding` token-bucket)
  - Optional per-protocol/per-port threshold overrides (`--rule <proto:port:threshold>`)
- Alert logging to both console and `logs/alerts.log`
- Optional BPF filters for live/replay capture
- Offline replay mode from `.pcap` files (no root required)
- Deterministic integration test for end-to-end alert behavior

## Project Layout

- `include/` -> headers for parser, tracker, logger, and utilities
- `src/` -> implementations and CLI application
- `tests/` -> deterministic unit/integration tests
- `logs/` -> runtime alert log output
- `bin/` -> compiled binaries

## Build

```bash
make app
```

Main binary:

```bash
./bin/packet_ids
```

## CLI Commands

### 1) List interfaces

```bash
./bin/packet_ids list
```

Expected output (example):

```text
Available network interfaces:
1) ens33
2) any - Pseudo-device that captures on all interfaces
...
```

### 2) Live capture + IDS

```bash
./bin/packet_ids live <interface> <threshold> <window_seconds> [packet_count] [--filter <bpf_expr>] [--sliding] [--rule <proto:port:threshold>]...
```

Example:

```bash
sudo ./bin/packet_ids live ens33 20 5 200
```

If not using `sudo`, grant capture capability once:

```bash
sudo setcap cap_net_raw,cap_net_admin=eip ./bin/packet_ids
```

### 3) Replay from pcap (no root)

```bash
./bin/packet_ids replay <pcap_file> <threshold> <window_seconds> [packet_count] [--filter <bpf_expr>] [--sliding] [--rule <proto:port:threshold>]...
```

Example with a filter:

```bash
./bin/packet_ids replay tests/data/test_burst.pcap 3 5 10 --filter "tcp or udp"
```

Example with rule overrides (DNS tighter than default):

```bash
./bin/packet_ids replay tests/data/test_burst.pcap 20 5 200 --rule udp:53:3 --rule tcp:443:40
```

Example:

```bash
./bin/packet_ids replay tests/data/ids_sample.pcap 3 5 10
```

Expected alert line (example):

```text
[YYYY-MM-DD HH:MM:SS] ALERT: source=10.0.0.9 protocol=UDP src_port=40003 dst=10.0.0.1:53 count=4 threshold=3 elapsed=3s window=5s
```

### 4) Internal self-test (IDS tracker logic)

```bash
./bin/packet_ids test
```

Expected output:

```text
Self-test passed. IDS tracker behavior is correct.
```

## Demo Targets (Learning Flow)

You can still run the intermediate binaries:

```bash
make setup_check
make list_interfaces
make capture_basic
make parse_headers_demo
make ids_rule_demo
make tracker_test
make rule_engine_test
make replay_demo
make integration_test
```

## End-to-End Test (No Root)

```bash
make integration_test
```

This target:

1. Creates a deterministic sample pcap at `tests/data/ids_sample.pcap`
2. Runs replay mode through the IDS pipeline
3. Verifies alert presence in stdout and in `logs/alerts.log`

## Experiment Automation

Run a repeatable experiment batch and generate summary artifacts:

```bash
python3 tools/run_experiments.py
```

Outputs:

- `reports/experiment_summary.json`
- `reports/experiment_summary.md`
- per-case evaluation JSON files in `reports/`

## Notes

- The IDS rule is intentionally simple for learning:
  - Alert when `count > threshold` during the current `window_seconds`
- One alert is emitted per source IP per active window.
- Counters reset when the source enters a new time window.
- IPv6 packets are parsed and can participate in alerting and export.

### Window Modes

- Default (fixed): counter resets when the current fixed window expires.
- Optional sliding (`--sliding`): token-bucket approximation of a sliding window.

### Rule Overrides

- Rule format: `proto:port:threshold`
- `proto`: `tcp`, `udp`, `icmp`, `any`, or numeric protocol id
- `port`: destination/source port number (`1..65535`) or `any`
- `threshold`: positive integer threshold for matching traffic

## AI Quick Prerequisites

- Ensure your system has `python3-venv` and `python3-pip` installed if you want to use a virtual environment and `pip`:

```bash
sudo apt update
sudo apt install python3-venv python3-pip
```

If you cannot install system packages, use `python3 -m pip install --user -r requirements.txt` instead of creating a virtualenv.

See `docs/AI.md` for corrected CLI examples for `tools/preprocess_cic.py` and `tools/cic_ai.py`.

## AI Usage

Offline AI preprocessing, training, scoring and evaluation are available. See [docs/AI.md](docs/AI.md) for full commands and paths to model and report artifacts.

### Final Default Model (One Command)

After promoting the final model to `data/models/cic_supervised_model_v3.pkl`, run:

```bash
make ai_default
```

This runs both:

- evaluation report -> `reports/cic_ai_report_v3.json`
- scored test CSV -> `reports/candidate_default_eval.csv`

Optional single-step targets:

```bash
make ai_eval
make ai_score
```

If your virtualenv is in a different path, override python executable:

```bash
make ai_default PYTHON=python3
```

