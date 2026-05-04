#!/usr/bin/env python3

from __future__ import annotations

import html
import os
import re
import shlex
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

from PySide6.QtCore import QProcess, QTimer, Qt
from PySide6.QtGui import QFont, QTextCursor
from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QComboBox,
    QFileDialog,
    QFrame,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QPlainTextEdit,
    QSpinBox,
    QSplitter,
    QStatusBar,
    QTabWidget,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)


REPO_ROOT = Path(__file__).resolve().parents[1]
APP_BINARY = REPO_ROOT / "bin" / "packet_ids"


FEATURE_COMMANDS: list[tuple[str, str, str]] = [
    ("Setup Check", "setup_check", "Verify libpcap and capture setup"),
    ("Interfaces", "list_interfaces", "List network interfaces"),
    ("Capture Basic", "capture_basic", "Basic live capture demo"),
    ("Parse Demo", "parse_headers_demo", "Header parsing demonstration"),
    ("IDS Rule Demo", "ids_rule_demo", "Rule-based IDS demo"),
    ("Tracker Test", "tracker_test", "IDS tracker unit test"),
    ("Rule Engine Test", "rule_engine_test", "Rule engine unit test"),
    ("Replay Demo", "replay_demo", "Live or pcap replay demo"),
    ("Integration Test", "integration_test", "Deterministic end-to-end validation"),
    ("AI Eval", "ai_eval", "Run AI evaluation report"),
    ("AI Score", "ai_score", "Score the test CSV"),
    ("AI Default", "ai_default", "Run evaluation and scoring together"),
]


@dataclass
class InterfaceEntry:
    name: str
    description: str | None = None


def parse_interfaces(output: str) -> list[InterfaceEntry]:
    interfaces: list[InterfaceEntry] = []
    for line in output.splitlines():
        match = re.match(r"^\d+\)\s*(\S+)(?:\s+-\s+(.*))?$", line.strip())
        if not match:
            continue
        interfaces.append(InterfaceEntry(match.group(1), match.group(2)))
    return interfaces


class DesktopUi(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.process: QProcess | None = None
        self.interfaces: list[InterfaceEntry] = []
        self.last_output: list[str] = []
        self.stop_requested = False
        self.setWindowTitle("Packet IDS Control Panel")
        self.setMinimumSize(1200, 760)
        self._build_ui()
        self._apply_theme()
        self.refresh_interfaces()

    def _build_ui(self) -> None:
        root = QWidget()
        self.setCentralWidget(root)
        outer = QVBoxLayout(root)
        outer.setContentsMargins(20, 20, 20, 20)
        outer.setSpacing(16)

        header = QFrame()
        header_layout = QHBoxLayout(header)
        header_layout.setContentsMargins(0, 0, 0, 0)

        title_block = QVBoxLayout()
        title = QLabel("Packet IDS Control Panel")
        title.setObjectName("title")
        subtitle = QLabel("Local desktop app for live capture and pcap replay")
        subtitle.setObjectName("subtitle")
        title_block.addWidget(title)
        title_block.addWidget(subtitle)
        header_layout.addLayout(title_block)
        header_layout.addStretch(1)

        self.status_chip = QLabel("Idle")
        self.status_chip.setObjectName("statusChip")
        self.status_chip.setAlignment(Qt.AlignCenter)
        self.status_chip.setMinimumWidth(120)
        header_layout.addWidget(self.status_chip)
        outer.addWidget(header)

        tabs = QTabWidget()
        outer.addWidget(tabs, 1)

        capture_panel = QWidget()
        controls_layout = QVBoxLayout(capture_panel)
        controls_layout.setContentsMargins(0, 0, 0, 0)
        controls_layout.setSpacing(14)

        mode_box = QGroupBox("Mode")
        mode_layout = QHBoxLayout(mode_box)
        self.live_button = QPushButton("Live")
        self.live_button.setCheckable(True)
        self.replay_button = QPushButton("Replay")
        self.replay_button.setCheckable(True)
        self.replay_button.setChecked(True)
        self.live_button.toggled.connect(self._sync_mode_buttons)
        self.live_button.toggled.connect(self._sync_mode_ui)
        self.replay_button.toggled.connect(self._sync_mode_buttons)
        self.replay_button.toggled.connect(self._sync_mode_ui)
        mode_layout.addWidget(self.live_button)
        mode_layout.addWidget(self.replay_button)
        mode_layout.addStretch(1)
        controls_layout.addWidget(mode_box)

        source_box = QGroupBox("Capture Source")
        source_grid = QGridLayout(source_box)
        source_grid.setHorizontalSpacing(10)
        source_grid.setVerticalSpacing(10)

        self.source_label = QLabel("PCAP File")
        self.source_edit = QLineEdit(str(REPO_ROOT / "tests" / "data" / "ids_sample.pcap"))
        self.source_edit.setPlaceholderText("Choose a pcap for replay or an interface for live capture")
        self.interface_combo = QComboBox()
        self.interface_combo.currentIndexChanged.connect(self._interface_selected)
        self.refresh_button = QPushButton("Refresh")
        self.refresh_button.clicked.connect(self.refresh_interfaces)
        self.browse_button = QPushButton("Browse")
        self.browse_button.clicked.connect(self.browse_pcap)

        source_grid.addWidget(self.source_label, 0, 0)
        source_grid.addWidget(self.source_edit, 0, 1, 1, 2)
        source_grid.addWidget(QLabel("Interfaces"), 1, 0)
        source_grid.addWidget(self.interface_combo, 1, 1)
        source_grid.addWidget(self.refresh_button, 1, 2)
        source_grid.addWidget(self.browse_button, 2, 2)
        controls_layout.addWidget(source_box)

        tuning_box = QGroupBox("IDS Settings")
        tuning_grid = QGridLayout(tuning_box)
        tuning_grid.setHorizontalSpacing(10)
        tuning_grid.setVerticalSpacing(10)

        self.threshold_spin = QSpinBox()
        self.threshold_spin.setRange(1, 100000)
        self.threshold_spin.setValue(3)
        self.window_spin = QSpinBox()
        self.window_spin.setRange(1, 3600)
        self.window_spin.setValue(5)
        self.packet_count_spin = QSpinBox()
        self.packet_count_spin.setRange(1, 1000000)
        self.packet_count_spin.setValue(10)
        self.filter_edit = QLineEdit()
        self.filter_edit.setPlaceholderText("tcp or udp")
        self.sliding_check = QCheckBox("Sliding window")

        self.rules_edit = QPlainTextEdit()
        self.rules_edit.setPlaceholderText("One override per line: proto:port:threshold\nExample: udp:53:3")
        self.rules_edit.setFixedHeight(96)

        tuning_grid.addWidget(QLabel("Threshold"), 0, 0)
        tuning_grid.addWidget(self.threshold_spin, 0, 1)
        tuning_grid.addWidget(QLabel("Window (s)"), 0, 2)
        tuning_grid.addWidget(self.window_spin, 0, 3)
        tuning_grid.addWidget(QLabel("Packets"), 1, 0)
        tuning_grid.addWidget(self.packet_count_spin, 1, 1)
        tuning_grid.addWidget(self.sliding_check, 1, 2, 1, 2)
        tuning_grid.addWidget(QLabel("BPF Filter"), 2, 0)
        tuning_grid.addWidget(self.filter_edit, 2, 1, 1, 3)
        tuning_grid.addWidget(QLabel("Rule Overrides"), 3, 0)
        tuning_grid.addWidget(self.rules_edit, 3, 1, 1, 3)
        controls_layout.addWidget(tuning_box)

        action_row = QHBoxLayout()
        self.start_button = QPushButton("Start")
        self.start_button.clicked.connect(self.start_capture)
        self.stop_button = QPushButton("Stop")
        self.stop_button.setEnabled(False)
        self.stop_button.clicked.connect(self.stop_capture)
        self.clear_button = QPushButton("Clear Log")
        self.clear_button.clicked.connect(self._clear_log)
        action_row.addWidget(self.start_button)
        action_row.addWidget(self.stop_button)
        action_row.addWidget(self.clear_button)
        action_row.addStretch(1)
        controls_layout.addLayout(action_row)

        hint = QLabel("Live mode may require elevated capture permissions. Replay mode is the easiest way to validate the UI.")
        hint.setObjectName("hint")
        hint.setWordWrap(True)
        controls_layout.addWidget(hint)

        self.permission_hint = QLabel()
        self.permission_hint.setObjectName("permissionHint")
        self.permission_hint.setWordWrap(True)
        controls_layout.addWidget(self.permission_hint)
        controls_layout.addStretch(1)

        features_panel = QWidget()
        features_layout = QVBoxLayout(features_panel)
        features_layout.setContentsMargins(0, 0, 0, 0)
        features_layout.setSpacing(14)

        launcher_box = QGroupBox("Feature Launcher")
        launcher_layout = QGridLayout(launcher_box)
        launcher_layout.setHorizontalSpacing(10)
        launcher_layout.setVerticalSpacing(10)
        for index, (label, action, description) in enumerate(FEATURE_COMMANDS):
            button = QPushButton(label)
            button.setToolTip(description)
            button.clicked.connect(lambda checked=False, value=action: self.run_feature(value))
            row = index // 3
            column = index % 3
            launcher_layout.addWidget(button, row, column)
        features_layout.addWidget(launcher_box)

        ai_box = QGroupBox("AI Paths")
        ai_grid = QGridLayout(ai_box)
        ai_grid.setHorizontalSpacing(10)
        ai_grid.setVerticalSpacing(10)
        self.ai_python_edit = QLineEdit(str(REPO_ROOT / ".venv" / "bin" / "python"))
        self.ai_model_edit = QLineEdit("data/models/cic_supervised_model_v3.pkl")
        self.ai_test_csv_edit = QLineEdit("data/processed/test.csv")
        self.ai_report_edit = QLineEdit("reports/cic_ai_report_v3.json")
        self.ai_score_out_edit = QLineEdit("reports/candidate_default_eval.csv")
        ai_grid.addWidget(QLabel("Python"), 0, 0)
        ai_grid.addWidget(self.ai_python_edit, 0, 1)
        ai_grid.addWidget(QLabel("Model"), 1, 0)
        ai_grid.addWidget(self.ai_model_edit, 1, 1)
        ai_grid.addWidget(QLabel("Test CSV"), 2, 0)
        ai_grid.addWidget(self.ai_test_csv_edit, 2, 1)
        ai_grid.addWidget(QLabel("Report"), 3, 0)
        ai_grid.addWidget(self.ai_report_edit, 3, 1)
        ai_grid.addWidget(QLabel("Score Out"), 4, 0)
        ai_grid.addWidget(self.ai_score_out_edit, 4, 1)

        ai_actions = QHBoxLayout()
        self.ai_eval_button = QPushButton("Run AI Eval")
        self.ai_eval_button.clicked.connect(self.run_ai_eval)
        self.ai_score_button = QPushButton("Run AI Score")
        self.ai_score_button.clicked.connect(self.run_ai_score)
        self.ai_default_button = QPushButton("Run AI Default")
        self.ai_default_button.clicked.connect(self.run_ai_default)
        ai_actions.addWidget(self.ai_eval_button)
        ai_actions.addWidget(self.ai_score_button)
        ai_actions.addWidget(self.ai_default_button)
        ai_actions.addStretch(1)
        features_layout.addWidget(ai_box)
        features_layout.addLayout(ai_actions)
        features_layout.addStretch(1)

        log_panel = QWidget()
        log_layout = QVBoxLayout(log_panel)
        log_layout.setContentsMargins(0, 0, 0, 0)
        log_layout.setSpacing(10)

        log_title = QLabel("Execution Log")
        log_title.setObjectName("panelTitle")
        self.log_view = QTextEdit()
        self.log_view.setReadOnly(True)
        self.log_view.setUndoRedoEnabled(False)
        self.log_view.setLineWrapMode(QTextEdit.NoWrap)
        self.log_view.document().setMaximumBlockCount(2000)
        self.log_view.setFont(QFont("DejaVu Sans Mono", 10))
        log_layout.addWidget(log_title)
        log_layout.addWidget(self.log_view, 1)

        tabs.addTab(capture_panel, "Capture")
        tabs.addTab(features_panel, "All Features")

        outer.addWidget(log_panel, 1)

        self.setStatusBar(QStatusBar())
        self.statusBar().showMessage("Ready")
        self._sync_mode_ui()

    def _apply_theme(self) -> None:
        self.setStyleSheet(
            """
            QWidget {
                background: #0b1118;
                color: #e5eef8;
                font-size: 13px;
            }
            QGroupBox {
                border: 1px solid #243244;
                border-radius: 14px;
                margin-top: 10px;
                padding: 12px;
                background: #101924;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 14px;
                padding: 0 8px;
                color: #8fb8d8;
            }
            QLabel#title {
                font-size: 25px;
                font-weight: 700;
                color: #f4fbff;
            }
            QLabel#subtitle {
                color: #94a9be;
            }
            QLabel#panelTitle {
                font-size: 16px;
                font-weight: 600;
                color: #d6e8f7;
            }
            QLabel#hint {
                color: #9eb2c7;
                background: #101924;
                border: 1px dashed #263648;
                border-radius: 10px;
                padding: 10px;
            }
            QLabel#permissionHint {
                color: #ffd38a;
                background: #2a2112;
                border: 1px solid #6b4d17;
                border-radius: 10px;
                padding: 10px;
            }
            QLabel#statusChip {
                background: #122130;
                color: #8ed1ff;
                border: 1px solid #22506b;
                border-radius: 999px;
                padding: 10px 18px;
                font-weight: 700;
            }
            QLineEdit, QPlainTextEdit, QTextEdit, QComboBox, QSpinBox {
                background: #0e1620;
                border: 1px solid #27384a;
                border-radius: 10px;
                padding: 8px 10px;
                selection-background-color: #1c6ea4;
            }
            QLineEdit:focus, QPlainTextEdit:focus, QTextEdit:focus, QComboBox:focus, QSpinBox:focus {
                border: 1px solid #4ca3d8;
            }
            QPushButton {
                background: #182535;
                border: 1px solid #2c4157;
                border-radius: 10px;
                padding: 10px 14px;
                font-weight: 600;
            }
            QPushButton:hover {
                background: #223044;
                border-color: #4a6682;
            }
            QPushButton:checked {
                background: #123049;
                border-color: #4ca3d8;
                color: #d8f1ff;
            }
            QPushButton:disabled {
                color: #6d7d8c;
                background: #121821;
                border-color: #202a35;
            }
            QTextEdit {
                font-family: "DejaVu Sans Mono";
            }
            QSplitter::handle {
                background: #1c2733;
            }
            """
        )

    def _sync_mode_buttons(self, checked: bool = False) -> None:
        if self.sender() is self.live_button and self.live_button.isChecked():
            self.replay_button.setChecked(False)
        elif self.sender() is self.replay_button and self.replay_button.isChecked():
            self.live_button.setChecked(False)

        if not self.live_button.isChecked() and not self.replay_button.isChecked():
            self.replay_button.setChecked(True)

    def _sync_mode_ui(self, checked: bool = False) -> None:
        live = self.live_button.isChecked()
        self.source_label.setText("Interface" if live else "PCAP File")
        self.interface_combo.setEnabled(live)
        self.refresh_button.setEnabled(live)
        self.browse_button.setEnabled(not live)
        self.source_edit.setPlaceholderText(
            "Select a network interface" if live else "Choose a pcap for replay"
        )
        if live and self.interface_combo.currentIndex() >= 0:
            self.source_edit.setText(self.interface_combo.currentData() or self.source_edit.text())

        if live:
            self.permission_hint.setText(
                "Live capture needs root or the packet capture capabilities set on the binary. "
                "If live capture fails, run make ui again (or make ui_permissions) from terminal."
            )
        else:
            self.permission_hint.setText(
                "Replay mode does not need capture permissions. Use it to verify the IDS pipeline without root."
            )

    def _clear_log(self, checked: bool = False) -> None:
        self.log_view.clear()

    def _append_log(self, text: str, color: str = "#d6e3f0") -> None:
        escaped = html.escape(text).replace("\n", "<br>")
        self.log_view.moveCursor(QTextCursor.End)
        self.log_view.insertHtml(f'<span style="color:{color};">{escaped}</span><br>')
        self.log_view.moveCursor(QTextCursor.End)

    def _append_output(self, text: str) -> None:
        for line in text.splitlines():
            if not line.strip():
                continue
            color = "#d6e3f0"
            if "ALERT:" in line:
                color = "#ff8f70"
            elif line.startswith("Running") or line.startswith("Loaded"):
                color = "#8ed1ff"
            elif line.startswith("Run complete") or line.startswith("Self-test"):
                color = "#8ff0b2"
            self._append_log(line, color)

    def _set_status(self, text: str) -> None:
        self.status_chip.setText(text)
        self.statusBar().showMessage(text)

    def _selected_interface(self) -> str | None:
        value = self.interface_combo.currentData()
        if value:
            return str(value)
        text = self.source_edit.text().strip()
        return text or None

    def _capture_source(self) -> str | None:
        if self.live_button.isChecked():
            return self._selected_interface()
        text = self.source_edit.text().strip()
        return text or None

    def _start_process(self, program: str, arguments: list[str]) -> None:
        if self.process is not None:
            return

        self.stop_requested = False
        self.last_output = []
        self.process = QProcess(self)
        self.process.setWorkingDirectory(str(REPO_ROOT))
        self.process.setProcessChannelMode(QProcess.MergedChannels)
        self.process.readyReadStandardOutput.connect(self._read_process_output)
        self.process.finished.connect(self._process_finished)
        self.process.errorOccurred.connect(self._process_error)

        self._append_log(f"$ {program} {' '.join(arguments)}".rstrip(), "#7aa7d9")
        self._set_status("Running")
        self.start_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self.ai_eval_button.setEnabled(False)
        self.ai_score_button.setEnabled(False)
        self.ai_default_button.setEnabled(False)
        self.process.start(program, arguments)

    def _finish_process_ui(self) -> None:
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.ai_eval_button.setEnabled(True)
        self.ai_score_button.setEnabled(True)
        self.ai_default_button.setEnabled(True)
        self._set_status("Idle")
        self.process = None

    def _read_process_output(self) -> None:
        if self.process is None:
            return
        chunk = bytes(self.process.readAllStandardOutput()).decode("utf-8", errors="replace")
        if chunk:
            self.last_output.extend(chunk.splitlines())
            self._append_output(chunk)

    def _process_finished(self, exit_code: int = 0, exit_status: QProcess.ExitStatus = QProcess.ExitStatus.NormalExit) -> None:
        if exit_code != 0 and not self.stop_requested:
            combined_output = "\n".join(self.last_output)
            if "Operation not permitted" in combined_output or "permission" in combined_output.lower():
                self._append_log(
                    "Live capture is blocked by system permissions. Rerun make ui (or make ui_permissions) in terminal to grant capture capabilities.",
                    "#ffd38a",
                )
        self.stop_requested = False
        self._finish_process_ui()

    def _process_error(self, error: QProcess.ProcessError) -> None:
        if self.stop_requested and error == QProcess.ProcessError.Crashed:
            return
        message = f"Process error: {error.name}"
        self._append_log(message, "#ff8f70")
        self._set_status("Error")

    def refresh_interfaces(self, checked: bool = False) -> None:
        completed = subprocess.run(
            ["/bin/bash", "-lc", "make list_interfaces >/dev/null && ./bin/interface_list"],
            cwd=REPO_ROOT,
            check=False,
            capture_output=True,
            text=True,
        )
        if completed.returncode != 0:
            self._append_log(completed.stderr.strip() or "Failed to list interfaces.", "#ff8f70")
            return

        self._append_output(completed.stdout)
        self.interfaces = parse_interfaces(completed.stdout)
        self.interface_combo.blockSignals(True)
        self.interface_combo.clear()
        for entry in self.interfaces:
            label = entry.name if not entry.description else f"{entry.name} - {entry.description}"
            self.interface_combo.addItem(label, entry.name)
        self.interface_combo.blockSignals(False)

        if self.interfaces:
            self.interface_combo.setCurrentIndex(0)
            if self.live_button.isChecked():
                self.source_edit.setText(self.interface_combo.currentData())
            self._append_log(f"Loaded {len(self.interfaces)} interfaces.", "#8ed1ff")
        else:
            self._append_log("No interfaces found.", "#ff8f70")

    def _interface_selected(self, index: int) -> None:
        if index < 0 or not self.live_button.isChecked():
            return
        value = self.interface_combo.itemData(index)
        if value:
            self.source_edit.setText(str(value))

    def browse_pcap(self, checked: bool = False) -> None:
        start_dir = str(REPO_ROOT / "tests" / "data")
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Select PCAP File",
            start_dir,
            "PCAP files (*.pcap *.pcapng);;All files (*)",
        )
        if file_path:
            self.source_edit.setText(file_path)

    def start_capture(self, checked: bool = False) -> None:
        if self.process is not None:
            return

        mode = "live" if self.live_button.isChecked() else "replay"
        source = self._capture_source()
        if not source:
            QMessageBox.warning(self, "Missing source", "Choose an interface or pcap file first.")
            return

        args = [
            str(APP_BINARY),
            mode,
            source,
            str(self.threshold_spin.value()),
            str(self.window_spin.value()),
            str(self.packet_count_spin.value()),
        ]

        filter_expr = self.filter_edit.text().strip()
        if filter_expr:
            args.extend(["--filter", filter_expr])
        if self.sliding_check.isChecked():
            args.append("--sliding")

        for line in self.rules_edit.toPlainText().splitlines():
            rule = line.strip()
            if rule:
                args.extend(["--rule", rule])

        self._start_process(args[0], args[1:])

    def stop_capture(self, checked: bool = False) -> None:
        if self.process is None:
            return
        self.stop_requested = True
        self.process.terminate()
        QTimer.singleShot(1200, self._force_kill_if_needed)
        self._append_log("Stopped by user.", "#ffcf70")

    def _force_kill_if_needed(self) -> None:
        if self.process is None:
            return
        if self.process.state() != QProcess.ProcessState.NotRunning:
            self.process.kill()

    def run_feature(self, action: str) -> None:
        if self.process is not None:
            return

        if action == "setup_check":
            self._start_process("/bin/bash", ["-lc", "make setup_check >/dev/null && ./bin/pcap_setup_check"])
            return

        if action == "list_interfaces":
            self.refresh_interfaces()
            return

        if action == "capture_basic":
            interface_name = self._selected_interface()
            if not interface_name:
                QMessageBox.warning(self, "Missing interface", "Select an interface first.")
                return
            self._start_process(
                "/bin/bash",
                [
                    "-lc",
                    f"make capture_basic >/dev/null && ./bin/live_capture_basic {shlex.quote(interface_name)} {self.packet_count_spin.value()}",
                ],
            )
            return

        if action == "parse_headers_demo":
            interface_name = self._selected_interface()
            if not interface_name:
                QMessageBox.warning(self, "Missing interface", "Select an interface first.")
                return
            self._start_process(
                "/bin/bash",
                [
                    "-lc",
                    f"make parse_headers_demo >/dev/null && ./bin/packet_header_parser_demo {shlex.quote(interface_name)} {self.packet_count_spin.value()}",
                ],
            )
            return

        if action == "ids_rule_demo":
            interface_name = self._selected_interface()
            if not interface_name:
                QMessageBox.warning(self, "Missing interface", "Select an interface first.")
                return
            self._start_process(
                "/bin/bash",
                [
                    "-lc",
                    (
                        "make ids_rule_demo >/dev/null && ./bin/ids_live_rule_demo "
                        f"{shlex.quote(interface_name)} {self.threshold_spin.value()} {self.window_spin.value()} {self.packet_count_spin.value()}"
                    ),
                ],
            )
            return

        if action == "replay_demo":
            source = self._capture_source()
            if not source:
                QMessageBox.warning(self, "Missing source", "Choose an interface or pcap file first.")
                return
            mode_flag = "--live" if self.live_button.isChecked() else "--pcap"
            extra_args = [
                f"{self.threshold_spin.value()}",
                f"{self.window_spin.value()}",
                f"{self.packet_count_spin.value()}",
            ]
            filter_part = f" --filter {shlex.quote(self.filter_edit.text().strip())}" if self.filter_edit.text().strip() else ""
            sliding_part = " --sliding" if self.sliding_check.isChecked() else ""
            rule_part = "".join(
                f" --rule {shlex.quote(line.strip())}"
                for line in self.rules_edit.toPlainText().splitlines()
                if line.strip()
            )
            self._start_process(
                "/bin/bash",
                [
                    "-lc",
                    (
                        "make replay_demo >/dev/null && ./bin/ids_live_or_pcap "
                        f"{mode_flag} {shlex.quote(source)} {' '.join(extra_args)}{filter_part}{sliding_part}{rule_part}"
                    ),
                ],
            )
            return

        if action == "tracker_test":
            self._start_process("/bin/bash", ["-lc", "make tracker_test >/dev/null && ./bin/ids_tracker_test"])
            return

        if action == "rule_engine_test":
            self._start_process("/bin/bash", ["-lc", "make rule_engine_test >/dev/null && ./bin/rule_engine_test"])
            return

        if action == "integration_test":
            self._start_process("/bin/bash", ["-lc", "make integration_test"])
            return

        if action == "ai_eval":
            self.run_ai_eval()
            return

        if action == "ai_score":
            self.run_ai_score()
            return

        if action == "ai_default":
            self.run_ai_default()
            return

        QMessageBox.warning(self, "Unknown action", f"No handler for {action}.")

    def run_ai_eval(self) -> None:
        if self.process is not None:
            return
        self._start_process(
            "make",
            [
                "ai_eval",
                f"PYTHON={self.ai_python_edit.text().strip()}",
                f"AI_MODEL={self.ai_model_edit.text().strip()}",
                f"AI_TEST_CSV={self.ai_test_csv_edit.text().strip()}",
                f"AI_REPORT={self.ai_report_edit.text().strip()}",
            ],
        )

    def run_ai_score(self) -> None:
        if self.process is not None:
            return
        self._start_process(
            "make",
            [
                "ai_score",
                f"PYTHON={self.ai_python_edit.text().strip()}",
                f"AI_MODEL={self.ai_model_edit.text().strip()}",
                f"AI_TEST_CSV={self.ai_test_csv_edit.text().strip()}",
                f"AI_SCORE_OUT={self.ai_score_out_edit.text().strip()}",
            ],
        )

    def run_ai_default(self) -> None:
        if self.process is not None:
            return
        self._start_process(
            "make",
            [
                "ai_default",
                f"PYTHON={self.ai_python_edit.text().strip()}",
                f"AI_MODEL={self.ai_model_edit.text().strip()}",
                f"AI_TEST_CSV={self.ai_test_csv_edit.text().strip()}",
                f"AI_REPORT={self.ai_report_edit.text().strip()}",
                f"AI_SCORE_OUT={self.ai_score_out_edit.text().strip()}",
            ],
        )


def main() -> int:
    app = QApplication(sys.argv)
    window = DesktopUi()
    window.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
