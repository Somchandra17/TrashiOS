"""
Background device-log collector — captures app-specific syslog during the
entire test run via `idevicesyslog`, then scans for sensitive data.

The iOS analogue of TrashDroid's BackgroundLogcatCollector: same thread /
process lifecycle and Presidio/regex scanning, only the log source changes
(idevicesyslog instead of `adb logcat`) and lines are filtered by process
name (the app's executable) rather than package name.
"""

from __future__ import annotations

import re
import subprocess
import threading
from pathlib import Path

from core.config import SENSITIVE_PATTERNS, LIMITS


class BackgroundSyslogCollector:
    """Lightweight background idevicesyslog collector thread."""

    def __init__(self, udid: str, process_name: str, output_dir: Path):
        self.udid = udid
        self.process_name = process_name or ""
        self.output_dir = output_dir
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._proc: subprocess.Popen | None = None
        self._proc_lock = threading.Lock()
        self._lines: list[str] = []

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._capture_loop, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop_event.set()
        self._terminate_process(force_kill=True)
        thread = self._thread
        if thread:
            thread.join(timeout=5)
            if thread.is_alive():
                self._terminate_process(force_kill=True)
                thread.join(timeout=2)
        self._thread = None

    def _get_process(self) -> subprocess.Popen | None:
        with self._proc_lock:
            return self._proc

    def _set_process(self, proc: subprocess.Popen | None) -> None:
        with self._proc_lock:
            self._proc = proc

    def _terminate_process(self, force_kill: bool) -> None:
        proc = self._get_process()
        if proc is None:
            return
        if proc.poll() is None:
            try:
                proc.terminate()
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                if force_kill:
                    try:
                        proc.kill()
                        proc.wait(timeout=2)
                    except Exception:
                        pass
            except Exception:
                pass
        self._set_process(None)

    def _capture_loop(self) -> None:
        cmd = ["idevicesyslog"]
        if self.udid:
            cmd += ["-u", self.udid]
        # idevicesyslog supports process filtering with -p; we still grep in
        # Python so partial/parenthesized process names also match.
        if self.process_name:
            cmd += ["-p", self.process_name]
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            self._set_process(proc)
            while not self._stop_event.is_set():
                if proc.stdout is None:
                    break
                line = proc.stdout.readline()
                if line:
                    if (not self.process_name) or (self.process_name in line):
                        self._lines.append(line)
                    if len(self._lines) >= LIMITS.max_syslog_lines:
                        break
        except Exception:
            pass
        finally:
            self._terminate_process(force_kill=True)

    def save_and_scan(self) -> list[dict]:
        if not self._lines:
            return []

        log_path = self.output_dir / "background_syslog.txt"
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_path.write_text("".join(self._lines), encoding="utf-8")

        findings: list[dict] = []
        full_text = "".join(self._lines)

        # Presidio entity-level scan (falls through to regex on any failure).
        try:
            from core.presidio_engine import get_engine
            engine = get_engine()
            if engine is not None:
                pii_results = engine.analyze_text_for_findings(full_text, source_label="background_syslog")
                if pii_results:
                    entity_groups: dict[str, list[dict]] = {}
                    for r in pii_results:
                        entity_groups.setdefault(r["entity_type"], []).append(r)
                    for entity_type, group in entity_groups.items():
                        avg_score = sum(g["score"] for g in group) / len(group)
                        samples = [g["text"] for g in group[:5]]
                        findings.append({
                            "title": f"PII detected in background syslog: {entity_type} "
                                     f"({len(group)} occurrence{'s' if len(group) > 1 else ''})",
                            "severity": group[0].get("severity", "High"),
                            "detail": (
                                f"Background syslog monitoring detected {len(group)} "
                                f"{entity_type} entity(ies) (avg confidence: {avg_score:.2f}).\n\n"
                                f"Sample matches:\n" + "\n".join(f"  - {s}" for s in samples)
                            ),
                        })
                    return findings
        except Exception:
            pass

        sensitive_lines = [
            line.strip() for line in self._lines
            if re.search(SENSITIVE_PATTERNS, line, re.IGNORECASE)
        ]
        if sensitive_lines:
            findings.append({
                "title": f"Sensitive data in background syslog ({len(sensitive_lines)} lines)",
                "severity": "High",
                "detail": (
                    "Background syslog monitoring during the entire test run captured "
                    f"{len(sensitive_lines)} lines containing potentially sensitive data:\n\n"
                    + "\n".join(sensitive_lines[:200])
                ),
            })
        return findings
