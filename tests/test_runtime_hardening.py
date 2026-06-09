"""
Runtime hardening tests for PII initialization, syslog lifecycle cleanup,
and idempotent runtime teardown (iOS / TrashiOS).
"""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

# Add project root to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import core.config as core_config
from core.pii_runtime import initialize_pii_detection
from core.runtime_cleanup import RuntimeCleanupManager
from phases.syslog import run_syslog_monitoring
from utils.syslog_collector import BackgroundSyslogCollector


class _SimpleConfig:
    def __init__(self):
        self.presidio_engine = None
        self.findings = {}


class _BadEngine:
    @property
    def analyzer(self):
        raise RuntimeError("backend warmup failed")


class _BlockingStdout:
    def __init__(self, proc):
        self._proc = proc

    def readline(self):
        while not self._proc.terminated:
            time.sleep(0.01)
        return ""


class _BlockingProcess:
    def __init__(self):
        self.terminated = False
        self.terminate_calls = 0
        self.kill_calls = 0
        self.stdout = _BlockingStdout(self)
        self.stderr = MagicMock()

    def poll(self):
        return 0 if self.terminated else None

    def terminate(self):
        self.terminate_calls += 1
        self.terminated = True

    def wait(self, timeout=None):
        if not self.terminated:
            raise subprocess.TimeoutExpired("idevicesyslog", timeout)
        return 0

    def kill(self):
        self.kill_calls += 1
        self.terminated = True


class _StubbornProcess(_BlockingProcess):
    def terminate(self):
        self.terminate_calls += 1
        # Simulate a process that ignores terminate until kill.

    def wait(self, timeout=None):
        if not self.terminated:
            raise subprocess.TimeoutExpired("idevicesyslog", timeout)
        return 0


class TestPIIRuntimeInitialization(unittest.TestCase):
    def test_ner_success_requires_warmup_then_enables(self):
        cfg = _SimpleConfig()
        console = MagicMock()
        engine = MagicMock()
        engine.analyzer = object()

        with patch("core.presidio_engine.is_available", return_value=True), patch(
            "core.presidio_engine.init_engine", return_value=engine
        ):
            rc = initialize_pii_detection(cfg, use_presidio=False, use_ner=True, console=console)

        self.assertEqual(rc, 0)
        self.assertIs(cfg.presidio_engine, engine)
        rendered = " ".join(str(c.args[0]) for c in console.print.call_args_list if c.args)
        self.assertIn("enabled", rendered)

    def test_ner_init_failure_exits_nonzero_without_false_success(self):
        cfg = _SimpleConfig()
        console = MagicMock()

        with patch("core.presidio_engine.is_available", return_value=True), patch(
            "core.presidio_engine.init_engine", return_value=_BadEngine()
        ):
            rc = initialize_pii_detection(cfg, use_presidio=False, use_ner=True, console=console)

        self.assertEqual(rc, 1)
        self.assertIsNone(cfg.presidio_engine)
        rendered = " ".join(str(c.args[0]) for c in console.print.call_args_list if c.args)
        self.assertIn("cannot fall back", rendered)
        self.assertNotIn("enabled", rendered)

    def test_presidio_init_failure_falls_back_to_regex(self):
        cfg = _SimpleConfig()
        console = MagicMock()

        with patch("core.presidio_engine.is_available", return_value=True), patch(
            "core.presidio_engine.init_engine", return_value=_BadEngine()
        ):
            rc = initialize_pii_detection(cfg, use_presidio=True, use_ner=False, console=console)

        self.assertEqual(rc, 0)
        self.assertIsNone(cfg.presidio_engine)
        rendered = " ".join(str(c.args[0]) for c in console.print.call_args_list if c.args)
        self.assertIn("Falling back to regex-only", rendered)


class TestBackgroundSyslogCollectorLifecycle(unittest.TestCase):
    @patch("utils.syslog_collector.subprocess.Popen")
    def test_stop_force_kills_stubborn_process_and_is_idempotent(self, popen_mock):
        proc = _StubbornProcess()
        popen_mock.return_value = proc

        with tempfile.TemporaryDirectory() as tmp:
            collector = BackgroundSyslogCollector("udid", "ExampleApp", Path(tmp))
            collector.start()
            time.sleep(0.05)
            collector.stop()
            collector.stop()  # Idempotency check

            self.assertGreaterEqual(proc.terminate_calls, 1)
            self.assertGreaterEqual(proc.kill_calls, 1)
            self.assertIsNone(collector._thread)
            self.assertIsNone(collector._proc)


class TestSyslogMonitoringLifecycle(unittest.TestCase):
    @patch("phases.syslog.presidio_scan_text", return_value=[])
    @patch("phases.syslog.time.sleep", return_value=None)
    def test_phase_iv_forces_teardown_even_when_readline_blocks(self, _sleep_mock, _scan_mock):
        proc = _StubbornProcess()

        class DummyDevice:
            device_id = "udid"

            def get_pid(self, bundle_id):
                return "123"

            def launch_app(self, bundle_id):
                return ""

            def syslog_stream(self, process=None):
                return proc

        class DummyConfig:
            bundle_id = "com.example.app"
            executable_name = "ExampleApp"
            auto_mode = True

            def __init__(self, output_dir):
                self.output_dir = output_dir
                self.findings = {}

            def log_command(self, *_a, **_k):
                return None

            def add_finding(self, *_a, **_k):
                return None

        with tempfile.TemporaryDirectory() as tmp:
            cfg = DummyConfig(Path(tmp))
            original = core_config.TIMING.syslog_auto_timeout
            core_config.TIMING.syslog_auto_timeout = 0
            try:
                run_syslog_monitoring(cfg, DummyDevice())
            finally:
                core_config.TIMING.syslog_auto_timeout = original

        self.assertGreaterEqual(proc.terminate_calls, 1)
        self.assertGreaterEqual(proc.kill_calls, 1)


class TestRuntimeCleanupManager(unittest.TestCase):
    @patch("core.runtime_cleanup.ReportGenerator")
    @patch("builtins.print")
    def test_cleanup_is_one_shot_and_stops_collectors_once(self, _print_mock, reporter_cls):
        screenshotter = MagicMock()
        bg_collector = MagicMock()
        device = MagicMock()

        cfg = MagicMock()
        cfg.findings = {"Phase I": [{"title": "x"}]}

        reporter = reporter_cls.return_value
        reporter.generate.return_value = "/tmp/partial.md"

        manager = RuntimeCleanupManager(screenshotter=screenshotter, config=cfg,
                                        device_info={"build": "20A"}, device=device)
        manager.set_background_collector(bg_collector)

        manager.cleanup(generate_partial_report=True)
        manager.cleanup(generate_partial_report=True)

        bg_collector.stop.assert_called_once()
        screenshotter.stop_mirror.assert_called_once()
        device.close.assert_called_once()
        reporter.generate.assert_called_once()

    @patch("core.runtime_cleanup.ReportGenerator")
    def test_no_partial_report_after_final_report_marked(self, reporter_cls):
        screenshotter = MagicMock()
        bg_collector = MagicMock()

        cfg = MagicMock()
        cfg.findings = {"Phase I": [{"title": "x"}]}

        manager = RuntimeCleanupManager(screenshotter=screenshotter, config=cfg,
                                        device_info={"build": "20A"})
        manager.set_background_collector(bg_collector)
        manager.mark_final_report_generated()
        manager.cleanup(generate_partial_report=True)

        reporter_cls.assert_not_called()


if __name__ == "__main__":
    unittest.main()
