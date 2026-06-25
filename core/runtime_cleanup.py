"""
Runtime cleanup manager for long-running assessment sessions.

Idempotent teardown of the background syslog collector, the screenshot
live-view, and the iOS device transports (the iproxy tunnel / frida session),
plus optional partial-report generation on signal/exit.
"""

from __future__ import annotations

from rich.console import Console

from core.report import ReportGenerator

console = Console()


class RuntimeCleanupManager:
    """Coordinates one-time teardown and optional partial-report generation."""

    def __init__(self, screenshotter, config, device_info: dict, device=None):
        self.screenshotter = screenshotter
        self.config = config
        self.device_info = device_info
        self.device = device
        self.bg_syslog = None
        self._cleaned = False
        self._final_report_generated = False

    def set_device(self, device) -> None:
        self.device = device

    def set_background_collector(self, collector) -> None:
        self.bg_syslog = collector

    def mark_final_report_generated(self) -> None:
        self._final_report_generated = True

    def cleanup(self, generate_partial_report: bool = True) -> None:
        if self._cleaned:
            return
        self._cleaned = True

        if self.bg_syslog is not None:
            try:
                self.bg_syslog.stop()
            except Exception:
                pass

        if self.screenshotter is not None:
            try:
                self.screenshotter.stop_mirror()
            except Exception:
                pass

        if self.device is not None:
            try:
                self.device.close()  # tear down iproxy tunnel
            except Exception:
                pass

        if not generate_partial_report or self._final_report_generated:
            return

        if self.config and self.device_info and any(self.config.findings.values()):
            try:
                reporter = ReportGenerator(self.config, self.device_info)
                path = reporter.generate()
                console.print(f"[green]\u2713 Partial report saved to:[/green] {path}")
            except Exception as e:
                console.print(f"[yellow]Partial report generation failed: {e}[/yellow]")
