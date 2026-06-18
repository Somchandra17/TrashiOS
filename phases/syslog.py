"""
Phase IV — Device Log Monitoring (the iOS logcat equivalent).

Captures device logs via idevicesyslog while the app is exercised, then scans
for leaked secrets/PII, cleartext HTTP, SQL statements, and crash/exception
stack traces. Same capture+scan model as TrashDroid's logcat phase; only the
log source changes.

Grounded in OWASP MASTG sensitive-data-in-logs, MASVS-STORAGE-2.
"""

from __future__ import annotations

import re
import threading
import time

from rich.console import Console
from rich.panel import Panel

from core.config import Config, TIMING, LIMITS
from core.ios_device import IOSDevice
from utils.helpers import presidio_scan_text, presidio_findings_to_report

console = Console()
PHASE = "Phase VIII — Device Log Monitoring"

_HTTP_RE = re.compile(r"http://[^\s\"'<>]+", re.IGNORECASE)
# Require real SQL context (paired keywords) so plain words like "update" in a log line don't match.
_SQL_RE = re.compile(
    r"\b(SELECT\b.{1,200}?\bFROM\b|INSERT\s+INTO\b|UPDATE\b.{1,120}?\bSET\b|DELETE\s+FROM\b|CREATE\s+TABLE\b)",
    re.IGNORECASE,
)
_EXC_RE = re.compile(r"(NSException|EXC_BAD_ACCESS|Fatal error|\*\*\* Terminating|"
                     r"unrecognized selector|Traceback|crash)", re.IGNORECASE)


def run_syslog_monitoring(config: Config, device: IOSDevice) -> None:
    console.print(f"\n[bold cyan]═══ {PHASE} ═══[/bold cyan]\n")

    process = config.executable_name or ""
    pid = device.get_pid(config.bundle_id)
    if not pid:
        console.print("  [cyan]Launching app to generate logs...[/cyan]")
        device.launch_app(config.bundle_id)
        time.sleep(3)

    lines: list[str] = []
    stop = threading.Event()
    proc = device.syslog_stream(process or None)

    def _reader():
        try:
            while not stop.is_set() and proc.stdout is not None:
                line = proc.stdout.readline()
                if not line:
                    break
                if (not process) or (process in line):
                    lines.append(line)
                if len(lines) >= LIMITS.max_syslog_lines:
                    break
        except Exception:
            pass

    t = threading.Thread(target=_reader, daemon=True)
    t.start()

    if config.auto_mode:
        console.print(f"[yellow]Auto-mode: capturing syslog for {TIMING.syslog_auto_timeout}s "
                      f"(exercising not driven automatically)...[/yellow]")
        time.sleep(TIMING.syslog_auto_timeout)
    else:
        console.print(Panel("Exercise the app now (log in, navigate, submit forms).\n"
                            "Press Enter here to stop log capture.", style="bold yellow"))
        input()

    stop.set()
    try:
        proc.terminate()
        proc.wait(timeout=3)
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass
    t.join(timeout=3)

    if not lines:
        console.print("  [yellow]No log lines captured.[/yellow]")
        config.add_finding(PHASE, "No device logs captured", "Info",
                           "idevicesyslog returned no lines for the target process. "
                           "Confirm the app was running and producing output.")
        return

    text = "".join(lines)
    out_path = config.output_dir / "syslog" / "syslog_capture.txt"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(text, encoding="utf-8")
    config.log_command(PHASE, f"idevicesyslog (filter={process or 'all'})", f"{len(lines)} lines -> {out_path}")
    console.print(f"  [green]Captured {len(lines)} line(s).[/green] Scanning...")

    _scan_pii(config, text)
    _scan_regex(config, lines, _HTTP_RE, "Cleartext HTTP URL in device log", "Medium",
                "App logs reference cleartext HTTP endpoints (MitM / cleartext exposure):")
    _scan_regex(config, lines, _SQL_RE, "SQL statements logged", "Medium",
                "SQL statements are visible in device logs (information disclosure / injection insight):")
    _scan_regex(config, lines, _EXC_RE, "Crash/exception stack traces logged", "Info",
                "Crash or exception traces are logged (may leak internal state):")

    console.print(f"\n[green]✓ {PHASE} complete.[/green]")


def _scan_pii(config: Config, text: str) -> None:
    findings = presidio_scan_text(text, config, source_label="syslog")
    if findings:
        presidio_findings_to_report(
            findings, PHASE, config,
            fallback_title="Sensitive data leaked in device log",
            fallback_detail="Device logs (syslog evidence) contain strings matching sensitive patterns.",
        )


def _scan_regex(config: Config, lines: list[str], rx: re.Pattern, title: str, severity: str, lead: str) -> None:
    hits = [ln.strip() for ln in lines if rx.search(ln)]
    if hits:
        config.add_finding(PHASE, f"{title} ({len(hits)})", severity,
                           f"{lead}\n\n" + "\n".join(hits[:60]))
