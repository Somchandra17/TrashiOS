"""
Phase VII — Pasteboard Leakage.

The general (system) UIPasteboard is readable by ANY app on the device. Apps
that copy secrets (passwords, OTPs, tokens, card numbers) to it leak them. This
phase monitors the general pasteboard (via Frida) while the operator copies
sensitive values in the app, then scans what was captured.

Grounded in OWASP MASTG-TEST-0073/0074, MASVS-PLATFORM-4 / STORAGE-2.
"""

from __future__ import annotations

import time

from rich.console import Console
from rich.panel import Panel

from core.config import Config
from core.ios_device import IOSDevice
from core.frida_bridge import FridaBridge
from utils.helpers import presidio_scan_text, presidio_findings_to_report

console = Console()
PHASE = "Phase VII — Pasteboard Leakage"
_MONITOR_SECONDS = 20


def run_pasteboard_analysis(config: Config, device: IOSDevice, frida: FridaBridge) -> None:
    console.print(f"\n[bold cyan]═══ {PHASE} ═══[/bold cyan]\n")

    if not frida.verify_connection():
        console.print("[yellow]frida-server not reachable — skipping pasteboard monitor.[/yellow]")
        config.add_finding(PHASE, "Pasteboard analysis skipped — Frida unavailable", "Info",
                           "Monitoring the general pasteboard requires frida-server over USB.")
        return

    pid = device.get_pid(config.bundle_id)
    if not pid:
        device.launch_app(config.bundle_id)
        time.sleep(3)

    if not config.auto_mode:
        console.print(Panel(
            f"In the app, trigger any 'copy' of sensitive data (reveal+copy a password, copy an OTP/token/card).\n"
            f"Monitoring the general pasteboard for {_MONITOR_SECONDS}s now...",
            style="bold yellow",
        ))
    else:
        console.print(f"[yellow]Auto-mode: monitoring the general pasteboard for {_MONITOR_SECONDS}s "
                      "(no copy actions driven automatically)...[/yellow]")

    res = frida.pasteboard_monitor(seconds=_MONITOR_SECONDS)
    config.log_command(PHASE, "frida: monitor UIPasteboard.generalPasteboard", res.stdout or res.stderr)

    if not res.success or not (res.stdout or "").strip():
        console.print("  [green]No changes captured on the general pasteboard.[/green]")
        config.add_finding(PHASE, "No general-pasteboard writes observed", "Info",
                           "No sensitive data was seen on the general pasteboard during the monitoring window. "
                           "Re-test by copying secrets in the app.")
        return

    captured = res.stdout
    (config.output_dir / "pasteboard_capture.txt").write_text(captured, encoding="utf-8")
    console.print("  [yellow]General-pasteboard content captured — scanning for secrets...[/yellow]")

    findings = presidio_scan_text(captured, config, source_label="pasteboard")
    if findings:
        presidio_findings_to_report(
            findings, PHASE, config,
            fallback_title="Sensitive data written to general pasteboard",
            fallback_detail="Values copied to the system pasteboard (readable by any app):\n" + captured,
        )
    else:
        config.add_finding(PHASE, "Data written to general pasteboard", "Low",
                           "Content was written to the general (system) pasteboard. Verify none of it is sensitive "
                           "and consider a named/local pasteboard with an expirationDate:\n" + captured[:1000])

    console.print(f"\n[green]✓ {PHASE} complete.[/green]")
