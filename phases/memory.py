"""
Phase IX — Process Memory Analysis.

Dumps the running app's read/write memory via Frida and scans it for secrets
retained in RAM (credentials/tokens that linger after login). Also enumerates
open file descriptors and network connections over SSH (the iOS replacement for
Android's /proc/<pid>/fd and /proc/<pid>/net, which don't exist here).

Grounded in OWASP MASTG-TEST-0011, MASVS-STORAGE-2.
"""

from __future__ import annotations

import re
import time

from rich.console import Console
from rich.panel import Panel

from core.config import Config, LIMITS
from core.ios_device import IOSDevice
from core.frida_bridge import FridaBridge
from utils.helpers import presidio_scan_file, presidio_findings_to_report


console = Console()
PHASE = "Phase IX — Process Memory Analysis"


def run_memory_analysis(config: Config, device: IOSDevice, frida: FridaBridge) -> None:
    console.print(f"\n[bold cyan]═══ {PHASE} ═══[/bold cyan]\n")

    if not frida.verify_connection():
        console.print("[yellow]frida-server not reachable — skipping memory analysis.[/yellow]")
        config.add_finding(PHASE, "Memory analysis skipped — Frida unavailable", "Info",
                           "Dumping process memory requires frida-server over USB.")
        return

    if not config.auto_mode:
        console.print(Panel("Ensure the app is LOGGED IN and on a data-rich screen, then press Enter "
                            "(secrets are most recoverable right after authentication).", style="bold yellow"))
        input()

    pid = device.get_pid(config.bundle_id)
    if not pid:
        console.print("  [cyan]Launching app...[/cyan]")
        device.launch_app(config.bundle_id)
        time.sleep(4)

    dump_path = config.output_dir / "memory" / "memory_dump.bin"
    console.print(f"  [cyan]Dumping process memory via Frida (cap {LIMITS.max_dump_mb} MB, ~2 min budget)...[/cyan]")
    _last = [0]
    def _progress(mb):
        if mb >= _last[0] + 8:
            _last[0] = mb
            console.print(f"    [dim]… {mb} MB captured[/dim]")
    res = frida.dump_memory(str(dump_path), max_mb=LIMITS.max_dump_mb, on_progress=_progress)
    config.log_command(PHASE, "frida: dump rw- ranges", res.stdout or res.stderr)

    if res.success and dump_path.exists() and dump_path.stat().st_size > 0:
        console.print(f"  [green]{dump_path.stat().st_size // (1024*1024)} MB dumped. Scanning for secrets...[/green]")
        findings = presidio_scan_file(str(dump_path), config, source_label="process_memory")
        if findings:
            presidio_findings_to_report(
                findings, PHASE, config,
                fallback_title="Sensitive data in process memory",
                fallback_detail="Secrets recovered from a live process memory dump (Frida). "
                                "Credentials/tokens should be zeroed after use.",
            )
        else:
            console.print("    [green]No high-signal secrets found in the memory dump.[/green]")
    else:
        reason = res.stderr or "unknown"
        console.print(f"  [yellow]Memory dump failed: {reason}[/yellow]")
        config.add_finding(PHASE, "Memory dump could not be captured", "Info",
                           f"Frida memory dump produced no data. Reason: {reason}\n"
                           "Common cause: anti-debug / managed-app (Intune MAM) protection detaches Frida. "
                           "Try bypassing anti-debug first, or confirm the app is running and logged in.")

    _open_fds_and_connections(config, device, pid or device.get_pid(config.bundle_id))
    console.print(f"\n[green]✓ {PHASE} complete.[/green]")


def _open_fds_and_connections(config: Config, device: IOSDevice, pid) -> None:
    if not device.caps.ssh or not pid:
        return
    # Open file descriptors (the /proc/<pid>/fd replacement).
    lsof = device.shell_output(f"lsof -p {pid} 2>/dev/null | head -200")
    if lsof:
        config.log_command(PHASE, f"lsof -p {pid}", lsof[:2000])
    # Network connections (the /proc/<pid>/net replacement).
    conns = device.shell_output(f"lsof -nP -i -p {pid} 2>/dev/null; netstat -an 2>/dev/null | grep ESTABLISHED | head -50")
    if conns:
        config.log_command(PHASE, "lsof -i / netstat (connections)", conns[:2000])
        non_tls = [ln for ln in conns.splitlines() if re.search(r":80\b|:8080\b|:21\b|:23\b", ln)]
        if non_tls:
            config.add_finding(PHASE, "Connections to non-TLS ports observed", "Medium",
                               "The process held connections on cleartext-typical ports (HTTP/FTP/Telnet):\n"
                               + "\n".join(non_tls[:20]))
