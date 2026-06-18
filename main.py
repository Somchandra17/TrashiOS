#!/usr/bin/env python3
"""
TrashiOS — Automated iOS SAST/DAST Framework
Main entry point and phase orchestrator.

Usage:
    python main.py
    python main.py --auto --device <UDID> --bundle com.example.app
    python main.py --phases 1,3,5 --bundle com.example.app
"""

from __future__ import annotations

import argparse
import atexit
import signal
import os
import sys
import traceback
import warnings

# Quiet third-party import noise (objection/frida pull in deprecated pkg_resources).
warnings.filterwarnings("ignore", category=DeprecationWarning)
warnings.filterwarnings("ignore", message=r".*pkg_resources.*")

from rich.console import Console
from rich.panel import Panel
from rich.align import Align

from core.config import Config, BANNER
from core.ios_device import IOSDevice
from core.frida_bridge import FridaBridge
from core.screenshot import ScreenshotManager
from core.report import ReportGenerator
from core.pii_runtime import initialize_pii_detection
from core.runtime_cleanup import RuntimeCleanupManager

from phases.preflight import run_preflight, verify_device_prerequisites
from phases.setup import select_device, get_app_input, install_and_prepare
from phases.decrypt import run_decryption
from phases.static_binary import run_static_binary_analysis
from phases.local_storage import run_local_storage_analysis
from phases.dump_verify import run_dump_verification
from phases.keychain import run_keychain_analysis
from phases.snapshot import run_snapshot_analysis
from phases.pasteboard import run_pasteboard_analysis
from phases.syslog import run_syslog_monitoring
from phases.memory import run_memory_analysis
from phases.url_schemes import run_url_scheme_testing
from phases.post_logout import run_post_logout_testing
from phases.backup import run_backup_analysis
from phases.runtime_hardening import run_runtime_hardening

console = Console()

# (name, key, track) — track is "static" (SAST) or "dynamic" (DAST) for --track filtering.
ALL_PHASES = {
    1:  ("Phase I    — App Binary Decryption", "decrypt", "static"),
    2:  ("Phase II   — Static Binary & Info.plist Analysis", "static_binary", "static"),
    3:  ("Phase III  — Local Data Storage Analysis", "local_storage", "dynamic"),
    4:  ("Phase IV   — Dump File Verification", "dump_verify", "static"),
    5:  ("Phase V    — Keychain Dump & Data Protection", "keychain", "dynamic"),
    6:  ("Phase VI   — Backgrounding Snapshot Leakage", "snapshot", "dynamic"),
    7:  ("Phase VII  — Pasteboard Leakage", "pasteboard", "dynamic"),
    8:  ("Phase VIII — Device Log Monitoring", "syslog", "dynamic"),
    9:  ("Phase IX   — Process Memory Analysis", "memory", "dynamic"),
    10: ("Phase X    — URL Scheme / IPC Testing", "url_schemes", "dynamic"),
    11: ("Phase XI   — Post-Logout Access Control", "post_logout", "dynamic"),
    12: ("Phase XII  — Backup Analysis", "backup", "dynamic"),
    13: ("Phase XIII — Runtime Hardening Assessment", "runtime_hardening", "dynamic"),
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="iOS SAST/DAST — Automated VAPT Framework (TrashiOS)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--skip-preflight", action="store_true", help="Skip host-tool availability checks")
    parser.add_argument("--phases", type=str, default="",
                        help="Comma-separated phase numbers to run (e.g. 1,3,5). Default: all")
    parser.add_argument("--bundle", type=str, default="", help="Target bundle id (skip interactive prompt)")
    parser.add_argument("--ipa", type=str, default="", help="Path to .ipa file (omit if pre-installed)")
    parser.add_argument("--device", type=str, default="", help="Device UDID (skip interactive prompt)")
    parser.add_argument("--auto", action="store_true", help="Non-interactive mode — sensible defaults for all prompts")
    parser.add_argument("--report", choices=["client", "internal"], default="client",
                        help="Report detail level (internal includes the AI prompt header)")
    parser.add_argument("--screenshot-delay", type=float, default=4.5,
                        help="Delay (s) before capturing a screenshot (default: 4.5)")
    parser.add_argument("--ssh-port", type=int, default=44,
                        help="Device SSH port (palera1n=44, classic checkra1n=22). Default: 44")
    parser.add_argument("--ssh-pass", type=str, default="alpine", help="Device root SSH password (default: alpine)")
    parser.add_argument("--local-port", type=int, default=2222, help="Local iproxy port for SSH (default: 2222)")
    parser.add_argument("--mirror", action="store_true",
                        help="Open a QuickTime live-view without asking (interactive mode otherwise prompts y/n; "
                             "default no). WARNING: mirroring sets UIScreen.isCaptured, so anti-screen-capture apps "
                             "(e.g. Intune-MAM) blur their UI — the screenshots captured during the run will be blurred too.")
    parser.add_argument("--track", choices=["all", "static", "dynamic"], default="all",
                        help="Run only static (SAST) or dynamic (DAST) phases. Default: all")
    parser.add_argument("--decrypt", action="store_true",
                        help="Authorize FairPlay binary decryption (frida-ios-dump) in Phase I — authorized testing only")
    parser.add_argument("--backup", action="store_true",
                        help="Run the (slow) full device backup in Phase XII")
    parser.add_argument("--ai-review", action="store_true",
                        help="After the run, auto-run `claude` headless over the ai_review/ package to write final_report.md")
    parser.add_argument("--presidio", action="store_true",
                        help="Enable Presidio PII detection (regex + checksum validators); falls back to regex on init failure")
    parser.add_argument("--ner", action="store_true",
                        help="Enable GLiNER NER backend for ML-based PII detection (implies --presidio, fails fast on init errors)")
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    console.print(Align.left(Panel(BANNER, style="bright_white", expand=True, subtitle="Author: 0xs0m")))

    # ── Pre-flight ──
    if not args.skip_preflight:
        if not run_preflight():
            return 1
    else:
        console.print("[yellow]Pre-flight checks skipped (--skip-preflight).[/yellow]")

    # ── Device selection ──
    if args.device:
        available = IOSDevice.get_devices()
        if args.device not in available:
            console.print(f"[red]Device '{args.device}' not found. Available: {available or 'none'}[/red]")
            return 1
        udid = args.device
        console.print(f"[green]Using device: {udid}[/green]")
    else:
        udid = select_device()
        if not udid:
            return 1

    device = IOSDevice(udid, ssh_pw=args.ssh_pass, ssh_device_port=args.ssh_port, local_port=args.local_port)
    config = Config(device_id=udid)

    # ── Probe device transports (starts iproxy SSH tunnel) ──
    if not verify_device_prerequisites(device):
        return 1
    config.capabilities = device.caps

    try:
        device_info = device.get_device_info()
    except Exception as e:
        console.print(f"[red]Failed to read device information: {e}[/red]")
        return 1
    console.print(f"[green]Device: {device_info.get('model', 'N/A')} | "
                  f"iOS {device_info.get('ios_version', 'N/A')} | build {device_info.get('build', 'N/A')}[/green]")

    # ── Target app input ──
    if args.bundle:
        config.bundle_id = args.bundle
        config.ipa_path = args.ipa or None
        config.is_preinstalled = not bool(args.ipa)
    else:
        ipa_path, bundle_id, is_pre = get_app_input(device)
        config.ipa_path = ipa_path
        config.bundle_id = bundle_id
        config.is_preinstalled = is_pre

    if not config.bundle_id.strip():
        console.print("[red]Bundle id cannot be empty.[/red]")
        return 1

    config.auto_mode = args.auto
    config.report_mode = args.report
    config.screenshot_delay = args.screenshot_delay
    config.allow_decrypt = args.decrypt
    config.allow_backup = args.backup
    config.init_output()

    # ── Initialize PII detection backend (eager warmup) ──
    pii_init_rc = initialize_pii_detection(config=config, use_presidio=args.presidio,
                                           use_ner=args.ner, console=console)
    if pii_init_rc != 0:
        return pii_init_rc

    # ── Install & prepare (hash, install, resolve containers, login state) ──
    install_and_prepare(device, config)

    # ── Init runtime helpers ──
    frida = FridaBridge(device, config.bundle_id)
    if not device.caps.frida:
        console.print("[cyan]Attempting to start frida-server over SSH...[/cyan]")
        if frida.ensure_server():
            device.caps.frida = True
            console.print("[green]frida-server is now reachable.[/green]")

    screenshotter = ScreenshotManager(device, config.screenshot_dir, config, frida=frida)

    # ── Cleanup handler (tears down iproxy tunnel + saves partial report) ──
    cleanup_manager = RuntimeCleanupManager(screenshotter, config, device_info, device)

    def _cleanup(generate_partial_report: bool = True):
        cleanup_manager.cleanup(generate_partial_report=generate_partial_report)

    atexit.register(_cleanup)

    def _signal_handler(signum, frame):
        console.print(f"\n[yellow]Received signal {signum} — cleaning up...[/yellow]")
        _cleanup(generate_partial_report=True)
        sys.exit(128 + signum)

    signal.signal(signal.SIGTERM, _signal_handler)
    signal.signal(signal.SIGINT, _signal_handler)

    # ── Determine phases ──
    if args.phases:
        selected = set()
        invalid: list[str] = []
        for p in args.phases.split(","):
            try:
                n = int(p.strip())
                (selected.add(n) if n in ALL_PHASES else invalid.append(str(n)))
            except ValueError:
                invalid.append(p.strip())
        if invalid:
            console.print(f"[yellow]Ignoring invalid phase(s): {', '.join(invalid)}[/yellow]")
    else:
        selected = set(ALL_PHASES.keys())

    # --track filter (static = SAST, dynamic = DAST)
    if args.track != "all":
        selected = {n for n in selected if ALL_PHASES[n][2] == args.track}
        console.print(f"[dim]Track filter '{args.track}' applied.[/dim]")

    console.print(f"\n[bold]Phases to run:[/bold] {sorted(selected)}\n")

    # Optional QuickTime live device view (interactive only). Mirroring triggers anti-screen-capture
    # blur in some apps and isn't needed for evidence (screenshots come from Frida), so we ASK.
    if not args.auto:
        from rich.prompt import Confirm
        want_mirror = args.mirror or Confirm.ask(
            "[yellow]⚠ Open a QuickTime live device view?[/yellow] [bold]Warning:[/bold] for anti-screen-capture "
            "apps (e.g. Intune-MAM) mirroring sets UIScreen.isCaptured and the app blurs its UI — so the "
            "[bold]screenshots captured this run will ALSO be blurred[/bold]. Leave OFF for crisp report screenshots",
            default=False)
        if want_mirror:
            screenshotter.start_mirror()

    # ── Execute phases ──
    phase_runners = {
        1: lambda: run_decryption(config, device, frida),
        2: lambda: run_static_binary_analysis(config, device),
        3: lambda: run_local_storage_analysis(config, device),
        4: lambda: run_dump_verification(config, device),
        5: lambda: run_keychain_analysis(config, device, frida),
        6: lambda: run_snapshot_analysis(config, device, screenshotter),
        7: lambda: run_pasteboard_analysis(config, device, frida),
        8: lambda: run_syslog_monitoring(config, device),
        9: lambda: run_memory_analysis(config, device, frida),
        10: lambda: run_url_scheme_testing(config, device, frida, screenshotter),
        11: lambda: run_post_logout_testing(config, device, frida, screenshotter),
        12: lambda: run_backup_analysis(config, device),
        13: lambda: run_runtime_hardening(config, device, frida),
    }

    from rich.prompt import Confirm
    for phase_num in sorted(selected):
        phase_name = ALL_PHASES[phase_num][0]
        try:
            phase_runners[phase_num]()
        except KeyboardInterrupt:
            console.print(f"\n[yellow]Phase {phase_num} interrupted by user.[/yellow]")
            if not args.auto and not Confirm.ask("Continue to next phase?", default=True):
                break
        except Exception as e:
            console.print(f"\n[red]Error in {phase_name}: {e}[/red]")
            console.print(f"[dim]{traceback.format_exc()}[/dim]")
            config.add_finding(phase_name, "Phase execution error", "Info",
                               f"Phase {phase_num} encountered an error:\n{traceback.format_exc()}")
            if not args.auto and not Confirm.ask("Continue to next phase?", default=True):
                break

    screenshotter.stop_mirror()

    # ── Generate report ──
    if not args.auto:
        from rich.prompt import Confirm
        config.report_mode = "internal" if Confirm.ask(
            "Include the AI-prompt header in the report (internal mode)?",
            default=(args.report == "internal")) else "client"
    console.print("\n[bold cyan]═══ Generating Report ═══[/bold cyan]\n")
    reporter = ReportGenerator(config, device_info)
    report_path = reporter.generate()
    cleanup_manager.mark_final_report_generated()
    device.close()

    total_findings = sum(len(v) for v in config.findings.values())
    console.print(Panel(
        f"[bold green]iOS Assessment Complete[/bold green]\n\n"
        f"  Report:      {report_path}\n"
        f"  Findings:    {total_findings}\n"
        f"  Screenshots: {len(config.screenshots)}\n"
        f"  Commands:    {len(config.commands_log)}\n"
        f"  Output dir:  {config.output_dir}",
        title="Summary", style="green", expand=False,
    ))
    # ── Assemble the claude-runnable AI-review package (no PDF; keeps screenshots + raw logs) ──
    from core.ai_review import assemble_review_package
    pkg = assemble_review_package(config, device_info, report_path)
    from core.ai_review import run_claude_review, launch_claude_interactive, print_next_steps
    if args.ai_review:                       # explicit flag → headless, unattended
        run_claude_review(pkg, console)
    elif not args.auto:                      # interactive → let the operator choose
        from rich.prompt import Prompt
        console.print(
            "\n[bold]Triage this evidence package with an AI now?[/bold]\n"
            "  [cyan]1[/cyan]) Interactive [white]claude[/white] session  "
            "[dim](recommended — it can ask you to connect the phone / log out and verify live)[/dim]\n"
            "  [cyan]2[/cyan]) Headless [white]claude[/white]  "
            "[dim](streaming, unattended — writes final_report.md, no live Q&A)[/dim]\n"
            "  [cyan]3[/cyan]) Custom / cloud command  "
            "[dim]($TRASHIOS_REVIEW_CMD — OpenRouter / Ollama / aider)[/dim]\n"
            "  [cyan]4[/cyan]) Just show me the prompt  [dim](paste into any AI — claude.ai, ChatGPT, …)[/dim]"
        )
        choice = Prompt.ask("Choice", choices=["1", "2", "3", "4"], default="1")
        if choice == "1":
            launch_claude_interactive(pkg, console)
        elif choice == "2":
            run_claude_review(pkg, console)
        elif choice == "3":
            if not os.environ.get("TRASHIOS_REVIEW_CMD"):
                console.print("[yellow]$TRASHIOS_REVIEW_CMD is not set. Set it first, e.g.:[/yellow]\n"
                              "  [white]export TRASHIOS_REVIEW_CMD='aider --message-file {prompt_file} --yes'[/white]\n"
                              "[dim]Then re-run, or use ./run_review.sh in the package.[/dim]")
            else:
                run_claude_review(pkg, console)
    print_next_steps(pkg, config, console)
    return 0


if __name__ == "__main__":
    sys.exit(main())
