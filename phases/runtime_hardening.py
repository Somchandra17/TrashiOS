"""
Phase XIII — Runtime Hardening Assessment.

Probes the app's defensive controls by attempting to bypass them with objection
and observing the result: certificate pinning, jailbreak detection, and
anti-debugging. Bypass output tells us whether a control is present (objection
hooks the relevant APIs) or absent (nothing to hook / app already runs freely on
a jailbroken device).

These are defense-in-depth signals — findings are recorded as needing manual
validation (confirm pinning with a MitM proxy). Grounded in OWASP MASTG
RESILIENCE (anti-debug/JB detection/pinning), MASVS-RESILIENCE-1/-2/-4.
"""

from __future__ import annotations

import time

from rich.console import Console

from core.config import Config
from core.ios_device import IOSDevice
from core.frida_bridge import FridaBridge

console = Console()
PHASE = "Phase XIII — Runtime Hardening Assessment"

# objection bypass output keywords indicating a control was actually hooked (=present).
_PINNING_HOOKS = ("ssl", "pinning", "sectrust", "nsurlsession", "tlstrust", "afnetworking", "trustkit")
_JB_HOOKS = ("jailbreak", "/applications/cydia", "fork", "stat", "fopen", "canopenurl", "jailbroken")


def run_runtime_hardening(config: Config, device: IOSDevice, frida: FridaBridge) -> None:
    console.print(f"\n[bold cyan]═══ {PHASE} ═══[/bold cyan]\n")

    if not frida.verify_connection():
        console.print("[yellow]frida-server not reachable — skipping hardening assessment.[/yellow]")
        config.add_finding(PHASE, "Runtime hardening assessment skipped — Frida unavailable", "Info",
                           "Requires frida-server + objection to attempt control bypasses.")
        return

    if not device.get_pid(config.bundle_id):
        device.launch_app(config.bundle_id)
        time.sleep(3)

    _assess_pinning(config, frida)
    _assess_jailbreak(config, frida)
    _assess_antidebug(config, device)

    console.print(f"\n[green]✓ {PHASE} complete.[/green]")


def _assess_pinning(config: Config, frida: FridaBridge) -> None:
    console.print("[cyan]Probing SSL/TLS certificate pinning (objection)...[/cyan]")
    res = frida.disable_sslpinning()
    out = (res.raw_stdout or res.stdout or "").lower()
    config.log_command(PHASE, "objection: ios sslpinning disable", res.stdout or res.stderr)
    hooked = any(k in out for k in _PINNING_HOOKS) and ("hook" in out or "found" in out or "disabl" in out)
    if hooked:
        config.add_finding(PHASE, "Certificate pinning present (positive control)", "Info",
                           "objection hooked pinning-related APIs — the app appears to implement certificate/"
                           "public-key pinning. Confirm strength with a MitM proxy (traffic should fail without "
                           "the bypass).")
    else:
        config.add_finding(PHASE, "No certificate pinning detected", "Medium",
                           "objection found no pinning APIs to hook — the app likely does not pin certificates, so a "
                           "network attacker with a trusted CA can MitM its traffic. Confirm with a MitM proxy "
                           "(traffic flows without any bypass). May indicate missing pinning.")


def _assess_jailbreak(config: Config, frida: FridaBridge) -> None:
    console.print("[cyan]Probing jailbreak detection (objection)...[/cyan]")
    res = frida.disable_jailbreak_detect()
    out = (res.raw_stdout or res.stdout or "").lower()
    config.log_command(PHASE, "objection: ios jailbreak disable", res.stdout or res.stderr)
    hooked = any(k in out for k in _JB_HOOKS)
    if hooked:
        config.add_finding(PHASE, "Jailbreak detection present (positive control)", "Info",
                           "objection hooked jailbreak-detection routines — the app implements some JB detection "
                           "(it was bypassable here, which is expected; strength varies).")
    else:
        config.add_finding(PHASE, "No jailbreak detection detected", "Low",
                           "The app ran on a jailbroken device without objection needing to hook any JB-detection "
                           "routine — it likely performs no jailbreak detection (defense-in-depth gap). "
                           "May indicate missing anti-tamper.")


def _assess_antidebug(config: Config, device: IOSDevice) -> None:
    # Anti-debug correlates with get-task-allow (covered statically) + ptrace(PT_DENY_ATTACH).
    # If Frida/lldb attached at all this run, PT_DENY_ATTACH is clearly not enforced.
    config.add_finding(PHASE, "No effective anti-debugging observed", "Low",
                       "A debugger/instrumentation (Frida) attached to the running app this session, so "
                       "ptrace(PT_DENY_ATTACH)/sysctl anti-debug is not effectively enforced (defense-in-depth gap). "
                       "Cross-check the get-task-allow entitlement from the Static Binary phase. Needs manual validation.")
