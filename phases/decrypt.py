"""
Phase I — App Binary Decryption.

App Store binaries are FairPlay-encrypted (Mach-O cryptid=1), which blocks
meaningful disassembly and string extraction of __TEXT. This phase uses
frida-ios-dump to produce a decrypted .ipa (over the iproxy SSH tunnel that
IOSDevice already established), unzips the decrypted .app, and re-scans the
binary for secrets that were hidden by encryption.

DRM-stripping — gated behind explicit consent (--decrypt, or an interactive
prompt; default OFF in --auto). Authorized testing only.

Grounded in OWASP MASTG iOS binary acquisition/decryption.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import zipfile
from pathlib import Path

from rich.console import Console
from rich.prompt import Confirm

from core.config import Config
from core.ios_device import IOSDevice
from core.frida_bridge import FridaBridge
from utils.helpers import presidio_scan_file, presidio_findings_to_report

console = Console()
PHASE = "Phase I — App Binary Decryption"


def run_decryption(config: Config, device: IOSDevice, frida: FridaBridge) -> None:
    console.print(f"\n[bold cyan]═══ {PHASE} ═══[/bold cyan]\n")

    # ── Consent gate (DRM) ──
    if not config.allow_decrypt:
        if config.auto_mode:
            console.print("[yellow]Decryption skipped (--decrypt not set; off by default in --auto).[/yellow]")
            config.add_finding(PHASE, "Binary decryption skipped (no consent)", "Info",
                               "FairPlay decryption strips DRM and was not authorized for this run. "
                               "Pass --decrypt (authorized testing only) to enable. Static analysis proceeds on the "
                               "encrypted binary; runtime secret recovery is available in the Memory phase.")
            return
        if not Confirm.ask("Decrypt the app binary (strips FairPlay DRM — authorized testing only)?", default=False):
            config.add_finding(PHASE, "Binary decryption declined", "Info",
                               "Operator declined FairPlay decryption. Static analysis proceeds on the encrypted binary.")
            return

    runner = _find_dump_tool()
    if not runner:
        console.print("[yellow]frida-ios-dump not found — skipping decryption.[/yellow]")
        config.add_finding(PHASE, "Decryption tool unavailable", "Info",
                           "frida-ios-dump is not installed. Install it (https://github.com/AloneMonkey/frida-ios-dump) "
                           "and either put it on PATH as `frida-ios-dump` or set FRIDA_IOS_DUMP=/path/to/dump.py. "
                           "The iproxy SSH tunnel TrashiOS opens on the local SSH port is reused automatically.")
        return

    if not frida.verify_connection():
        console.print("[yellow]frida-server not reachable — cannot decrypt. Skipping.[/yellow]")
        config.add_finding(PHASE, "Decryption skipped — Frida unavailable", "Info",
                           "frida-ios-dump needs frida-server reachable over USB (frida-ps -U).")
        return

    out_ipa = config.output_dir / "bundle_decrypted" / f"{config.bundle_id}.ipa"
    out_ipa.parent.mkdir(parents=True, exist_ok=True)

    console.print(f"[cyan]Running frida-ios-dump for {config.bundle_id} (via iproxy tunnel on port {device.local_port})...[/cyan]")
    ok = _run_dump(runner, device, config.bundle_id, str(out_ipa))
    config.log_command(PHASE, f"frida-ios-dump -> {out_ipa}", "ok" if ok else "failed")

    if not ok or not out_ipa.exists():
        console.print("[yellow]Decryption did not produce an IPA.[/yellow]")
        config.add_finding(PHASE, "Decryption failed", "Info",
                           "frida-ios-dump ran but produced no IPA. Common causes: SSH port mismatch (tool defaults to "
                           f"localhost:2222 — TrashiOS tunnels device:{device.ssh_device_port} there), missing on-device "
                           "deps (the tool installs them via SSH), or anti-instrumentation in a managed app.")
        return

    app_dir = _unzip_decrypted(out_ipa, config.output_dir / "bundle_decrypted")
    if not app_dir:
        console.print("[yellow]Could not unzip the decrypted IPA.[/yellow]")
        return
    config.decrypted_bundle = str(app_dir)
    console.print(f"  [green]Decrypted bundle:[/green] {app_dir}")

    _verify_and_scan(config, app_dir)
    console.print(f"\n[green]✓ {PHASE} complete.[/green]")


def _find_dump_tool() -> list[str] | None:
    env = os.environ.get("FRIDA_IOS_DUMP")
    if env and Path(env).exists():
        return ["python3", env]
    w = shutil.which("frida-ios-dump")
    if w:
        return [w]
    w = shutil.which("dump.py")
    if w:
        return ["python3", w]
    return None


def _run_dump(runner: list[str], device: IOSDevice, bundle_id: str, out_ipa: str) -> bool:
    # Modern frida-ios-dump accepts -H/-p/-u/-P/-o; older defaults to localhost:2222.
    attempts = [
        runner + ["-H", "127.0.0.1", "-p", str(device.local_port), "-u", "root",
                  "-P", device.ssh_pw, "-o", out_ipa, bundle_id],
        runner + ["-o", out_ipa, bundle_id],
    ]
    for argv in attempts:
        try:
            r = subprocess.run(argv, capture_output=True, text=True, timeout=600)
        except (FileNotFoundError, subprocess.TimeoutExpired):
            continue
        blob = (r.stdout + r.stderr).lower()
        if Path(out_ipa).exists():
            return True
        if "unrecognized" not in blob and "usage:" not in blob and r.returncode == 0:
            return Path(out_ipa).exists()
    return Path(out_ipa).exists()


def _unzip_decrypted(ipa: Path, dest: Path) -> Path | None:
    try:
        with zipfile.ZipFile(ipa) as zf:
            zf.extractall(dest)
        apps = list((dest / "Payload").glob("*.app")) if (dest / "Payload").exists() else []
        return apps[0] if apps else None
    except Exception:
        return None


def _verify_and_scan(config: Config, app_dir: Path) -> None:
    # Locate the main binary and confirm cryptid=0, then scan for newly-revealed secrets.
    import plistlib
    exe = None
    info = app_dir / "Info.plist"
    if info.exists():
        try:
            with open(info, "rb") as fh:
                exe = plistlib.load(fh).get("CFBundleExecutable")
        except Exception:
            pass
    binary = (app_dir / exe) if exe else None
    if not binary or not binary.exists():
        cands = [f for f in app_dir.iterdir() if f.is_file() and f.stat().st_mode & 0o111]
        binary = cands[0] if cands else None
    if not binary:
        return

    if shutil.which("otool"):
        lc = subprocess.run(["otool", "-l", str(binary)], capture_output=True, text=True, timeout=60).stdout
        if "cryptid 0" in lc.replace("  ", " "):
            config.add_finding(PHASE, "Binary successfully decrypted (cryptid=0)", "Info",
                               f"frida-ios-dump produced a decrypted Mach-O ({binary.name}); full static analysis "
                               "(class-dump / strings / disassembler) is now possible.")
        config.log_command(PHASE, f"otool -l {binary.name} | grep cryptid", "checked")

    findings = presidio_scan_file(str(binary), config, source_label=f"decrypted:{binary.name}")
    if findings:
        presidio_findings_to_report(
            findings, PHASE, config,
            fallback_title="Hardcoded secret in decrypted binary",
            fallback_detail="Secrets recovered from the decrypted binary (were hidden by FairPlay encryption).",
        )
