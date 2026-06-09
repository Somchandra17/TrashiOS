"""
Phase III — Keychain Dump & Data-Protection-Class Assessment.

Dumps the keychain items the app stored (via objection) and assesses the
kSecAttrAccessible* protection class of each: items accessible regardless of
lock state, or that are not ThisDeviceOnly (so they migrate via backup/iCloud),
are weaker than they should be.

Grounded in OWASP MASTG-TECH-0061 / MASTG-TEST-0055, MASVS-STORAGE-1/-2.
"""

from __future__ import annotations

import json
import time
from pathlib import Path

from rich.console import Console
from rich.panel import Panel

from core.config import Config
from core.ios_device import IOSDevice
from core.frida_bridge import FridaBridge
from utils.helpers import presidio_scan_text, presidio_findings_to_report

console = Console()
PHASE = "Phase V — Keychain Dump & Data Protection"


def run_keychain_analysis(config: Config, device: IOSDevice, frida: FridaBridge) -> None:
    console.print(f"\n[bold cyan]═══ {PHASE} ═══[/bold cyan]\n")

    if not frida.verify_connection():
        console.print("[yellow]frida-server not reachable — cannot dump keychain. Skipping.[/yellow]")
        config.add_finding(PHASE, "Keychain dump skipped — Frida unavailable", "Info",
                           "frida-server must be reachable over USB (frida-ps -U) to dump the keychain.")
        return

    if not config.auto_mode:
        console.print(Panel("Ensure the app is LOGGED IN so the keychain holds its secrets, then press Enter.",
                            style="bold yellow"))
        input()

    # objection attaches to the running app — make sure it's running.
    _ensure_running(config, device)

    console.print("[cyan]Dumping keychain via objection...[/cyan]")
    json_path = (config.output_dir / "keychain" / "keychain.json").resolve()
    res = frida._objection_run(f"ios keychain dump --json {json_path}")
    config.log_command(PHASE, "objection: ios keychain dump --json", res.stdout or res.stderr)

    items = _load_items(json_path, res.stdout)
    if not items:
        # Last resort: a plain dump for evidence
        plain = frida.keychain_dump()
        (config.output_dir / "keychain" / "keychain_dump.txt").write_text(
            plain.raw_stdout or plain.stdout, encoding="utf-8")
        if not plain.success or not plain.stdout.strip():
            # Distinguish a real attach/dump failure from a genuinely empty keychain.
            diag = (res.stderr or plain.stderr or res.raw_stdout or "").strip()
            attach_failed = any(s in diag.lower() for s in
                                ("failed to", "unable to", "not found", "needsbridge", "frida"))
            if attach_failed:
                console.print(f"[yellow]Keychain dump failed (objection could not attach / run).[/yellow]")
                console.print(f"[dim]  {diag[:300]}[/dim]")
                config.add_finding(PHASE, "Keychain dump failed (instrumentation error)", "Info",
                                   "objection could not attach to the app or run the keychain module — possibly "
                                   "anti-debug / managed-app (Intune MAM) protection, or the app was not running. "
                                   f"Diagnostic:\n{diag[:800]}\nRaw output saved to keychain/keychain_dump.txt.")
            else:
                console.print("[yellow]No keychain items returned (keychain appears empty for this app).[/yellow]")
                config.add_finding(PHASE, "Keychain empty for this app", "Info",
                                   "objection attached but returned no keychain items. The app may store secrets "
                                   "in files/NSUserDefaults instead (see the Local Data Storage phase) rather than "
                                   "the keychain. Confirm the app was logged in.")
            return
        items = _parse_text_dump(plain.stdout)

    console.print(f"  [green]{len(items)} keychain item(s) retrieved.[/green]")
    _assess_items(config, items)

    console.print(f"\n[green]✓ {PHASE} complete.[/green]")


def _ensure_running(config: Config, device: IOSDevice) -> None:
    pid = device.get_pid(config.bundle_id)
    if not pid:
        console.print("  [cyan]Launching app for keychain context...[/cyan]")
        device.launch_app(config.bundle_id)
        time.sleep(4)


def _load_items(json_path: Path, stdout: str) -> list[dict]:
    if json_path.exists():
        try:
            data = json.loads(json_path.read_text(encoding="utf-8"))
            if isinstance(data, list):
                return data
            if isinstance(data, dict):
                # some objection versions wrap under a key
                for v in data.values():
                    if isinstance(v, list):
                        return v
        except Exception:
            pass
    return []


def _accessible_of(item: dict) -> str:
    for k, v in item.items():
        if "access" in k.lower() and isinstance(v, str) and "kSecAttrAccessible" in v:
            return v
        if k.lower() in ("accessible", "accessible_attribute", "protection") and isinstance(v, str):
            return v
    return item.get("accessible", "") or ""


def _field(item: dict, *names: str) -> str:
    for n in names:
        for k, v in item.items():
            if k.lower() == n and v:
                return str(v)
    return ""


def _assess_items(config: Config, items: list[dict]) -> None:
    secret_blob_parts: list[str] = []
    weak_always = 0
    not_device_only = 0

    for it in items:
        accessible = _accessible_of(it)
        acc_l = accessible.lower()
        account = _field(it, "account", "acct")
        service = _field(it, "service", "svce")
        data_val = _field(it, "data", "v_data", "value")
        label = f"{service or '?'} / {account or '?'}"
        if data_val:
            secret_blob_parts.append(f"{label}: {data_val}")

        if "always" in acc_l:
            weak_always += 1
            config.add_finding(
                PHASE, f"Keychain item accessible regardless of lock state: {label}", "High",
                f"Item uses {accessible or 'kSecAttrAccessibleAlways'} — readable even when the device is locked, "
                f"and recoverable from a lost/stolen device. Account='{account}', Service='{service}'. "
                "Verified via keychain dump.",
            )
        elif accessible and "thisdeviceonly" not in acc_l:
            not_device_only += 1
            sev = "Medium" if "afterfirstunlock" in acc_l else "Low"
            config.add_finding(
                PHASE, f"Keychain item not ThisDeviceOnly: {label}", sev,
                f"Item uses {accessible} (not *ThisDeviceOnly) — it migrates to a new device via encrypted "
                f"backup/iCloud Keychain. Prefer a ...ThisDeviceOnly class for app secrets. "
                f"Account='{account}', Service='{service}'. Verified via keychain dump.",
            )

    # Treat recovered secret material as a finding (PII/credentials in keychain values).
    if secret_blob_parts:
        blob = "\n".join(secret_blob_parts)
        (config.output_dir / "keychain" / "keychain_values.txt").write_text(blob, encoding="utf-8")
        findings = presidio_scan_text(blob, config, source_label="keychain")
        if findings:
            presidio_findings_to_report(
                findings, PHASE, config,
                fallback_title="Credentials recoverable from keychain",
                fallback_detail="Keychain item values contain sensitive material recoverable from the device. "
                                "Verified via keychain dump.",
            )

    if weak_always == 0 and not_device_only == 0:
        config.add_finding(PHASE, f"Keychain protection classes acceptable ({len(items)} items)", "Info",
                           "No items used kSecAttrAccessibleAlways and none lacked ThisDeviceOnly scoping. "
                           "Confirm long-lived tokens still warrant WhenPasscodeSetThisDeviceOnly.")


def _parse_text_dump(stdout: str) -> list[dict]:
    """Fallback: parse objection's text table into dicts (best-effort)."""
    items: list[dict] = []
    header: list[str] = []
    for line in stdout.splitlines():
        cells = [c.strip() for c in line.split("  ") if c.strip()]
        if not cells:
            continue
        low = line.lower()
        if not header and ("account" in low or "service" in low) and "data" in low:
            header = [c.lower() for c in cells]
            continue
        if header and len(cells) >= 2:
            items.append({header[i]: cells[i] for i in range(min(len(header), len(cells)))})
    return items
