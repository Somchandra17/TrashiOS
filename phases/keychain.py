"""
Phase V — Keychain Dump & Data-Protection-Class Assessment.

Dumps keychain items via a raw Frida agent (SecItemCopyMatching — objection-free
and Frida-17 compatible), then assesses each item's kSecAttrAccessible protection
class: items accessible while the device is locked (kSecAttrAccessibleAlways) or
that are not ThisDeviceOnly (so they migrate via encrypted backup / iCloud
Keychain) are weaker than they should be. Item data is scanned for secrets.

Grounded in OWASP MASTG-TECH-0061 / MASTG-TEST-0055, MASVS-STORAGE-1/-2.
"""

from __future__ import annotations

import json

from rich.console import Console
from rich.panel import Panel

from core.config import Config
from core.ios_device import IOSDevice
from core.frida_bridge import FridaBridge
from utils.helpers import presidio_scan_text, presidio_findings_to_report

console = Console()
PHASE = "Phase V — Keychain Dump & Data Protection"

# kSecAttrAccessible protection classes, keyed by the on-disk "pdmn" code.
# value = (readable name, this_device_only, accessible_while_locked)
_PDMN = {
    "ak":   ("WhenUnlocked", False),
    "ck":   ("AfterFirstUnlock", False),
    "dk":   ("Always", False),
    "aku":  ("WhenUnlockedThisDeviceOnly", True),
    "cku":  ("AfterFirstUnlockThisDeviceOnly", True),
    "dku":  ("AlwaysThisDeviceOnly", True),
    "akpu": ("WhenPasscodeSetThisDeviceOnly", True),
}


def _label(code) -> str:
    info = _PDMN.get(code)
    return info[0] if info else (code or "unknown")


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

    console.print("[cyan]Dumping keychain via Frida (SecItemCopyMatching)...[/cyan]")
    items, err = frida.keychain_dump()
    config.log_command(PHASE, "frida: SecItemCopyMatching (all security classes)",
                       f"{len(items)} item(s)" if items else (err or "no items"))

    if not items and err:
        console.print(f"[yellow]Keychain dump failed: {err}[/yellow]")
        config.add_finding(PHASE, "Keychain dump failed (instrumentation error)", "Info",
                           f"Could not dump the keychain via Frida. Reason: {err}\n"
                           "Common cause: anti-debug / managed-app (Intune MAM) protection, or the app not running.")
        return
    if not items:
        console.print("[yellow]No keychain items (empty for this app's access groups).[/yellow]")
        config.add_finding(PHASE, "Keychain empty for this app", "Info",
                           "Frida attached but SecItemCopyMatching returned no items for the app's keychain access "
                           "groups. The app may store secrets in files / NSUserDefaults instead — see Local Storage.")
        return

    console.print(f"  [green]{len(items)} keychain item(s) dumped.[/green]")
    _write_evidence(config, items)
    _assess_protection_classes(config, items)
    _scan_secrets(config, items)
    console.print(f"\n[green]✓ {PHASE} complete.[/green]")


def _write_evidence(config: Config, items: list[dict]) -> None:
    kdir = config.output_dir / "keychain"
    kdir.mkdir(parents=True, exist_ok=True)
    (kdir / "keychain_items.json").write_text(json.dumps(items, indent=2, default=str), encoding="utf-8")
    values = "\n".join(
        f"[{it.get('cls')}] {it.get('service') or '?'} / {it.get('account') or '?'} "
        f"(accessible={it.get('accessible')}={_label(it.get('accessible'))}, group={it.get('agrp')}):\n  {it.get('data')}"
        for it in items if it.get("data")
    )
    if values:
        (kdir / "keychain_values.txt").write_text(values, encoding="utf-8")


def _assess_protection_classes(config: Config, items: list[dict]) -> None:
    always_not_device, always_device, not_device_only, unknown = [], [], [], []
    for it in items:
        code = (it.get("accessible") or "").strip()
        info = _PDMN.get(code)
        tag = (f"{it.get('service') or it.get('account') or '?'} "
               f"(class={code or '?'}={_label(code)}, group={it.get('agrp')})")
        if not info:
            unknown.append(tag)
            continue
        _, device_only = info
        if code == "dk":
            always_not_device.append(tag)
        elif code == "dku":
            always_device.append(tag)
        elif not device_only:
            not_device_only.append(tag)

    if always_not_device:
        config.add_finding(PHASE,
                           f"Keychain items accessible while locked & not device-bound ({len(always_not_device)})",
                           "High",
                           "kSecAttrAccessibleAlways: readable even when the device is locked AND migrates via "
                           "encrypted backup / iCloud Keychain. Use the strictest class that fits "
                           "(prefer ...WhenPasscodeSetThisDeviceOnly).\n  - " + "\n  - ".join(always_not_device[:40]))
    if always_device:
        config.add_finding(PHASE, f"Keychain items accessible while device is locked ({len(always_device)})",
                           "Medium",
                           "kSecAttrAccessibleAlwaysThisDeviceOnly: readable even when the device is locked "
                           "(device-bound, so no migration). Prefer a When-Unlocked / passcode-set class.\n  - "
                           + "\n  - ".join(always_device[:40]))
    if not_device_only:
        config.add_finding(PHASE, f"Keychain items not ThisDeviceOnly ({len(not_device_only)})", "Medium",
                           "These items are NOT ...ThisDeviceOnly, so they migrate to a new device via encrypted "
                           "backup / iCloud Keychain. Scope app secrets to a *ThisDeviceOnly class.\n  - "
                           + "\n  - ".join(not_device_only[:40]))
    if not (always_not_device or always_device or not_device_only):
        config.add_finding(PHASE, f"Keychain protection classes acceptable ({len(items)} items)", "Info",
                           "All items use ThisDeviceOnly classes and none use kSecAttrAccessibleAlways. "
                           "Confirm long-lived tokens warrant WhenPasscodeSetThisDeviceOnly.")


def _scan_secrets(config: Config, items: list[dict]) -> None:
    blob = "\n".join(
        f"{it.get('service') or ''} {it.get('account') or ''}: {it.get('data')}"
        for it in items
        if it.get("data") and not str(it.get("data")).startswith("<binary")
    )
    if not blob.strip():
        return
    findings = presidio_scan_text(blob, config, source_label="keychain")
    if findings:
        presidio_findings_to_report(
            findings, PHASE, config,
            fallback_title="Credentials recoverable from keychain",
            fallback_detail="Keychain item values (recovered from this device via Frida) contain sensitive material. "
                            "Verified via SecItemCopyMatching dump.",
        )
    else:
        config.add_finding(PHASE, f"Keychain contents recoverable on jailbroken device ({len(items)} items)", "Medium",
                           "All keychain items for the app's access groups were dumped via Frida on this jailbroken "
                           "device (accounts, services, data). Protection classes apply on a non-jailbroken device, "
                           "but on a compromised/jailbroken device the contents are recoverable. "
                           "Evidence: keychain/keychain_items.json.")
