"""
Phase XI — Post-Logout / Session & Access-Control Testing.

After logout, proves (a) authenticated screens are still reachable via URL
schemes/deeplinks, and (b) session tokens persist locally (keychain / prefs)
instead of being cleared. The iOS counterpart of TrashDroid's post-logout
activity re-test — the relaunch vector is a URL scheme instead of `am start`.

Grounded in OWASP MASTG-TEST-0017 (session termination), MASVS-AUTH-2/-3.
"""

from __future__ import annotations

import re
import time

from rich.console import Console
from rich.panel import Panel

from core.config import Config
from core.ios_device import IOSDevice
from core.frida_bridge import FridaBridge
from core.screenshot import ScreenshotManager
from utils.helpers import grep_sensitive_lines

console = Console()
PHASE = "Phase XI — Post-Logout Access Control"

# Tokens whose survival after logout is a real finding.
_TOKEN_RE = re.compile(r"(auth[_\-]?token|access[_\-]?token|refresh[_\-]?token|session|bearer|jwt|"
                       r"password|secret|api[_\-]?key)", re.IGNORECASE)
_PRIV_DEEPLINKS = ["dashboard", "account", "profile", "settings", "wallet", "home"]


def run_post_logout_testing(config: Config, device: IOSDevice, frida: FridaBridge,
                            screenshotter: ScreenshotManager) -> None:
    """After logout, verify session tokens are cleared (keychain + preference plists) and that privileged deeplinks no longer reach authenticated screens; evidence is residual-token dumps and replayed-deeplink screenshots."""
    console.print(f"\n[bold cyan]═══ {PHASE} ═══[/bold cyan]\n")

    _perform_logout(config, device)
    time.sleep(2)

    _check_token_persistence(config, device, frida)
    _retest_deeplinks(config, device, frida, screenshotter)

    console.print(f"\n[green]✓ {PHASE} complete.[/green]")


def _perform_logout(config: Config, device: IOSDevice) -> None:
    if config.auto_mode:
        console.print("[yellow]Auto-mode: cannot drive UI logout automatically — relaunching app and "
                      "checking local token persistence (server-side logout not exercised).[/yellow]")
        device.force_stop(config.bundle_id)
        device.launch_app(config.bundle_id)
        time.sleep(3)
        return
    console.print(Panel("Please LOG OUT of the application now, then press Enter.\n"
                        "(Do NOT clear app data — we want to see whether logout itself clears local secrets.)",
                        style="bold yellow"))
    input()


def _check_token_persistence(config: Config, device: IOSDevice, frida: FridaBridge) -> None:
    console.print("[cyan]Checking for residual tokens after logout...[/cyan]")

    # 1) Keychain re-dump
    if frida.verify_connection():
        _ensure_running(config, device)
        items, _err = frida.keychain_dump()
        kc_text = "\n".join(
            f"[{it.get('cls')}] {it.get('service') or '?'}/{it.get('account') or '?'} "
            f"accessible={it.get('accessible')}: {it.get('data')}"
            for it in items
        )
        (config.output_dir / "keychain" / "keychain_post_logout.txt").write_text(kc_text, encoding="utf-8")
        residual = [ln for ln in kc_text.splitlines() if _TOKEN_RE.search(ln)]
        if residual:
            config.add_finding(
                PHASE, "Session token persists in keychain after logout", "High",
                "After logout, the keychain still contains token/session/credential material — the session "
                "was not invalidated locally. Verified via keychain dump.\n\nResidual entries:\n"
                + "\n".join(residual[:40]),
            )
        else:
            console.print("  [green]No obvious token material left in keychain.[/green]")

    # 2) Preferences plist re-pull
    if device.caps.ssh and (config.data_container or device.get_data_container(config.bundle_id)):
        data = config.data_container or device.get_data_container(config.bundle_id)
        dest = config.output_dir / "post_logout_prefs"
        dest.mkdir(parents=True, exist_ok=True)
        device.pull_as_root(f"{data}/Library/Preferences", str(dest))
        hits = []
        for p in dest.rglob("*.plist"):
            try:
                txt = p.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue
            if _TOKEN_RE.search(txt):
                hits.append(f"### {p.name}\n{grep_sensitive_lines(txt, max_lines=20)}")
        if hits:
            config.add_finding(
                PHASE, "Token persists in plist/NSUserDefaults after logout", "High",
                "After logout, preference plists still contain token/session material (extracted from container). "
                "Clear all auth state on logout.\n\n" + "\n\n".join(hits[:10]),
            )
        else:
            console.print("  [green]No token material left in preference plists.[/green]")


def _retest_deeplinks(config: Config, device: IOSDevice, frida: FridaBridge,
                      screenshotter: ScreenshotManager) -> None:
    # Reuse the schemes discovered in the URL-scheme phase (re-enumerate from the bundle).
    from phases.url_schemes import _enumerate_schemes
    schemes = _enumerate_schemes(config, device)
    if not schemes:
        console.print("  [yellow]No URL schemes to replay post-logout.[/yellow]")
        return

    uiopen_ok = bool(device.caps.ssh and device.shell_output("which uiopen 2>/dev/null"))
    use_frida = (not uiopen_ok) and frida.verify_connection()
    if not uiopen_ok and not use_frida:
        console.print("  [yellow]Neither uiopen nor Frida available — skipping deeplink re-test.[/yellow]")
        return
    if use_frida:
        device.launch_app(config.bundle_id)
        time.sleep(3)

    console.print("[cyan]Replaying privileged deeplinks after logout...[/cyan]")
    fired = []
    for scheme in schemes[:2]:
        for target in _PRIV_DEEPLINKS:
            url = f"{scheme}://{target}"
            if uiopen_ok:
                device.force_stop(config.bundle_id)
                device.shell(f"uiopen '{url}'")
            else:
                frida.open_url(url)
            config.log_command(PHASE, f"replay '{url}' (post-logout)", "fired")
            shot = screenshotter.capture("post_logout_deeplink", f"{scheme}_{target}", delay=2.5)
            if shot:
                config.add_screenshot(shot, f"Post-logout deeplink: {url}", PHASE)
            fired.append(url)

    if fired:
        config.add_finding(
            PHASE, "Privileged deeplinks replayed after logout (verify access control)", "High",
            "Privileged-screen deeplinks were fired after logout. Review the attached screenshots: if any "
            "authenticated screen rendered its content (rather than a login wall), the app has broken access "
            "control / does not enforce server-side session validation. Deeplinks replayed:\n  - "
            + "\n  - ".join(fired),
        )


def _ensure_running(config: Config, device: IOSDevice) -> None:
    if not device.get_pid(config.bundle_id):
        device.launch_app(config.bundle_id)
        time.sleep(3)
