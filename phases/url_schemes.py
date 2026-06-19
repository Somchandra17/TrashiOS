"""
Phase V — URL Scheme / IPC Testing (the iOS analogue of Drozer component testing).

iOS has no exported Activities/Services/Receivers/Providers; the app's external
entry points are custom URL schemes, Universal Links, and app extensions. This
phase enumerates declared CFBundleURLTypes and fires each scheme with benign,
privileged-action, and injection payloads via `uiopen`, screenshotting the
result for analyst review.

Because firing a URL has no programmatic success oracle, findings here are
recorded as attack surface requiring manual validation (the report marks them
'Needs manual validation'); the screenshots are the evidence.

Grounded in OWASP MASTG-TEST-0070/-0071/-0075, MASVS-PLATFORM-1/-3.
"""

from __future__ import annotations

import plistlib
import subprocess
import time
from pathlib import Path

from rich.console import Console
from rich.table import Table

from core.config import Config
from core.ios_device import IOSDevice
from core.frida_bridge import FridaBridge
from core.screenshot import ScreenshotManager

console = Console()
PHASE = "Phase X — URL Scheme / IPC Testing"

# Payload suffixes appended to each "<scheme>://" entry point.
_PAYLOADS = [
    ("", "base scheme"),
    ("dashboard", "privileged screen"),
    ("?role=admin&bypass_auth=true", "privilege params"),
    ("open?redirect_uri=https://evil.example", "open redirect"),
    ("item?id=1'%20OR%20'1'='1", "SQL injection"),
    ("file?path=../../../../etc/passwd", "path traversal"),
    ("login?token=injected_token", "auth token inject"),
]

# Only screenshot the payloads likely to show a meaningful UI state (keeps runtime sane).
_SCREENSHOT_LABELS = {"base scheme", "privileged screen"}


def run_url_scheme_testing(config: Config, device: IOSDevice, frida: FridaBridge,
                           screenshotter: ScreenshotManager) -> None:
    console.print(f"\n[bold cyan]═══ {PHASE} ═══[/bold cyan]\n")

    schemes = _enumerate_schemes(config, device)
    if not schemes:
        console.print("  [yellow]No custom URL schemes declared (CFBundleURLTypes empty).[/yellow]")
        config.add_finding(PHASE, "No custom URL schemes declared", "Info",
                           "The app declares no CFBundleURLTypes. Universal Links / app extensions may still exist "
                           "(test manually). No custom-scheme attack surface from Info.plist.")
        return

    console.print(f"  [green]URL scheme(s):[/green] {', '.join(schemes)}")

    # Choose a fire method: uiopen (uikittools) if present, else Frida openURL.
    uiopen_path = _resolve_uiopen(device)
    if uiopen_path:
        method = "uiopen"
        console.print(f"  [green]uiopen found:[/green] {uiopen_path}  [dim](cold-launch via scheme)[/dim]")
    elif frida.verify_connection():
        method = "frida"
        console.print("  [cyan]uiopen not on device — firing URLs via Frida (UIApplication openURL:).[/cyan]")
        device.launch_app(config.bundle_id)  # app must be running for openURL
        time.sleep(3)
    else:
        method = None
        console.print("  [yellow]Neither uiopen nor Frida available — recording schemes as attack surface only.[/yellow]")

    table = Table(title="URL Scheme Fuzzing")
    table.add_column("URL")
    table.add_column("Payload")
    table.add_column("Fired")

    # Build the full (url, label, scheme) list once.
    entries = [(f"{scheme}://{suffix}", label, scheme) for scheme in schemes for suffix, label in _PAYLOADS]
    results: dict[str, bool] = {}
    fired_log: list[str] = []

    def _maybe_shot(url: str, label: str, scheme: str) -> None:
        if label in _SCREENSHOT_LABELS:
            shot = screenshotter.capture("url_scheme", f"{scheme}_{label}", delay=2.0)
            if shot:
                config.add_screenshot(shot, f"URL scheme: {url} ({label})", PHASE)

    if method == "frida":
        # One Frida attach for ALL urls (fast + reliable); screenshot the curated labels.
        meta = {u: (label, scheme) for u, label, scheme in entries}

        def _on_fired(u: str, ok: bool) -> None:
            label, scheme = meta[u]
            config.log_command(PHASE, f"frida openURL '{u}'", "ok" if ok else "fail")
            if ok:
                _maybe_shot(u, label, scheme)

        results = frida.open_urls([u for u, _, _ in entries], settle=1.0, on_fired=_on_fired)
    elif method == "uiopen":
        for url, label, scheme in entries:
            device.force_stop(config.bundle_id)
            r = device.shell(f"{uiopen_path} '{url}'")
            ok = r.returncode == 0
            results[url] = ok
            config.log_command(PHASE, f"{uiopen_path} '{url}'", (r.stdout or r.stderr).strip())
            if ok:
                _maybe_shot(url, label, scheme)

    for url, label, scheme in entries:
        ok = results.get(url, False)
        fired_log.append(f"  {url}    [{label}]" + ("" if ok else "  (not fired)"))
        table.add_row(url[:50], label, "[green]yes[/green]" if ok else "[yellow]no[/yellow]")

    console.print(table)

    # Attack-surface finding (manual validation required — drives the report's confidence heuristic).
    config.add_finding(
        PHASE, f"Custom URL scheme entry points exposed: {', '.join(schemes)}", "Medium",
        "The app handles custom URL scheme(s) reachable by any other app or a malicious web link. "
        "Each must authenticate + authorize the action and validate/sanitize parameters. "
        "The following payloads were fired (review the attached screenshots to confirm whether any "
        "performed an unauthenticated/privileged action or reflected injected input — may indicate "
        "broken access control or injection):\n\n" + "\n".join(fired_log),
    )

    console.print(f"\n[green]✓ {PHASE} complete.[/green]")


def _enumerate_schemes(config: Config, device: IOSDevice) -> list[str]:
    plist = _find_local_info_plist(config) or _pull_info_plist(config, device)
    if not plist:
        return []
    schemes: list[str] = []
    for ut in plist.get("CFBundleURLTypes", []) or []:
        schemes.extend(ut.get("CFBundleURLSchemes", []) or [])
    # de-dupe, drop common framework/system schemes that aren't app entry points
    seen, out = set(), []
    for s in schemes:
        if s and s not in seen:
            seen.add(s)
            out.append(s)
    return out


def _find_local_info_plist(config: Config) -> dict | None:
    base = config.output_dir / "bundle"
    candidates = list(base.glob("Payload/*.app/Info.plist")) + list(base.glob("*.app/Info.plist"))
    for c in candidates:
        pl = _load_plist(c)
        if pl:
            return pl
    return None


def _pull_info_plist(config: Config, device: IOSDevice) -> dict | None:
    bundle = config.bundle_container or device.get_bundle_container(config.bundle_id)
    if not bundle or not device.caps.ssh:
        return None
    dest = config.output_dir / "bundle"
    dest.mkdir(parents=True, exist_ok=True)
    device.pull_as_root(f"{bundle}/Info.plist", str(dest))
    return _load_plist(dest / "Info.plist")


def _load_plist(path: Path) -> dict | None:
    if not path.exists():
        return None
    try:
        with open(path, "rb") as fh:
            return plistlib.load(fh)
    except Exception:
        try:
            xml = subprocess.run(["plutil", "-convert", "xml1", "-o", "-", str(path)],
                                 capture_output=True, timeout=30)
            return plistlib.loads(xml.stdout)
        except Exception:
            return None


def _resolve_uiopen(device: IOSDevice) -> str:
    """Return a runnable path to `uiopen`, or "" if absent. A bare `which uiopen`
    misses it on rootless jailbreaks (palera1n): uikittools installs to
    /var/jb/usr/bin, which is NOT on the non-login SSH shell's PATH. Probe both."""
    if not device.caps.ssh:
        return ""
    found = device.shell_output(
        "command -v uiopen 2>/dev/null || "
        "for p in /var/jb/usr/bin/uiopen /usr/bin/uiopen /var/jb/usr/local/bin/uiopen; "
        "do [ -x \"$p\" ] && echo \"$p\" && break; done"
    ).strip()
    return found.splitlines()[0].strip() if found else ""
