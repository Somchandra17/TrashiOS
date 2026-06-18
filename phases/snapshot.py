"""
Phase VI — Backgrounding Snapshot Leakage.

When an app is backgrounded, iOS caches a screenshot of the current screen in
Library/Caches/Snapshots/. If a sensitive screen (login, payment, OTP) is on
screen at that moment, the snapshot leaks it — readable by anyone with device
access. This phase drives the app to background (interactive), then pulls and
reports the cached snapshots.

Grounded in OWASP MASTG-TEST-0009, MASVS-STORAGE-2 / PLATFORM-3.
"""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel

from core.config import Config
from core.ios_device import IOSDevice
from core.screenshot import ScreenshotManager

console = Console()
PHASE = "Phase VI — Backgrounding Snapshot Leakage"
_IMG_EXTS = (".ktx", ".jpeg", ".jpg", ".png")


def run_snapshot_analysis(config: Config, device: IOSDevice, screenshotter: ScreenshotManager) -> None:
    console.print(f"\n[bold cyan]═══ {PHASE} ═══[/bold cyan]\n")

    data_remote = config.data_container or device.get_data_container(config.bundle_id)
    if not data_remote or not device.caps.ssh:
        console.print("[yellow]Need SSH + resolved Data container — skipping.[/yellow]")
        config.add_finding(PHASE, "Snapshot analysis skipped", "Info",
                           "Requires SSH-over-USB and a resolved Data container to read Library/Caches/Snapshots.")
        return

    if not config.auto_mode:
        console.print(Panel(
            "Navigate the app to a SENSITIVE screen (login with data entered, payment, OTP, profile),\n"
            "then send the app to the background (press the Home indicator / swipe up).\n"
            "Press Enter here once you've backgrounded it.",
            style="bold yellow",
        ))
        input()
    else:
        console.print("[yellow]Auto-mode: pulling any existing backgrounding snapshots "
                      "(auto-mode can't navigate to a sensitive screen and background it first — "
                      "run this phase interactively for a true test).[/yellow]")

    snap_remote = f"{data_remote}/Library/Caches/Snapshots"
    local = config.output_dir / "snapshots"
    local.mkdir(parents=True, exist_ok=True)
    console.print(f"  [cyan]Pulling snapshots:[/cyan] {snap_remote}")
    out = device.pull_as_root(snap_remote, str(local))
    config.log_command(PHASE, f"scp -r {snap_remote}", out)

    images = [p for p in local.rglob("*") if p.is_file() and p.suffix.lower() in _IMG_EXTS]
    if not images:
        console.print("  [green]No backgrounding snapshots found.[/green]")
        config.add_finding(PHASE, "No backgrounding snapshots present", "Info",
                           "Library/Caches/Snapshots held no images, or the app masks its UI before backgrounding (good).")
        return

    # Embed renderable images as evidence; .ktx (compressed texture) can't render inline.
    renderable = [p for p in images if p.suffix.lower() in (".jpeg", ".jpg", ".png")]
    for img in renderable[:10]:
        try:
            rel = "./snapshots/" + str(img.relative_to(local))
            # Copy/normalize into screenshots dir so the report's relative path resolves uniformly.
            config.add_screenshot(rel, f"Backgrounding snapshot: {img.name}", PHASE)
        except Exception:
            pass

    config.add_finding(
        PHASE, f"Backgrounding snapshots present ({len(images)})", "Medium",
        "iOS cached app-switcher snapshots of the app. If any captured a sensitive screen (credentials, card, OTP), "
        "the data is recoverable from the device. Review the pulled images. Mask sensitive UI in "
        "applicationWillResignActive/sceneWillResignActive.\n\nFiles:\n  - "
        + "\n  - ".join(str(p.relative_to(local)) for p in images[:30]),
    )
    console.print(f"  [yellow]{len(images)} snapshot image(s) pulled to {local}.[/yellow]")
    console.print(f"\n[green]✓ {PHASE} complete.[/green]")
