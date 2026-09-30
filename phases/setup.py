"""
Setup phase — device (UDID) selection, target app input, installation,
container resolution, permission grant, and login state.
"""

from __future__ import annotations

import hashlib
import re
from pathlib import Path

from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.prompt import Prompt, Confirm

from core.ios_device import IOSDevice
from core.config import Config

console = Console()

# iOS bundle identifiers are reverse-DNS and may contain hyphens.
_BUNDLE_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9\-]*(\.[A-Za-z0-9\-]+)+$')


def _validate_bundle_id(bid: str) -> bool:
    if not bid or ' ' in bid or len(bid) < 3:
        return False
    return bool(_BUNDLE_RE.match(bid))


def select_device() -> str:
    """Return the UDID of the iOS device to test: auto-selected when one is connected, otherwise prompted from the usbmuxd device list. Returns "" if none are connected."""
    devices = IOSDevice.get_devices()
    if not devices:
        console.print("[red]No connected iOS devices found via usbmuxd.[/red]")
        return ""
    if len(devices) == 1:
        console.print(f"[green]Auto-selected device (UDID):[/green] {devices[0]}")
        return devices[0]

    console.print("\n[bold cyan]Connected devices:[/bold cyan]")
    for i, dev in enumerate(devices, 1):
        console.print(f"  [{i}] {dev}")

    while True:
        choice = Prompt.ask("Select device number", default="1")
        try:
            idx = int(choice) - 1
            if 0 <= idx < len(devices):
                return devices[idx]
        except ValueError:
            pass
        console.print("[red]Invalid selection, try again.[/red]")


def _select_installed_app(apps: dict[str, str]) -> str:
    """Show *apps* ({bundle_id: name}) as a numbered list and return the chosen bundle id.
    The prompt takes either a list number or a bundle id typed by hand (which may not be in the list)."""
    entries = sorted(apps.items(), key=lambda kv: (kv[1].lower(), kv[0]))
    width = len(str(len(entries)))
    console.print("[dim]Installed apps (Apple built-ins hidden — type a bundle id to use one):[/dim]")
    for i, (bid, name) in enumerate(entries, 1):
        console.print(f"  [cyan]{i:>{width}}.[/cyan] {escape(name)} [dim]— {escape(bid)}[/dim]")

    while True:
        choice = Prompt.ask(
            "Enter the app number, or type a bundle id manually (e.g. com.example.app)"
        ).strip()
        if choice.isdigit():
            idx = int(choice) - 1
            if 0 <= idx < len(entries):
                bid, name = entries[idx]
                console.print(f"[green]Selected:[/green] {escape(name)} [dim]({escape(bid)})[/dim]")
                return bid
            console.print(f"[red]No app #{choice} — pick 1-{len(entries)} or type a bundle id.[/red]")
        elif _validate_bundle_id(choice):
            return choice
        else:
            console.print("[red]Invalid bundle id format. Expected: com.example.app[/red]")


def get_app_input(device: IOSDevice) -> tuple[str | None, str, bool]:
    """Returns (ipa_path or None, bundle_id, is_preinstalled)."""
    console.print("\n[bold cyan]═══ Target Application ═══[/bold cyan]\n")
    preinstalled = Confirm.ask("Is the app already installed on the device?", default=True)

    if preinstalled:
        # Offer the installed apps as a numbered list; fall back to typing the id when none can be listed.
        # TrollStore / jailbreak installs register as "System" apps, so list everything and hide
        # Apple's built-ins (they can still be typed in by hand).
        apps = {bid: name for bid, name in device.get_installed_apps(include_system=True).items()
                if not bid.startswith("com.apple.")}
        if apps:
            return None, _select_installed_app(apps), True
        bid = Prompt.ask("Enter the target bundle identifier (e.g. com.example.app)").strip()
        while not _validate_bundle_id(bid):
            console.print("[red]Invalid bundle id format. Expected: com.example.app[/red]")
            bid = Prompt.ask("Enter a valid bundle id").strip()
        return None, bid, True

    ipa_path = Prompt.ask("Enter the full path to the .ipa file").strip().strip("'\"")
    bid = IOSDevice.get_bundle_id_from_ipa(ipa_path)
    if not bid:
        bid = Prompt.ask("Could not auto-detect bundle id from IPA. Enter it manually").strip()
    while not _validate_bundle_id(bid):
        console.print("[red]Invalid bundle id format. Expected: com.example.app[/red]")
        bid = Prompt.ask("Enter a valid bundle id").strip()
    return ipa_path, bid, False


def install_and_prepare(device: IOSDevice, config: Config) -> None:
    """Compute IPA hash, install if needed, resolve containers, prompt login/permissions."""
    # IPA SHA-256 for evidence chain-of-custody (mirrors TrashDroid's apk_hash).
    if config.ipa_path and Path(config.ipa_path).exists():
        ipa_hash = hashlib.sha256(Path(config.ipa_path).read_bytes()).hexdigest()
        config.ipa_hash = ipa_hash
        console.print(f"  [dim]IPA SHA-256: {ipa_hash}[/dim]")

    if not config.is_preinstalled and config.ipa_path:
        console.print(f"\n[cyan]Installing IPA: {config.ipa_path}[/cyan]")
        try:
            result = device.install_app(config.ipa_path)
            console.print(f"  {result}")
            config.log_command("Setup", f"ideviceinstaller -i {config.ipa_path}", result)
        except Exception as e:
            console.print(f"[yellow]Install reported: {e}[/yellow]")
            config.log_command("Setup", f"ideviceinstaller -i {config.ipa_path}", "", str(e))

    # Resolve on-device container paths (Data + Bundle) so phases consume constants.
    if device.caps.ssh:
        console.print("[cyan]Resolving app container paths over SSH...[/cyan]")
        data, bundle, exe = device.resolve_containers(config.bundle_id)
        config.data_container = data
        config.bundle_container = bundle
        config.executable_name = exe
        if data:
            console.print(f"  [green]Data:[/green]   {data}")
        else:
            console.print("  [yellow]Data container not resolved (is the app installed / has it been launched once?).[/yellow]")
        if bundle:
            console.print(f"  [green]Bundle:[/green] {bundle}")
        else:
            console.print("  [yellow]Bundle container not resolved.[/yellow]")
        config.log_command("Setup", f"resolve containers for {config.bundle_id}",
                           f"data={data}\nbundle={bundle}\nexecutable={exe}")
    else:
        console.print("[yellow]SSH unavailable — container paths will be resolved per-phase via Frida where possible.[/yellow]")

    if config.auto_mode:
        console.print("[yellow]Auto-mode: skipping permission/login prompts.[/yellow]")
        config.logged_in = False
    else:
        console.print(Panel(
            "Please open the app, grant ALL permissions,\nthen press Enter to continue.",
            style="bold yellow",
        ))
        input()
        want_login = Confirm.ask("Do you want to run tests in a logged-in state?", default=True)
        if want_login:
            console.print("\n[yellow]Please log in to the application now. Press Enter when ready.[/yellow]")
            input()
            config.logged_in = True
        else:
            config.logged_in = False

    console.print(f"\n[green]✓ Setup complete — testing '{config.bundle_id}' "
                  f"({'logged in' if config.logged_in else 'logged out'})[/green]")
