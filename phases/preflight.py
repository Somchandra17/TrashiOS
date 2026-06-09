"""
Pre-flight checks — verifies host tooling, device pairing, SSH-over-USB (root),
and frida-server reachability before the assessment begins.
"""

from __future__ import annotations

import shutil
import subprocess

from rich.console import Console
from rich.table import Table

from typing import TYPE_CHECKING
from core.config import REQUIRED_TOOLS, OPTIONAL_TOOLS

if TYPE_CHECKING:
    from core.ios_device import IOSDevice

console = Console()


def check_tool(name: str) -> bool:
    return shutil.which(name) is not None


def check_tool_version(name: str) -> str:
    for flag in ["--version", "version", "-V", "-v"]:
        try:
            result = subprocess.run([name, flag], capture_output=True, text=True, timeout=10)
            output = (result.stdout or result.stderr).strip()
            if output and "unknown command" not in output.lower():
                return output.splitlines()[0][:80]
        except Exception:
            continue
    return "installed"


def verify_device_prerequisites(device: "IOSDevice") -> bool:
    """Probe the connected device: pairing, SSH-over-USB root, frida-server.

    Returns False only when the device is unreachable via libimobiledevice
    (a hard stop). Missing SSH/frida degrade coverage but do not abort —
    mirroring TrashDroid's 'device not rooted, some tests may fail' behaviour.
    """
    console.print("\n[cyan]Probing device transports (this starts the iproxy SSH tunnel)...[/cyan]")
    caps = device.connect()
    console.print(f"  [dim]Capabilities: {caps.summary()}[/dim]")

    if not caps.afc:
        console.print(
            "\n[red bold]✗ Device not reachable via libimobiledevice.[/red bold]\n"
            "  Ensure the phone is plugged in, unlocked, and 'Trust This Computer' was accepted.\n"
            "  Verify with: [white]idevice_id -l && ideviceinfo -k ProductType[/white]"
        )
        return False

    if not caps.ssh:
        console.print(
            "\n[yellow]⚠ SSH-over-USB not available.[/yellow] Filesystem/keychain/runtime phases will be limited.\n"
            f"  palera1n exposes OpenSSH on device port [bold]{device.ssh_device_port}[/bold] "
            f"(root pw '[bold]{device.ssh_pw}[/bold]'). Tunnel: "
            f"[white]iproxy {device.local_port} {device.ssh_device_port}[/white] then "
            f"[white]ssh root@127.0.0.1 -p {device.local_port}[/white].\n"
            "  Also ensure the device passcode is DISABLED (A11 checkm8 requirement) and "
            "`sshpass` is installed for non-interactive login (brew install sshpass)."
        )
    elif not caps.root:
        console.print("[yellow]⚠ SSH connected but not root — full-filesystem phases will be limited.[/yellow]")
    else:
        console.print("[green]✓ SSH-over-USB root shell available.[/green]")

    if not caps.frida:
        console.print(
            "[yellow]⚠ frida-server not reachable over USB.[/yellow] Keychain/runtime/memory phases need it.\n"
            "  Install frida via Sileo (source https://build.frida.re) and verify: [white]frida-ps -U[/white]"
        )
    else:
        console.print("[green]✓ frida-server reachable.[/green]")

    return True


def run_preflight() -> bool:
    """Verify host tools and device presence. Returns True if critical checks pass."""
    console.print("\n[bold cyan]═══ Pre-flight Checks ═══[/bold cyan]\n")

    table = Table(title="Tool Availability")
    table.add_column("Tool", style="bold")
    table.add_column("Status")
    table.add_column("Version")

    all_ok = True
    for tool in REQUIRED_TOOLS:
        found = check_tool(tool)
        version = check_tool_version(tool) if found else "—"
        status = "[green]✓ Found[/green]" if found else "[red]✗ Missing[/red]"
        table.add_row(tool, status, version)
        if not found:
            all_ok = False

    for extra in OPTIONAL_TOOLS:
        found = check_tool(extra)
        version = check_tool_version(extra) if found else "—"
        status = "[green]✓ Found[/green]" if found else "[yellow]~ Optional[/yellow]"
        table.add_row(extra, status, version)

    # sshpass — needed for non-interactive SSH password auth (else use SSH keys)
    found = check_tool("sshpass")
    table.add_row(
        "sshpass",
        "[green]✓ Found[/green]" if found else "[yellow]~ Optional[/yellow]",
        check_tool_version("sshpass") if found else "brew install sshpass (or set up SSH keys)",
    )

    # Presidio / GLiNER (reused PII backend)
    try:
        import presidio_analyzer
        presidio_ver = getattr(presidio_analyzer, "__version__", "installed")
        table.add_row("presidio-analyzer", "[green]✓ Found[/green]", str(presidio_ver))
    except ImportError:
        table.add_row("presidio-analyzer", "[yellow]~ Optional[/yellow]", "pip install presidio-analyzer")

    try:
        try:
            from presidio_analyzer.predefined_recognizers.ner.gliner_recognizer import GLiNERRecognizer  # noqa: F401
        except ImportError:
            from presidio_analyzer.predefined_recognizers.gliner_recognizer import GLiNERRecognizer  # noqa: F401
        table.add_row("GLiNER (NER)", "[green]✓ Found[/green]", "urchade/gliner_multi_pii-v1")
    except ImportError:
        table.add_row("GLiNER (NER)", "[yellow]~ Optional[/yellow]", 'pip install "presidio-analyzer[gliner]"')

    console.print(table)

    if not all_ok:
        console.print("\n[red bold]✗ Critical tools are missing. Install them before proceeding.[/red bold]")
        console.print("  Host setup: [white]brew install libimobiledevice libusbmuxd ideviceinstaller[/white] "
                      "and [white]pip install frida-tools objection[/white]")
        return False

    from core.ios_device import IOSDevice
    devices = IOSDevice.get_devices()
    if not devices:
        console.print("\n[red bold]✗ No iOS device detected via usbmuxd.[/red bold]")
        console.print("  Ensure the device is connected, unlocked, and trusted. Verify: [white]idevice_id -l[/white]")
        return False

    console.print(f"\n[green]✓ {len(devices)} device(s) connected via usbmuxd.[/green]")
    return True
