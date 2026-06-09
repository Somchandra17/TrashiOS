"""
Screenshot management: captures the device screen via idevicescreenshot
(through IOSDevice.screencap, which normalizes TIFF->PNG).

iOS has no scrcpy equivalent. Live mirroring over USB is done with QuickTime
Player (File -> New Movie Recording -> select the device) and is a manual,
optional step; screenshots are always captured automatically regardless.
"""

from __future__ import annotations

import subprocess
import time
from datetime import datetime
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.panel import Panel

console = Console()

# AppleScript: open QuickTime and start a New Movie Recording window (the closest
# macOS has to scrcpy for a USB iOS device). The recording source still has to be
# switched to the device from the record-button dropdown — that part isn't scriptable.
_QT_SCRIPT = (
    'tell application "QuickTime Player"\n'
    '  activate\n'
    '  if (count of documents) = 0 then new movie recording\n'
    'end tell'
)


class ScreenshotManager:
    def __init__(self, device, screenshot_dir: Path, config=None, frida=None):
        self.device = device
        self.screenshot_dir = screenshot_dir
        self.config = config
        self.frida = frida  # FridaBridge — used as a screenshot fallback when the DDI isn't mountable
        self._counter = 0

    def start_mirror(self) -> None:
        """Open a QuickTime 'New Movie Recording' window for live device viewing.

        QuickTime is the only built-in macOS way to mirror a USB iOS device. We
        launch it and open the recording window via AppleScript; the user then
        picks the iPhone from the record-button (⌄) dropdown. Screenshots are
        captured automatically regardless of whether the mirror is used.
        """
        try:
            r = subprocess.run(["osascript", "-e", _QT_SCRIPT],
                               capture_output=True, text=True, timeout=20)
            if r.returncode == 0:
                console.print(Panel(
                    "QuickTime opened a [bold]New Movie Recording[/bold] window for live device view.\n\n"
                    "[bold yellow]The blurry image you see first is the Mac's webcam — not the phone.[/bold yellow] "
                    "To mirror the device:\n"
                    "  1. Click the [bold]⌄[/bold] arrow next to the red ● record button.\n"
                    "  2. Under [bold]Camera[/bold], select your iPhone.\n"
                    "  3. (Optional) Under [bold]Quality[/bold], choose [bold]Maximum[/bold] for a crisp feed.\n\n"
                    "[dim]Live view is optional — full-resolution screenshots are captured automatically via "
                    "idevicescreenshot regardless.[/dim]",
                    title="Live Device View (QuickTime)", style="cyan",
                ))
                return
        except Exception:
            pass
        console.print(
            "[dim]  Live mirroring: open QuickTime Player -> File -> New Movie Recording, then click the ⌄ next to "
            "the record button and select the iPhone (optional). Screenshots are captured automatically.[/dim]"
        )

    def stop_mirror(self) -> None:
        # QuickTime is user-managed; nothing to tear down (don't kill their window).
        return

    def capture(self, phase: str, label: str, delay: Optional[float] = None) -> Optional[str]:
        """
        Capture a screenshot with an optional delay (to let the UI settle).
        Returns the local (report-relative) file path or None on failure.
        """
        if delay is None:
            delay = self.config.screenshot_delay if self.config else 4.5
        time.sleep(delay)
        self._counter += 1
        ts = datetime.now().strftime("%H%M%S")
        safe_label = label.replace(" ", "_").replace("/", "_").replace(".", "_")[:60]
        filename = f"{phase}_{safe_label}_{ts}_{self._counter}.png"
        output_path = self.screenshot_dir / filename
        output_path.parent.mkdir(parents=True, exist_ok=True)

        success = self.device.screencap(str(output_path))
        if not success and self.frida is not None:
            # idevicescreenshot needs the Developer Disk Image; on a jailbroken device
            # fall back to a Frida-rendered screenshot of the running app.
            success = self.frida.screenshot(str(output_path))
        if success:
            return f"./screenshots/{filename}"
        console.print(f"[yellow]  Screenshot capture failed for {label}[/yellow]")
        return None
