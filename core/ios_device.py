"""
iOS device communication layer for TrashiOS — the `ADB` equivalent.

Composes three transports with a capability ladder, mirroring TrashDroid's
rooted/non-rooted ADB branching:

  T1  libimobiledevice CLIs   (idevice*, ideviceinstaller, afcclient) — no jailbreak needed
  T2  SSH-over-USB            (iproxy <local> <device:44> -> ssh root@127.0.0.1) — full root FS
  T3  Frida                   (frida-ps -U / frida spawn) — runtime PID/launch

`IOSDevice` deliberately mirrors the method surface of TrashDroid's `ADB`
(shell / shell_output / pull / pull_as_root / screencap / get_pid /
launch_app / force_stop / list_dir / get_app_data_path / is_rooted /
get_device_info / get_devices) so phases barely change.

palera1n note: OpenSSH listens on device port **44**, root password "alpine".
"""

from __future__ import annotations

import os
import plistlib
import shlex
import shutil
import subprocess
import tempfile
import time
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from rich.console import Console

from core.config import TIMING

console = Console()


class IOSError(Exception):
    pass


@dataclass
class Capabilities:
    afc: bool = False     # libimobiledevice reachable (device paired + trusted)
    ssh: bool = False     # iproxy tunnel + ssh login works
    frida: bool = False   # frida-server reachable over USB
    root: bool = False    # ssh login is uid=0 (jailbroken)

    def summary(self) -> str:
        """One-line transport-ladder summary for logging, e.g. "libimobiledevice=ok, ssh=ok, frida=no, root=yes"."""
        parts = [
            f"libimobiledevice={'ok' if self.afc else 'no'}",
            f"ssh={'ok' if self.ssh else 'no'}",
            f"frida={'ok' if self.frida else 'no'}",
            f"root={'yes' if self.root else 'no'}",
        ]
        return ", ".join(parts)


class IOSDevice:
    def __init__(
        self,
        udid: str = "",
        ssh_pw: str = "alpine",
        ssh_device_port: int = 44,
        local_port: int = 2222,
    ):
        self.udid = udid
        self.device_id = udid  # alias used by ScreenshotManager / report
        self.ssh_pw = ssh_pw
        self.ssh_device_port = ssh_device_port
        self.local_port = local_port
        self.caps = Capabilities()

        self._iproxy_proc: Optional[subprocess.Popen] = None
        self._sshpass = shutil.which("sshpass")
        self._data_container: Optional[str] = None
        self._bundle_container: Optional[str] = None
        self._executable_name: Optional[str] = None
        self._screenshot_ready: Optional[bool] = None  # None=unknown, True/False once probed

    # ── transport: iproxy lifecycle ──────────────────────────────

    def _ensure_iproxy(self) -> bool:
        """Start the USB->SSH tunnel idempotently (iproxy <local> <device>)."""
        if self._iproxy_proc is not None and self._iproxy_proc.poll() is None:
            return True
        try:
            self._iproxy_proc = subprocess.Popen(
                ["iproxy", str(self.local_port), str(self.ssh_device_port)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            time.sleep(1.0)  # let it bind
            return self._iproxy_proc.poll() is None
        except FileNotFoundError:
            return False

    def connect(self) -> Capabilities:
        """Probe transports and start the SSH tunnel. Returns Capabilities."""
        self._ensure_iproxy()
        self.caps = self._probe_capabilities()
        return self.caps

    def close(self) -> None:
        """Tear down the iproxy tunnel (called by the cleanup manager)."""
        if self._iproxy_proc is not None:
            try:
                self._iproxy_proc.terminate()
                try:
                    self._iproxy_proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    self._iproxy_proc.kill()
            except Exception:
                pass
            self._iproxy_proc = None

    def _probe_capabilities(self) -> Capabilities:
        caps = Capabilities()
        # libimobiledevice / pairing
        try:
            r = subprocess.run(["ideviceinfo", "-k", "ProductType"] + self._u(),
                               capture_output=True, text=True, timeout=10)
            caps.afc = r.returncode == 0 and bool(r.stdout.strip())
        except Exception:
            caps.afc = False
        # frida over USB
        try:
            r = subprocess.run(["frida-ps", "-U"], capture_output=True, text=True, timeout=TIMING.frida_ps_timeout)
            caps.frida = r.returncode == 0
        except Exception:
            caps.frida = False
        # ssh-over-USB
        try:
            r = self.shell("id", timeout=12)
            out = (r.stdout or "")
            caps.ssh = "uid=" in out
            caps.root = "uid=0" in out
        except Exception:
            caps.ssh = False
            caps.root = False
        return caps

    # ── ssh / scp helpers ────────────────────────────────────────

    def _u(self) -> list[str]:
        """`-u <udid>` for libimobiledevice tools when a UDID is pinned."""
        return ["-u", self.udid] if self.udid else []

    def _ssh_base_opts(self) -> list[str]:
        """Shared `-o` options for ssh/scp: host-key relaxation, timeout, legacy-RSA,
        and (under sshpass) password-only auth."""
        opts = [
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            "-o", f"ConnectTimeout={TIMING.ssh_connect_timeout}",
            "-o", "LogLevel=ERROR",
            "-o", "HostKeyAlgorithms=+ssh-rsa",
            "-o", "PubkeyAcceptedAlgorithms=+ssh-rsa",
        ]
        if self._sshpass:
            opts += ["-o", "PreferredAuthentications=password",
                     "-o", "PubkeyAuthentication=no"]
        return opts

    def _ssh_argv(self, remote_cmd: str) -> list[str]:
        argv: list[str] = []
        if self._sshpass:
            argv += ["sshpass", "-p", self.ssh_pw]
        argv += ["ssh", "-p", str(self.local_port)] + self._ssh_base_opts()
        argv += ["root@127.0.0.1", remote_cmd]
        return argv

    def _scp_argv(self, remote: str, local: str) -> list[str]:
        argv: list[str] = []
        if self._sshpass:
            argv += ["sshpass", "-p", self.ssh_pw]
        argv += ["scp", "-O", "-r", "-P", str(self.local_port)] + self._ssh_base_opts()
        argv += [f"root@127.0.0.1:{remote}", local]
        return argv

    # ── shell over SSH (mirror ADB.shell) ────────────────────────

    def shell(self, cmd: str, root: bool = True, timeout: int = 60) -> subprocess.CompletedProcess:
        """Run a command on the device over SSH (always root under palera1n).
        `root` kept for ADB API parity; SSH login is already uid=0."""
        self._ensure_iproxy()
        argv = self._ssh_argv(cmd)
        try:
            return subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
        except subprocess.TimeoutExpired:
            return subprocess.CompletedProcess(argv, 124, "", f"ssh timed out after {timeout}s")

    def shell_output(self, cmd: str, root: bool = True, timeout: int = 60) -> str:
        """Run a command over SSH and return only its stripped stdout."""
        return self.shell(cmd, root=root, timeout=timeout).stdout.strip()

    def list_dir(self, path: str, root: bool = True) -> list[str]:
        """`ls -la` the device *path* over SSH, returned as a list of output lines."""
        out = self.shell_output(f"ls -la '{path}'", root=root)
        return out.splitlines()

    # ── device management (mirror ADB) ───────────────────────────

    @staticmethod
    def get_devices() -> list[str]:
        """List connected device UDIDs (the `adb devices` equivalent)."""
        try:
            r = subprocess.run(["idevice_id", "-l"], capture_output=True, text=True, timeout=10)
            return [ln.strip() for ln in r.stdout.splitlines() if ln.strip()]
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return []

    def is_rooted(self) -> bool:
        """True if SSH login is uid=0 (i.e. jailbroken + reachable)."""
        if self.caps.ssh:
            return self.caps.root
        return "uid=0" in self.shell_output("id")

    def get_device_info(self) -> dict:
        """Device model / iOS version / build from a single `ideviceinfo` call."""
        info: dict[str, str] = {}
        try:
            r = subprocess.run(["ideviceinfo"] + self._u(),
                               capture_output=True, text=True, timeout=10)
            for line in r.stdout.splitlines():
                if ": " in line:
                    key, _, val = line.partition(": ")
                    info[key.strip()] = val.strip()
        except Exception:
            pass
        return {
            "model": info.get("ProductType") or info.get("DeviceName") or "iOS device",
            "ios_version": info.get("ProductVersion", ""),
            "build": info.get("BuildVersion", ""),
        }

    # ── app management (mirror ADB) ──────────────────────────────

    def _installer_list(self) -> str:
        """Run the app-list command, handling the ideviceinstaller 1.2.0 CLI change
        (`list` subcommand) with a fallback to the legacy `-l` flag (1.1.x)."""
        for variant in (["list"], ["-l"]):
            try:
                r = subprocess.run(["ideviceinstaller"] + self._u() + variant,
                                   capture_output=True, text=True, timeout=90)
            except (FileNotFoundError, subprocess.TimeoutExpired):
                return ""
            blob = (r.stdout + r.stderr).lower()
            if r.returncode == 0 and "invalid option" not in blob and "usage:" not in blob:
                return r.stdout
        return ""

    def get_installed_apps(self) -> dict[str, str]:
        """Return {bundle_id: display_name} via ideviceinstaller."""
        apps: dict[str, str] = {}
        stdout = self._installer_list()
        for line in stdout.splitlines():
            line = line.strip()
            if not line or line.lower().startswith("total") or line.startswith("CFBundleIdentifier"):
                continue
            # Common formats: "com.x, "1.0", "Name"" or "com.x - Name"
            if "," in line:
                parts = [p.strip().strip('"') for p in line.split(",")]
                bid = parts[0]
                name = parts[-1] if len(parts) >= 2 else bid
            elif " - " in line:
                bid, name = [p.strip() for p in line.split(" - ", 1)]
            else:
                bid, name = line, line
            if "." in bid:
                apps[bid] = name
        return apps

    def is_package_installed(self, bundle_id: str) -> bool:
        """True if *bundle_id* is present in the device's installed-app list."""
        return bundle_id in self.get_installed_apps()

    def install_app(self, ipa_path: str) -> str:
        """Install an .ipa via ideviceinstaller (handles the 1.2.0 `install` vs 1.1.x `-i` split); returns installer stdout, raises IOSError if the file is missing or every variant fails."""
        if not Path(ipa_path).exists():
            raise IOSError(f"IPA file not found: {ipa_path}")
        # ideviceinstaller 1.2.0 uses `install <ipa>`; 1.1.x uses `-i <ipa>`.
        last = ""
        for variant in (["install", ipa_path], ["-i", ipa_path]):
            try:
                r = subprocess.run(["ideviceinstaller"] + self._u() + variant,
                                   capture_output=True, text=True, timeout=300)
            except FileNotFoundError as e:
                raise IOSError("ideviceinstaller not found in PATH") from e
            blob = (r.stdout + r.stderr)
            if r.returncode == 0 and "invalid option" not in blob.lower() and "usage:" not in blob.lower():
                return r.stdout.strip()
            last = blob.strip()
        raise IOSError(f"Install failed: {last}")

    @staticmethod
    def get_bundle_id_from_ipa(ipa_path: str) -> Optional[str]:
        """Read CFBundleIdentifier from Payload/*.app/Info.plist inside the IPA."""
        if not Path(ipa_path).exists():
            return None
        try:
            with zipfile.ZipFile(ipa_path) as zf:
                infos = [n for n in zf.namelist()
                         if n.startswith("Payload/") and n.endswith(".app/Info.plist")
                         and n.count("/") == 2]
                if not infos:
                    return None
                with zf.open(infos[0]) as fh:
                    pl = plistlib.load(fh)
                return pl.get("CFBundleIdentifier")
        except Exception:
            return None

    def get_pid(self, bundle_id: str) -> Optional[str]:
        """PID of the running app via `frida-ps -Ua` (identifier match)."""
        try:
            r = subprocess.run(["frida-ps", "-Ua"], capture_output=True, text=True, timeout=TIMING.frida_ps_timeout)
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return None
        for line in r.stdout.splitlines():
            cols = line.split()
            if len(cols) >= 2 and cols[-1] == bundle_id and cols[0].isdigit():
                return cols[0]
        return None

    def launch_app(self, bundle_id: str) -> str:
        """Spawn the app. Prefer Frida (clean PID), fall back to SSH uiopen."""
        try:
            import frida
            dev = frida.get_usb_device(timeout=TIMING.frida_device_timeout)
            pid = dev.spawn([bundle_id])
            dev.resume(pid)
            return f"spawned pid={pid}"
        except Exception:
            r = self.shell(f"uiopen --bundleid {shlex.quote(bundle_id)} 2>/dev/null || open {shlex.quote(bundle_id)}")
            return (r.stdout or r.stderr).strip() or "launch attempted via ssh"

    def force_stop(self, bundle_id: str) -> None:
        """Kill the running app by pid (frida-ps), falling back to killall on the resolved executable name."""
        pid = self.get_pid(bundle_id)
        if pid:
            self.shell(f"kill -9 {pid}")
        elif self._executable_name:
            self.shell(f"killall -9 '{self._executable_name}'")

    def clear_app_data(self, bundle_id: str) -> str:
        """Best-effort logout-equivalent: wipe the Data container contents (root SSH)."""
        data = self.get_data_container(bundle_id)
        if not data:
            return "data container not resolved — skipped clear"
        self.force_stop(bundle_id)
        r = self.shell(
            f"rm -rf '{data}/Documents/'* '{data}/Library/'* '{data}/tmp/'* 2>/dev/null; echo cleared"
        )
        return (r.stdout or "").strip()

    # ── file transfer (mirror pull / pull_as_root) ───────────────

    def pull(self, remote: str, local: str) -> str:
        """Copy remote path (file or dir) to local via scp over SSH-root."""
        Path(local).mkdir(parents=True, exist_ok=True)
        argv = self._scp_argv(remote, local)
        try:
            r = subprocess.run(argv, capture_output=True, text=True, timeout=TIMING.file_pull_timeout)
            if r.returncode != 0 and r.stderr.strip():
                return f"(scp note) {r.stderr.strip()[:300]}"
            return r.stdout.strip() or f"pulled {remote}"
        except subprocess.TimeoutExpired:
            return f"scp timed out pulling {remote}"

    def pull_as_root(self, remote: str, local: str) -> str:
        """Pull *remote* to *local* over root SSH — alias of pull() (palera1n's SSH login is already uid=0)."""
        # SSH login is already root under palera1n; identical to pull.
        return self.pull(remote, local)

    # ── capture / telemetry (mirror screencap / logcat / backup) ──

    def ensure_screenshot_service(self) -> bool:
        """idevicescreenshot needs the Developer Disk Image mounted (com.apple.mobile.screenshotr).
        Probe once; if unavailable, auto-mount the matching DDI shipped with Xcode."""
        if self._screenshot_ready is not None:
            return self._screenshot_ready
        probe = Path(tempfile.gettempdir()) / "trashios_ddi_probe.png"
        if self._try_screenshot(probe):
            self._screenshot_ready = True
            return True
        console.print("  [yellow]Screenshot service unavailable — mounting Developer Disk Image...[/yellow]")
        if self._mount_ddi() and self._try_screenshot(probe):
            console.print("  [green]Developer Disk Image mounted; screenshots enabled.[/green]")
            self._screenshot_ready = True
            return True
        console.print("  [yellow]idevicescreenshot unavailable (no matching Developer Disk Image for this iOS "
                      "version) — falling back to Frida-rendered screenshots.[/yellow]")
        self._screenshot_ready = False
        return False

    def _try_screenshot(self, out: Path) -> bool:
        try:
            r = subprocess.run(["idevicescreenshot"] + self._u() + [str(out)],
                               capture_output=True, text=True, timeout=30)
            ok = r.returncode == 0 and out.exists() and out.stat().st_size > 100
            if out.exists():
                try:
                    out.unlink()
                except OSError:
                    pass
            return ok
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False

    def _mount_ddi(self) -> bool:
        """Mount the Developer Disk Image for this device's iOS version from Xcode/Xcode device support."""
        ver = self.get_device_info().get("ios_version", "")
        if not ver:
            return False
        parts = ver.split(".")
        major_minor = ".".join(parts[:2])   # e.g. 16.7
        major = parts[0]
        search_bases = [
            "/Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/DeviceSupport",
            os.path.expanduser("~/Library/Developer/Xcode/iOS DeviceSupport"),
            "/Library/Developer/Xcode/iOS DeviceSupport",
        ]
        candidates: list[tuple[int, Path]] = []
        for base in search_bases:
            bp = Path(base)
            if not bp.exists():
                continue
            for d in bp.iterdir():
                if not d.is_dir():
                    continue
                dmg = d / "DeveloperDiskImage.dmg"
                if not dmg.exists():
                    continue
                if d.name.startswith(major_minor):
                    candidates.append((0, dmg))          # exact major.minor — best
                elif d.name.startswith(major + "."):
                    candidates.append((1, dmg))          # same major — acceptable
        candidates.sort(key=lambda c: c[0])
        for _, dmg in candidates:
            sig = Path(str(dmg) + ".signature")
            sig_arg = [str(sig)] if sig.exists() else []
            base = ["ideviceimagemounter"] + self._u()
            # ideviceimagemounter 1.4.0 uses a `mount` subcommand; older versions take the image directly.
            for argv in (base + ["mount", str(dmg)] + sig_arg, base + [str(dmg)] + sig_arg):
                try:
                    r = subprocess.run(argv, capture_output=True, text=True, timeout=90)
                except (FileNotFoundError, subprocess.TimeoutExpired):
                    continue
                blob = (r.stdout + r.stderr).lower()
                if r.returncode == 0 or "already mounted" in blob or "is mounted" in blob:
                    return True
        return False

    def screencap(self, output_path: str) -> bool:
        """Capture a screenshot via idevicescreenshot; normalize TIFF->PNG (sips)."""
        if not self.ensure_screenshot_service():
            return False
        out = Path(output_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        try:
            r = subprocess.run(["idevicescreenshot"] + self._u() + [str(out)],
                               capture_output=True, text=True, timeout=30)
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False
        if r.returncode != 0 or not out.exists() or out.stat().st_size < 100:
            return False
        # Normalize format if the device returned TIFF.
        head = out.read_bytes()[:4]
        if head[:4] in (b"II*\x00", b"MM\x00*"):  # TIFF
            tmp = str(out) + ".tiff"
            out.rename(tmp)
            conv = subprocess.run(["sips", "-s", "format", "png", tmp, "--out", str(out)],
                                  capture_output=True, text=True, timeout=30)
            try:
                Path(tmp).unlink()
            except OSError:
                pass
            return conv.returncode == 0 and out.exists()
        return True

    def syslog_stream(self, process: Optional[str] = None) -> subprocess.Popen:
        """Start an idevicesyslog stream (the `adb logcat` stream equivalent)."""
        cmd = ["idevicesyslog"] + self._u()
        if process:
            cmd += ["-p", process]
        return subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    def backup(self, bundle_id: str, output_dir: str) -> subprocess.CompletedProcess:
        """Create a device backup (Milestone 2 backup phase)."""
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        return subprocess.run(
            ["idevicebackup2"] + self._u() + ["backup", "--full", output_dir],
            capture_output=True, text=True, timeout=900,
        )

    # ── iOS container resolution (no Android analogue) ───────────

    def resolve_containers(self, bundle_id: str) -> tuple[Optional[str], Optional[str], Optional[str]]:
        """Resolve (data_container, bundle_container, executable_name) over SSH.

        Uses the per-install metadata plists; bundle id is stored as a UTF-8
        string even inside binary plists, so `grep -l` matches reliably.
        """
        data = self._data_container
        bundle = self._bundle_container

        if not data:
            meta = self.shell_output(
                f"grep -rl {shlex.quote(bundle_id)} "
                f"/var/mobile/Containers/Data/Application/*/.com.apple.mobile_container_manager.metadata.plist "
                f"2>/dev/null | head -1"
            )
            if meta:
                data = str(Path(meta).parent)

        if not bundle:
            info = self.shell_output(
                f"grep -rl {shlex.quote(bundle_id)} "
                f"/var/containers/Bundle/Application/*/*.app/Info.plist 2>/dev/null | head -1"
            )
            if info:
                bundle = str(Path(info).parent)

        self._data_container = data or self._data_container
        self._bundle_container = bundle or self._bundle_container
        if bundle and not self._executable_name:
            # Derive a fallback executable name; static phase reads the real CFBundleExecutable.
            self._executable_name = Path(bundle).name.replace(".app", "")
        return self._data_container, self._bundle_container, self._executable_name

    def get_data_container(self, bundle_id: str) -> Optional[str]:
        """Resolved (and cached) Data-container path /var/mobile/Containers/Data/Application/<UUID>, or None."""
        if self._data_container:
            return self._data_container
        self.resolve_containers(bundle_id)
        return self._data_container

    def get_bundle_container(self, bundle_id: str) -> Optional[str]:
        """Resolved (and cached) Bundle-container path /var/containers/Bundle/Application/<UUID>/<App>.app, or None."""
        if self._bundle_container:
            return self._bundle_container
        self.resolve_containers(bundle_id)
        return self._bundle_container

    def get_app_data_path(self, bundle_id: str) -> str:
        """Mirror ADB.get_app_data_path — returns the resolved Data container."""
        return self.get_data_container(bundle_id) or ""
