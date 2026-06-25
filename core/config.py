"""
Global configuration and shared state for the iOS DAST framework (TrashiOS).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional

# Strip NUL + non-printable control bytes (keep tab/newline/CR) so binary content
# pulled from the device (memory dumps, strings on binaries, etc.) can't leak into
# the Markdown/JSON report and turn it into a "binary" file.
_CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def scrub(text) -> str:
    """Strip NUL/non-printable control bytes (keeping tab/newline/CR) so binary device output can't corrupt the report; coerces non-str input to str."""
    if not isinstance(text, str):
        text = str(text)
    return _CONTROL_RE.sub("", text)


# Platform-agnostic secret regex (reused verbatim from TrashDroid).
SENSITIVE_PATTERNS = (
    r"password|passwd|pwd"
    r"|token|auth_token|access_token|refresh_token|bearer"
    r"|api[_\-]?key|apikey|api[_\-]?secret"
    r"|secret|client_secret"
    r"|private[_\-]?key|priv[_\-]?key"
    r"|credential|cred"
    r"|email|e-mail"
    r"|ssn|social.security"
    r"|credit.card|card.number|cvv|pan"
    r"|otp|pin"
    r"|jdbc:|connection.string"
    r"|BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY"
)

# ── Info.plist security-relevant keys (the iOS "manifest flags") ──
# Keyed by the plist key/condition the static_binary phase looks for.
INFO_PLIST_SECURITY_FLAGS = {
    "NSAllowsArbitraryLoads": {
        "risk": "High",
        "desc": "App Transport Security disabled globally (NSAppTransportSecurity.NSAllowsArbitraryLoads=true) — "
                "allows cleartext HTTP to any domain; susceptible to MitM.",
    },
    "NSAllowsArbitraryLoadsForMedia": {
        "risk": "Medium",
        "desc": "ATS disabled for media loads — cleartext media traffic permitted.",
    },
    "NSAllowsArbitraryLoadsInWebContent": {
        "risk": "Medium",
        "desc": "ATS disabled inside WebViews — cleartext loads permitted in web content.",
    },
    "NSExceptionAllowsInsecureHTTPLoads": {
        "risk": "Medium",
        "desc": "Per-domain ATS exception allows insecure HTTP loads.",
    },
    "NSExceptionMinimumTLSVersion": {
        "risk": "Medium",
        "desc": "Per-domain ATS exception lowers the minimum TLS version (< TLSv1.2).",
    },
    "UIFileSharingEnabled": {
        "risk": "Medium",
        "desc": "iTunes/Finder file sharing enabled (UIFileSharingEnabled=true) — exposes the app's Documents directory.",
    },
    "LSSupportsOpeningDocumentsInPlace": {
        "risk": "Low",
        "desc": "App supports opening documents in place — Documents may be reachable via the Files app.",
    },
    "CFBundleURLTypes": {
        "risk": "Info",
        "desc": "Custom URL scheme(s) declared — external entry point; validate handlers for unauthenticated actions/injection.",
    },
    "UIBackgroundModes": {
        "risk": "Info",
        "desc": "Background execution mode(s) declared; review for sensitive activity while backgrounded.",
    },
    "UIApplicationExitsOnSuspend": {
        "risk": "Info",
        "desc": "Legacy suspend-exit flag present.",
    },
}

# ── Mach-O binary hardening checks (no Android analogue) ──
# Each entry: the protection that SHOULD be present and the risk if it is MISSING.
MACHO_HARDENING_CHECKS = {
    "PIE": {
        "risk": "Medium",
        "desc": "Binary not compiled as a Position-Independent Executable (MH_PIE absent) — defeats ASLR.",
    },
    "STACK_CANARY": {
        "risk": "Medium",
        "desc": "Stack-smashing protection missing (no __stack_chk_guard/__stack_chk_fail) for Obj-C/C code.",
    },
    "ARC": {
        "risk": "Low",
        "desc": "Automatic Reference Counting not detected (no _objc_release) — higher risk of memory-management bugs.",
    },
    "ENCRYPTION": {
        "risk": "Info",
        "desc": "LC_ENCRYPTION_INFO cryptid=0 — binary is unencrypted (expected after decryption / sideloaded build).",
    },
    "GET_TASK_ALLOW": {
        "risk": "High",
        "desc": "Entitlement get-task-allow=true — a debugger can attach to the running app (the iOS 'debuggable' equivalent).",
    },
}

# Entitlement keys whose over-broad scope is worth flagging.
ENTITLEMENT_RISK_KEYS = {
    "get-task-allow": ("High", "Debugger attach allowed (get-task-allow)."),
    "keychain-access-groups": ("Medium", "Keychain access group sharing — review scope; wildcard/many groups widen exposure."),
    "com.apple.security.application-groups": ("Medium", "App-group container sharing — data shared across apps in the group."),
    "com.apple.developer.associated-domains": ("Medium", "Associated domains (Universal Links) — wildcard '*' is dangerous."),
}

# Host tools TrashiOS drives. Critical ones gate preflight; optional ones warn.
REQUIRED_TOOLS = [
    "idevice_id",        # device enumeration (libimobiledevice)
    "ideviceinfo",       # device info
    "ideviceinstaller",  # app list / install
    "idevicescreenshot", # screenshots
    "idevicesyslog",     # device logs
    "iproxy",            # SSH-over-USB tunnel
    "ssh",               # device shell (jailbroken)
    "frida-ps",          # runtime instrumentation
    "objection",         # high-level runtime introspection
]

OPTIONAL_TOOLS = [
    "idevicebackup2",    # backup phase (Milestone 2)
    "scp",               # file pull over SSH
    "otool",             # Mach-O hardening checks
    "class-dump",        # ObjC header dump
    "jtool2",            # Mach-O alt
    "codesign",          # entitlements
    "plutil",            # plist conversion
    "sqlite3",           # DB analysis
    "strings",           # binary string extraction
]

# Apple / common third-party framework prefixes used to filter library noise
# out of class-dump output and symbol scans (the iOS analogue of androidx.* etc).
FALSE_POSITIVE_PREFIXES = (
    "NS", "UI", "CA", "CF", "CG", "CL", "CM", "CN", "CT", "SK", "AV",
    "WK", "_T", "_OBJC_", "Swift", "$s", "$S",
    "FBSDK", "GUL", "Firebase", "FIR", "Google", "GTM", "GPB",
    "Alamofire", "RxSwift", "AF", "Realm", "RLM", "SQLite", "Crashlytics",
    "Sentry", "Branch", "Adjust", "Mixpanel", "Amplitude",
)


def _load_banner() -> str:
    banner_path = Path(__file__).resolve().parent.parent / "banner.txt"
    try:
        return banner_path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return "  TrashiOS — Automated iOS SAST/DAST Framework\n  Author: 0xs0m\n"


BANNER = _load_banner()


@dataclass
class Timing:
    cmd_run_timeout: int = 60
    syslog_auto_timeout: int = 45
    screenshot_settle_delay: float = 4.5
    db_query_timeout: int = 120
    polling_retries: int = 3
    file_pull_timeout: int = 300
    ssh_connect_timeout: int = 10
    frida_device_timeout: int = 5        # frida.get_usb_device()
    frida_ps_timeout: int = 15           # frida-ps -U / -Ua
    frida_spawn_settle: int = 3          # post-spawn settle before attach
    objection_command_timeout: int = 60  # objection sslpinning / jailbreak disable


@dataclass
class Limits:
    max_dump_mb: int = 64
    binary_file_scan_limit: int = 50 * 1024 * 1024
    max_binary_files: int = 500
    max_syslog_lines: int = 50000


TIMING = Timing()
LIMITS = Limits()


@dataclass
class Config:
    """Mutable state shared across all phases (iOS)."""

    device_id: str = ""                  # device UDID (from idevice_id -l)
    bundle_id: str = ""                  # target app bundle identifier (e.g. com.example.app)
    ipa_path: Optional[str] = None       # local .ipa path (None when pre-installed)
    ipa_hash: Optional[str] = None       # SHA-256 of the .ipa for chain-of-custody
    is_preinstalled: bool = False
    logged_in: bool = False

    # Resolved on-device container paths (filled during setup).
    data_container: Optional[str] = None     # /var/mobile/Containers/Data/Application/<UUID>
    bundle_container: Optional[str] = None    # /var/containers/Bundle/Application/<UUID>/<App>.app
    executable_name: Optional[str] = None     # CFBundleExecutable
    decrypted_bundle: Optional[str] = None    # local decrypted .app (from frida-ios-dump), if produced

    # Consent gates for heavy / DRM-touching phases.
    allow_decrypt: bool = False               # FairPlay decryption (authorized testing only)
    allow_backup: bool = False                # full device backup (slow)

    output_dir: Path = Path(".")
    screenshot_dir: Path = Path(".")
    timestamp: str = field(default_factory=lambda: datetime.now().strftime("%Y%m%d_%H%M%S"))

    auto_mode: bool = False
    report_mode: str = "client"  # client | internal

    screenshot_delay: float = 4.5

    # Device capabilities probed at connect time (afc / ssh / frida / root).
    capabilities: object = None

    # Presidio PII detection engine (None when not enabled)
    presidio_engine: object = None

    # accumulated findings per phase (phase_name -> list of finding dicts)
    findings: dict = field(default_factory=dict)
    # Commands executed (list of {cmd, stdout, stderr, phase})
    commands_log: list = field(default_factory=list)
    # Screenshot paths (list of {path, caption, phase})
    screenshots: list = field(default_factory=list)

    def init_output(self) -> None:
        """Create the output/<bundle_id>/ evidence tree (screenshots, data_container, bundle, keychain, syslog, memory, ...) and point output_dir/screenshot_dir at it."""
        self.output_dir = Path("output") / self.bundle_id
        self.screenshot_dir = self.output_dir / "screenshots"
        for d in [
            self.output_dir,
            self.screenshot_dir,
            self.output_dir / "data_container",
            self.output_dir / "data_container" / "Documents",
            self.output_dir / "data_container" / "Library",
            self.output_dir / "data_container" / "Library" / "Preferences",
            self.output_dir / "data_container" / "Library" / "Caches",
            self.output_dir / "data_container" / "tmp",
            self.output_dir / "bundle",
            self.output_dir / "bundle_decrypted",
            self.output_dir / "keychain",
            self.output_dir / "syslog",
            self.output_dir / "memory",
            self.output_dir / "backup",
            self.output_dir / "snapshots",
        ]:
            d.mkdir(parents=True, exist_ok=True)

    _VALID_SEVERITIES = {"Critical", "High", "Medium", "Low", "Info"}

    def add_finding(self, phase: str, title: str, severity: str, detail: str, status: str = "Open") -> None:
        """Record a finding under *phase*; severity is normalized to Critical/High/Medium/Low/Info (invalid warns -> Info) and title/detail are scrubbed of control bytes."""
        severity = severity.strip().title()
        if severity not in self._VALID_SEVERITIES:
            import warnings
            warnings.warn(
                f"Invalid finding severity '{severity}' for '{title}' — defaulting to 'Info'",
                stacklevel=2,
            )
            severity = "Info"
        self.findings.setdefault(phase, []).append(
            {"title": scrub(title), "severity": severity, "detail": scrub(detail), "status": status}
        )

    def log_command(self, phase: str, cmd: str, stdout: str, stderr: str = "", rc: int = 0) -> None:
        """Append a command's cmd/stdout/stderr/return-code to the evidence log (all fields scrubbed of control bytes)."""
        self.commands_log.append(
            {"phase": phase, "cmd": scrub(cmd), "stdout": scrub(stdout), "stderr": scrub(stderr), "rc": rc}
        )

    def add_screenshot(self, path: str, caption: str, phase: str) -> None:
        """Record a captured screenshot (report-relative path, caption, owning phase) for embedding in the report."""
        self.screenshots.append({"path": path, "caption": caption, "phase": phase})
