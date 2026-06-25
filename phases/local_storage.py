"""
Phase III — Local Data Storage Analysis.

Pulls the app's Data container and scans every store for secrets / PII using
the reused Presidio/regex engine. Highlights notable stores: NSUserDefaults
(Library/Preferences/*.plist), SQLite/Realm databases, Cache.db, cookies, and
WebKit storage.

Grounded in OWASP MASTG-TEST-0052/-0053/-0054, MASVS-STORAGE-1/-2.
"""

from __future__ import annotations

from pathlib import Path

from rich.console import Console

from core.config import Config, LIMITS
from core.ios_device import IOSDevice
from utils.helpers import presidio_scan_file, presidio_findings_to_report, grep_sensitive_lines

console = Console()
PHASE = "Phase III — Local Data Storage Analysis"

# Files worth calling out individually when found in the container.
_DB_SUFFIXES = (".sqlite", ".sqlite3", ".db", ".realm")
_INTERESTING = ("cache.db", "cookies.binarycookies")


def run_local_storage_analysis(config: Config, device: IOSDevice) -> None:
    """Pull the app's Data container and scan every store for secrets/PII, flagging notable stores (NSUserDefaults plists, SQLite/Realm DBs, cookies, backgrounding snapshots)."""
    console.print(f"\n[bold cyan]═══ {PHASE} ═══[/bold cyan]\n")

    data_remote = config.data_container or device.get_data_container(config.bundle_id)
    if not data_remote:
        console.print("[red]Data container not resolved. Launch the app once, then retry. Skipping.[/red]")
        config.add_finding(PHASE, "Local storage skipped — Data container unresolved", "Info",
                           "Could not resolve /var/mobile/Containers/Data/Application/<UUID> for the bundle. "
                           "Ensure the app is installed and has been launched at least once, and that SSH is available.")
        return

    if not device.caps.ssh:
        console.print("[yellow]SSH unavailable — cannot pull the full Data container. Skipping.[/yellow]")
        config.add_finding(PHASE, "Local storage limited — no SSH", "Info",
                           "Full-container pull requires SSH-over-USB (jailbroken). Only AFC Documents would be "
                           "reachable otherwise; reduced coverage.")
        return

    local_base = config.output_dir / "data_container"
    local_base.mkdir(parents=True, exist_ok=True)
    console.print(f"  [cyan]Pulling Data container:[/cyan] {data_remote}")
    out = device.pull_as_root(data_remote, str(local_base))
    config.log_command(PHASE, f"scp -r {data_remote} -> {local_base}", out)

    files = [p for p in local_base.rglob("*") if p.is_file()]
    if not files:
        console.print("  [yellow]No files pulled (container empty or pull failed).[/yellow]")
        config.add_finding(PHASE, "Data container empty or inaccessible", "Info",
                           f"No files were retrieved from {data_remote}.")
        return
    console.print(f"  [green]Pulled {len(files)} file(s). Scanning for secrets...[/green]")

    _flag_notable_stores(config, files, local_base)
    _scan_for_secrets(config, files)

    console.print(f"\n[green]✓ {PHASE} complete.[/green]")


def _flag_notable_stores(config: Config, files: list[Path], base: Path) -> None:
    """Call out NSUserDefaults, databases, cookies, snapshots so the reader knows what exists."""
    dbs, cookies, prefs, snapshots = [], [], [], []
    for f in files:
        name = f.name.lower()
        rel = str(f.relative_to(base))
        if name.endswith(_DB_SUFFIXES) or _has_sqlite_header(f):
            dbs.append(rel)
        if name == "cookies.binarycookies":
            cookies.append(rel)
        if "library/preferences/" in rel.lower().replace("\\", "/") and name.endswith(".plist"):
            prefs.append(rel)
        if "/snapshots/" in ("/" + rel.lower().replace("\\", "/")):
            snapshots.append(rel)

    if dbs:
        config.add_finding(PHASE, f"Local databases present ({len(dbs)})", "Info",
                           "SQLite/Realm databases found in the container (per-table deep analysis is Milestone 2):\n  - "
                           + "\n  - ".join(dbs[:40]))
    if prefs:
        config.add_finding(PHASE, f"NSUserDefaults / preference plists present ({len(prefs)})", "Info",
                           "Preference plists (the iOS shared_prefs equivalent) — scanned for secrets below:\n  - "
                           + "\n  - ".join(prefs[:40]))
    if cookies:
        config.add_finding(PHASE, "Persisted cookies present (Cookies.binarycookies)", "Low",
                           "Cookie jar found on disk; verify no long-lived session/auth cookies persist:\n  - "
                           + "\n  - ".join(cookies))
    if snapshots:
        config.add_finding(PHASE, f"Backgrounding snapshots present ({len(snapshots)})", "Info",
                           "App-switcher snapshots found under Library/Caches/Snapshots — reviewed in the "
                           "snapshot-leakage phase (Milestone 2):\n  - " + "\n  - ".join(snapshots[:20]))


def _scan_for_secrets(config: Config, files: list[Path]) -> None:
    """Run the reused Presidio/regex engine over every pulled file."""
    all_findings: list[dict] = []
    scanned = 0
    grep_lines: list[str] = []

    for f in files:
        try:
            if f.stat().st_size > LIMITS.binary_file_scan_limit:
                continue
        except OSError:
            continue
        if scanned >= LIMITS.max_binary_files:
            break
        scanned += 1
        findings = presidio_scan_file(str(f), config, source_label=f.name)
        for fd in findings:
            all_findings.append(fd)
        # cheap text grep for the raw evidence file
        try:
            text = f.read_text(encoding="utf-8", errors="ignore")
            hit = grep_sensitive_lines(text, max_lines=20)
            if hit:
                grep_lines.append(f"### {f.name}\n{hit}")
        except Exception:
            pass

    # Write raw grep evidence
    if grep_lines:
        (config.output_dir / "storage_grep_results.txt").write_text(
            "\n\n".join(grep_lines), encoding="utf-8")
        config.log_command(PHASE, "grep <sensitive patterns> over Data container",
                           f"{len(grep_lines)} file(s) had matches")

    if all_findings:
        presidio_findings_to_report(
            all_findings, PHASE, config,
            fallback_title="Sensitive data in local storage",
            fallback_detail="Files in the app's Data container contain strings matching sensitive patterns.",
        )
        console.print(f"  [red]{len(all_findings)} sensitive finding(s) across {scanned} scanned file(s).[/red]")
    else:
        console.print(f"  [green]No sensitive data detected across {scanned} scanned file(s).[/green]")


def _has_sqlite_header(path: Path) -> bool:
    try:
        with open(path, "rb") as fh:
            return fh.read(16).startswith(b"SQLite format 3")
    except Exception:
        return False
