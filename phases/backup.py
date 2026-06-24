"""
Phase XII — Backup Analysis.

Creates an unencrypted device backup (idevicebackup2), then inspects the files
belonging to the target app's backup domain — proving what sensitive data is
recoverable offline from a Finder/iTunes backup, and which files were NOT
excluded via NSURLIsExcludedFromBackupKey.

A full backup is slow (GBs) — gated behind consent (--backup, or an interactive
prompt; skipped by default in --auto).

Grounded in OWASP MASTG-TEST-0059/0060, MASVS-STORAGE-2.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

from rich.console import Console
from rich.prompt import Confirm

from core.config import Config
from core.ios_device import IOSDevice
from utils.helpers import presidio_scan_file, presidio_findings_to_report

console = Console()
PHASE = "Phase XII — Backup Analysis"
_MAX_SCAN_FILES = 300


def run_backup_analysis(config: Config, device: IOSDevice) -> None:
    console.print(f"\n[bold cyan]═══ {PHASE} ═══[/bold cyan]\n")

    if not config.allow_backup:
        if config.auto_mode:
            console.print("[yellow]Backup skipped (--backup not set; off by default in --auto — it's slow).[/yellow]")
            config.add_finding(PHASE, "Backup analysis skipped", "Info",
                               "A full device backup is slow (GBs) and was not requested. Pass --backup to enable.")
            return
        if not Confirm.ask("Run a full device backup now? This can take several minutes (GBs).", default=False):
            config.add_finding(PHASE, "Backup analysis declined", "Info", "Operator declined the (slow) device backup.")
            return

    backup_dir = config.output_dir / "backup"
    backup_dir.mkdir(parents=True, exist_ok=True)
    console.print("[cyan]Creating device backup (idevicebackup2 backup --full)... this is slow.[/cyan]")
    r = device.backup(config.bundle_id, str(backup_dir))
    config.log_command(PHASE, f"idevicebackup2 backup --full {backup_dir}",
                       (r.stdout or "")[:1000], (r.stderr or "")[:1000], r.returncode)
    if r.returncode != 0:
        console.print(f"[yellow]Backup failed: {(r.stderr or r.stdout)[:200]}[/yellow]")
        config.add_finding(PHASE, "Backup failed", "Info",
                           "idevicebackup2 did not complete. If the backup is encrypted with an unknown password, or "
                           "the device declined, the backup can't be parsed. Detail:\n" + (r.stderr or r.stdout)[:800])
        return

    manifest, root = _find_manifest(backup_dir)
    if not manifest:
        console.print("[yellow]Manifest.db not found in backup output.[/yellow]")
        config.add_finding(PHASE, "Backup produced but Manifest.db missing", "Info",
                           "The backup may be encrypted (Manifest.db is itself encrypted then). Disable backup "
                           "encryption on the device or supply the password to analyze.")
        return

    app_files = _app_domain_files(manifest, config.bundle_id, root)
    if not app_files:
        console.print("  [green]No files for this app's backup domain (well excluded, or app excluded from backup).[/green]")
        config.add_finding(PHASE, "App data not present in backup", "Info",
                           f"No AppDomain-{config.bundle_id} files were found in the backup — the app's data is "
                           "excluded from backup (good) or the app stores nothing backup-eligible.")
        return

    console.print(f"  [green]{len(app_files)} app file(s) present in the backup. Scanning...[/green]")
    all_findings = []
    for rel_path, disk_path in app_files[:_MAX_SCAN_FILES]:
        if not Path(disk_path).exists():
            continue
        for fd in presidio_scan_file(disk_path, config, source_label=f"backup:{rel_path}"):
            all_findings.append(fd)

    if all_findings:
        presidio_findings_to_report(
            all_findings, PHASE, config,
            fallback_title="Sensitive data in unencrypted backup",
            fallback_detail="Sensitive data recoverable offline from the device backup.",
        )
    config.add_finding(
        PHASE, f"App data included in backup ({len(app_files)} files, not excluded)", "Medium",
        f"{len(app_files)} files in AppDomain-{config.bundle_id} are captured by an (unencrypted) backup — they are "
        "NOT marked NSURLIsExcludedFromBackupKey. Sensitive files should be excluded and/or stored in the keychain. "
        "Sample paths:\n  - " + "\n  - ".join(p for p, _ in app_files[:30]),
    )
    console.print(f"\n[green]✓ {PHASE} complete.[/green]")


def _find_manifest(backup_dir: Path):
    for m in backup_dir.rglob("Manifest.db"):
        return m, m.parent
    return None, None


def _app_domain_files(manifest: Path, bundle_id: str, root: Path):
    """Return [(relativePath, on-disk path)] for the app's backup domain via Manifest.db."""
    out = []
    try:
        con = sqlite3.connect(f"file:{manifest}?mode=ro", uri=True)
        cur = con.cursor()
        cur.execute("SELECT fileID, domain, relativePath FROM Files WHERE domain LIKE ? AND flags=1",
                    (f"AppDomain-{bundle_id}%",))
        for file_id, domain, rel in cur.fetchall():
            # Backup files are stored as <root>/<first2 of fileID>/<fileID>
            disk = root / file_id[:2] / file_id
            out.append((rel or file_id, str(disk)))
        con.close()
    except Exception as e:
        config.log_command(PHASE, "Manifest.db parse", f"FAILED: {e}")
        config.add_finding(PHASE, "Backup Manifest.db parse error", "Low",
                           f"Could not read backup file list from Manifest.db: {e}")
    return out
