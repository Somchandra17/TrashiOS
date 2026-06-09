"""
Phase IV — Dump File Verification.

Deep, per-store analysis of the artifacts pulled in Phase III: per-table SQLite
dumps, binary-plist key/value extraction, and string scans of Realm/other DBs.
Distinguishes encrypted DBs (SQLCipher) from cleartext ones.

Grounded in OWASP MASTG-TEST-0052/0058, MASVS-STORAGE-1.
"""

from __future__ import annotations

import plistlib
import sqlite3
from pathlib import Path

from rich.console import Console

from core.config import Config, TIMING
from core.ios_device import IOSDevice
from utils.helpers import presidio_scan_text, presidio_findings_to_report, grep_sensitive_lines

console = Console()
PHASE = "Phase IV — Dump File Verification"

_MAX_DBS = 30
_MAX_TABLES = 40
_MAX_ROWS = 200
_INTERESTING_KEYS = ("token", "password", "secret", "session", "auth", "key", "credential", "jwt", "pin", "otp")


def run_dump_verification(config: Config, device: IOSDevice) -> None:
    console.print(f"\n[bold cyan]═══ {PHASE} ═══[/bold cyan]\n")

    base = config.output_dir / "data_container"
    has_files = any(p.is_file() for p in base.rglob("*")) if base.exists() else False
    if not has_files:
        # Phase III didn't pull (or run) — pull the container ourselves if SSH is up.
        data_remote = config.data_container or device.get_data_container(config.bundle_id)
        if data_remote and device.caps.ssh:
            console.print(f"  [cyan]Pulling Data container for verification:[/cyan] {data_remote}")
            device.pull_as_root(data_remote, str(base))
        else:
            console.print("[yellow]No pulled data and no SSH — skipping. Run Phase III first.[/yellow]")
            config.add_finding(PHASE, "Dump verification skipped — no data", "Info",
                               "No pulled Data container available and SSH unavailable to pull one.")
            return

    files = [p for p in base.rglob("*") if p.is_file()]
    dbs = [p for p in files if p.suffix.lower() in (".sqlite", ".sqlite3", ".db", ".realm") or _is_sqlite(p)]
    plists = [p for p in files if p.suffix.lower() == ".plist"]
    console.print(f"  [green]{len(dbs)} database(s), {len(plists)} plist(s) to verify.[/green]")

    for db in dbs[:_MAX_DBS]:
        _verify_db(config, db)
    for pl in plists:
        _verify_plist(config, pl)

    console.print(f"\n[green]✓ {PHASE} complete.[/green]")


def _is_sqlite(path: Path) -> bool:
    try:
        with open(path, "rb") as fh:
            return fh.read(16).startswith(b"SQLite format 3")
    except Exception:
        return False


def _verify_db(config: Config, db: Path) -> None:
    if not _is_sqlite(db):
        # Not a readable SQLite header — likely SQLCipher-encrypted or Realm.
        config.add_finding(PHASE, f"Encrypted/opaque database: {db.name}", "Info",
                           f"{db.name} does not have a cleartext SQLite header — likely SQLCipher-encrypted or Realm "
                           "(positive if it should hold secrets). String-scanned below for any leaked plaintext.")
        findings = presidio_scan_text(_safe_read(db), config, source_label=db.name)
        if findings:
            presidio_findings_to_report(findings, PHASE, config,
                                        fallback_title=f"Sensitive strings in {db.name}",
                                        fallback_detail="Plaintext sensitive strings found inside an opaque DB.")
        return
    try:
        con = sqlite3.connect(f"file:{db}?mode=ro", uri=True, timeout=TIMING.db_query_timeout)
        con.text_factory = lambda b: b.decode("utf-8", "replace")
        cur = con.cursor()
        cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = [r[0] for r in cur.fetchall()][:_MAX_TABLES]
        hits: list[str] = []
        for t in tables:
            try:
                cur.execute(f'SELECT * FROM "{t}" LIMIT {_MAX_ROWS}')
                rows = cur.fetchall()
            except Exception:
                continue
            blob = "\n".join(" | ".join(str(c) for c in row) for row in rows)
            line_hits = grep_sensitive_lines(blob, max_lines=20)
            if line_hits:
                hits.append(f"[table {t}] ({len(rows)} rows sampled)\n{line_hits}")
            findings = presidio_scan_text(blob, config, source_label=f"{db.name}:{t}")
            if findings:
                presidio_findings_to_report(findings, PHASE, config,
                                            fallback_title=f"Sensitive data in {db.name} table {t}",
                                            fallback_detail=f"Sensitive values in {db.name}.{t} (extracted from container).")
        con.close()
        if hits:
            config.add_finding(PHASE, f"Sensitive columns in {db.name}", "High",
                               f"Per-table verification of {db.name} surfaced sensitive content:\n\n" + "\n\n".join(hits[:10]))
        config.log_command(PHASE, f"sqlite3 {db.name} .dump (sampled {len(tables)} tables)", f"{len(hits)} table(s) with hits")
    except Exception as e:
        config.log_command(PHASE, f"sqlite3 {db.name}", "", str(e))


def _verify_plist(config: Config, pl: Path) -> None:
    try:
        with open(pl, "rb") as fh:
            data = plistlib.load(fh)
    except Exception:
        return
    flat = _flatten(data)
    interesting = {k: v for k, v in flat.items() if any(kw in k.lower() for kw in _INTERESTING_KEYS)}
    blob = "\n".join(f"{k} = {v}" for k, v in flat.items())
    findings = presidio_scan_text(blob, config, source_label=pl.name)
    if findings:
        presidio_findings_to_report(findings, PHASE, config,
                                    fallback_title=f"Sensitive data in {pl.name}",
                                    fallback_detail=f"Sensitive values in plist {pl.name} (extracted from container).")
    if interesting:
        detail = "\n".join(f"  {k} = {str(v)[:200]}" for k, v in list(interesting.items())[:30])
        config.add_finding(PHASE, f"Interesting keys in plist: {pl.name}", "Medium",
                           f"Keys suggesting secrets/session state in {pl.name} (verify if sensitive):\n{detail}")


def _flatten(obj, prefix="") -> dict:
    out = {}
    if isinstance(obj, dict):
        for k, v in obj.items():
            out.update(_flatten(v, f"{prefix}.{k}" if prefix else str(k)))
    elif isinstance(obj, (list, tuple)):
        for i, v in enumerate(obj):
            out.update(_flatten(v, f"{prefix}[{i}]"))
    else:
        out[prefix] = obj
    return out


def _safe_read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return ""
