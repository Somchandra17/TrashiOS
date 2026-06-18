"""
AI-review package assembler.

The Markdown report → PDF path strips exactly what an AI triager needs (the
screenshots and the raw logs). Instead, after a run we assemble a self-contained
`ai_review/` folder that `claude` can be pointed at directly: it reads the
findings JSON, the human report, the raw logs, and VIEWS every screenshot as an
image, then writes a triaged final report (VAPT tickets) — no PDF, nothing lost.

The package is built to be GREPPED and ACTED ON:
  • findings.json — one object per (deduped) finding, each with a stable `id`
    (F-001…), severity, detail, and an `evidence` block naming the exact
    screenshots and log files that back it.
  • screenshots/index.json — each PNG → caption + the finding id(s) it supports.
  • logs/ — full, untruncated raw evidence with predictable filenames.

Layout:
  ai_review/
  ├── PROMPT.md          triage instructions (false-positive-first) + VAPT format + steps
  ├── CLAUDE.md          same role, auto-loaded for interactive `claude`
  ├── findings.json      deduped findings with ids + per-finding evidence map
  ├── report.md          the human report (evidence)
  ├── screenshots/       *.png + index.json (png → caption / phase / finding ids)
  ├── logs/              commands.log (full) + syslog / keychain / grep / ...
  └── run_review.sh      claude -p "$(cat PROMPT.md)" --permission-mode acceptEdits → final_report.md
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from datetime import datetime
from pathlib import Path

from rich.console import Console
from rich.panel import Panel

from core.report import AI_PROMPT, _dedupe_findings

console = Console()

# Copy-pasteable starter prompt the operator can give Claude (or any AI) to begin the triage.
STARTER_PROMPT = (
    "You are triaging an iOS pentest evidence package. Read PROMPT.md in this folder and follow it "
    "exactly: triage findings.json (aggressively filter false positives), VIEW every screenshot, then "
    "for each Likely finding offer to verify it live on the connected jailbroken iPhone and run the "
    "checks yourself, and write final_report.md as iOS VAPT tickets with the screenshot evidence embedded."
)

_SEV_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}

# Raw log files we surface, and the phase each one is evidence for.
_LOG_SOURCES = {
    "syslog.txt": ("syslog/syslog_capture.txt", "Phase VIII — Device Log Monitoring"),
    "background_syslog.txt": ("background_syslog.txt", "Phase VIII — Device Log Monitoring"),
    "keychain_items.json": ("keychain/keychain_items.json", "Phase V — Keychain Dump & Data Protection"),
    "keychain_values.txt": ("keychain/keychain_values.txt", "Phase V — Keychain Dump & Data Protection"),
    "keychain_dump.txt": ("keychain/keychain_dump.txt", "Phase V — Keychain Dump & Data Protection"),
    "storage_grep_results.txt": ("storage_grep_results.txt", "Phase III — Local Data Storage Analysis"),
    "pasteboard_capture.txt": ("pasteboard_capture.txt", "Phase VII — Pasteboard Leakage"),
    "class-dump.txt": ("bundle/class-dump.txt", "Phase II — Static Binary & Info.plist Analysis"),
}


def assemble_review_package(config, device_info: dict, report_path) -> Path:
    pkg = config.output_dir / "ai_review"
    if pkg.exists():
        shutil.rmtree(pkg)
    (pkg / "screenshots").mkdir(parents=True, exist_ok=True)
    (pkg / "logs").mkdir(parents=True, exist_ok=True)

    ss_index = _copy_screenshots(config, pkg)        # [{file, caption, phase}]
    log_files = _assemble_logs(config, pkg)          # [{file, phase|None}]
    findings = _build_findings(config, ss_index, log_files)

    _write_findings_json(config, device_info, findings, pkg)
    _write_screenshot_index(pkg, ss_index, findings)
    _copy_report(report_path, pkg)
    _write_prompt(config, device_info, findings, pkg)
    _write_claude_md(pkg)
    _write_runner(pkg)
    return pkg


# ── screenshots ──────────────────────────────────────────────────

def _copy_screenshots(config, pkg: Path) -> list[dict]:
    dest = pkg / "screenshots"
    index = []
    for ss in config.screenshots:
        rel = str(ss.get("path", "")).lstrip("./")
        src = config.output_dir / rel
        if not src.exists():
            continue
        try:
            shutil.copy2(src, dest / src.name)
            index.append({"file": src.name, "caption": ss.get("caption", ""), "phase": ss.get("phase", "")})
        except Exception:
            continue
    return index


# ── logs ─────────────────────────────────────────────────────────

def _assemble_logs(config, pkg: Path) -> list[dict]:
    logs = pkg / "logs"
    out: list[dict] = []

    # Full, untruncated command log (the .md collapses/clips this).
    lines = []
    for c in config.commands_log:
        lines.append(f"### [{c.get('phase','')}] {c.get('cmd','')}")
        if c.get("stdout"):
            lines.append(c["stdout"])
        if c.get("stderr"):
            lines.append(f"[stderr] {c['stderr']}")
        lines.append("\n" + "-" * 80 + "\n")
    (logs / "commands.log").write_text("\n".join(lines), encoding="utf-8")
    out.append({"file": "commands.log", "phase": None})  # general, all phases

    # Raw artifact files (skip the multi-MB memory dump + full data container).
    for name, (rel, phase) in _LOG_SOURCES.items():
        src = config.output_dir / rel
        try:
            if src.exists() and src.stat().st_size > 0:
                shutil.copy2(src, logs / name)
                out.append({"file": name, "phase": phase})
        except Exception:
            continue
    return out


# ── findings (deduped, stable ids, per-finding evidence) ─────────

def _build_findings(config, ss_index: list[dict], log_files: list[dict]) -> list[dict]:
    deduped = _dedupe_findings(config)  # {phase: [{title, severity, status, detail, occurrences}]}

    flat = [(phase, f) for phase, items in deduped.items() for f in items]
    flat.sort(key=lambda pf: (_SEV_ORDER.get(pf[1].get("severity", "Info"), 9), pf[0]))

    ss_by_phase: dict[str, list[str]] = {}
    for s in ss_index:
        ss_by_phase.setdefault(s["phase"], []).append(s["file"])
    logs_by_phase: dict[str, list[str]] = {}
    general_logs = []
    for l in log_files:
        if l["phase"]:
            logs_by_phase.setdefault(l["phase"], []).append(l["file"])
        else:
            general_logs.append(l["file"])

    findings = []
    for i, (phase, f) in enumerate(flat, start=1):
        findings.append({
            "id": f"F-{i:03d}",
            "phase": phase,
            "title": f.get("title", ""),
            "severity": f.get("severity", "Info"),
            "status": f.get("status", "Open"),
            "occurrences": f.get("occurrences", 1),
            "detail": f.get("detail", ""),
            "evidence": {
                "screenshots": ss_by_phase.get(phase, []),
                "logs": logs_by_phase.get(phase, []) + general_logs,
            },
        })
    return findings


def _write_findings_json(config, device_info: dict, findings: list[dict], pkg: Path) -> None:
    counts = {k: 0 for k in _SEV_ORDER}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    export = {
        "tool": "TrashiOS",
        "generated": datetime.now().isoformat(timespec="seconds"),
        "bundle_id": config.bundle_id,
        "device": device_info,
        "tested_logged_in": config.logged_in,
        "total_findings": len(findings),
        "severity_counts": counts,
        "findings": findings,
    }
    (pkg / "findings.json").write_text(json.dumps(export, indent=2, default=str), encoding="utf-8")


def _write_screenshot_index(pkg: Path, ss_index: list[dict], findings: list[dict]) -> None:
    ids_by_phase: dict[str, list[str]] = {}
    for f in findings:
        ids_by_phase.setdefault(f["phase"], []).append(f["id"])
    enriched = [{
        "file": s["file"],
        "caption": s["caption"],
        "phase": s["phase"],
        "finding_ids": ids_by_phase.get(s["phase"], []),
    } for s in ss_index]
    (pkg / "screenshots" / "index.json").write_text(json.dumps(enriched, indent=2), encoding="utf-8")


# ── report.md (strip the embedded AI-prompt header) ──────────────

def _copy_report(report_path, pkg: Path) -> None:
    try:
        text = Path(report_path).read_text(encoding="utf-8", errors="replace")
        marker = text.find("# iOS DAST")
        if marker > 0:
            text = text[marker:]
        (pkg / "report.md").write_text(text, encoding="utf-8")
    except Exception:
        pass


# ── PROMPT.md ────────────────────────────────────────────────────

def _write_prompt(config, device_info: dict, findings: list[dict], pkg: Path) -> None:
    counts = {k: 0 for k in _SEV_ORDER}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    counts_line = ", ".join(f"{k}: {v}" for k, v in counts.items() if v)

    prompt = f"""# START HERE — iOS pentest evidence triage

{AI_PROMPT}

────────────────────────────────────────────────────────────────────────
THIS FOLDER IS A SELF-CONTAINED iOS PENTEST EVIDENCE PACKAGE (grep it freely).

Target : {config.bundle_id}
Device : {device_info.get('model','?')} | iOS {device_info.get('ios_version','?')} (build {device_info.get('build','?')})
Logged in during test : {config.logged_in}
Findings to triage : {len(findings)}  ({counts_line})

FILES:
  • findings.json     — THE WORK LIST. One object per finding, each with:
        id (F-001…), phase, title, severity, status, occurrences, detail,
        evidence:{{ screenshots:[…], logs:[…] }}  ← the exact files that back this finding.
  • report.md         — human-readable report (extra context).
  • screenshots/      — PNG evidence. **VIEW every image you need.** screenshots/index.json
                        maps each file → caption, phase, and the finding_ids it supports.
  • logs/             — raw evidence (read in full):
        commands.log              every command + its full, untruncated output
        syslog.txt                captured device logs
        keychain_items.json       dumped keychain (account/service/access-group/protection-class/data)
        storage_grep_results.txt  sensitive-pattern matches from the data container
        class-dump.txt, pasteboard_capture.txt … (when present)

HOW TO WORK (finding-by-finding):
  1. Load findings.json. Iterate findings in severity order.
  2. For EACH finding, open the files named in its `evidence` block:
        - VIEW every screenshot in evidence.screenshots (they are in screenshots/).
        - READ every file in evidence.logs (they are in logs/).
  3. Decide the verdict (CONFIRMED / LIKELY / FALSE POSITIVE / INFORMATIONAL) per the rules above.
  4. Cite the finding `id` and the exact screenshot filename / log line in your justification.
  5. WRITE your output to `final_report.md` in THIS directory.

FINAL REPORT (`final_report.md`):
  A. Executive summary (2-4 sentences): real risk posture, noise excluded.
  B. Triage table (EVERY finding): ID | Finding | Verdict (Confirmed/Likely/FP/Info) | Real severity | One-line reason.
  C. For each CONFIRMED or LIKELY finding, a finding block in THIS EXACT field format
     (match the operator's report style) and EMBED the supporting evidence images inline:

        ### <id> - <Title>
        - **Severity:** <triaged severity>
        - **Status:** Open
        - **Confidence:** Confirmed | Likely | Needs manual validation
        - **CVSS (estimated):** <score, re-derived from real attack prerequisites>
        - **CVSS Vector (estimated):** `CVSS:3.1/...`
        - **CWE / OWASP:** CWE-... · MASVS-... · MASTG-...
        - **Affected:** <bundle id / file / URL scheme / keychain item>
        - **Business Impact:** <real-world impact; note if jailbroken/physical access is required>
        - **Description:** <what it is + the evidence you actually saw>
        - **Proof of Concept:** <steps + the relevant log lines, and EMBED each supporting
              screenshot inline -> ![<caption>](screenshots/<file>)  (file + caption come from
              screenshots/index.json; paths are relative to this folder so they render in the .md)>
        - **Remediation:** <concrete, code-level>

     IMAGES ARE REQUIRED wherever a finding has screenshot evidence — embed them in the PoC.

  D. AUTOMATED LIVE VERIFICATION & DEEP-DIVE — this is the core of the job, not an afterthought.
     Do NOT leave findings as "verify manually." Drive the verification yourself, end to end:
       i.   Ask the operator to connect the jailbroken iPhone over USB and confirm it's reachable
            (`idevice_id -l`, `frida-ps -U`). If a check needs a particular app state (e.g. logged
            OUT), ask them to set it, then continue automatically.
       ii.  For EVERY Likely / needs-validation finding, actually RUN the proof with the on-host
            tooling. Reuse the TrashiOS bridges from the repo root — this package is at
            <repo>/output/<bundle>/ai_review, so the repo is `../../..`: `core.ios_device.IOSDevice`
            (SSH/scp/screencap/containers) and `core.frida_bridge.FridaBridge` (keychain_dump,
            open_url/open_urls, dump_memory, run_script) — or raw frida / ssh / sqlite3 /
            idevicesyslog / otool / plutil / base64.
       iii. DEEP-DIVE — don't stop at the first signal. Decode/parse blobs (sqlite3 + base64/plutil),
            re-fire URL schemes while LOGGED OUT and screenshot the result, dump & grep process memory,
            and for keychain DECODE THE ITEM VALUES to prove whether they're real secrets or SDK
            metadata. Chain it: a leaked token → where is it used, is it still valid, what does it unlock?
       iv.  Capture fresh EVIDENCE — save new screenshots into `screenshots/` and command output into
            `logs/`, and embed/cite them.
       v.   For each confirmed check, upgrade the finding to CONFIRMED, re-derive CVSS from what you
            actually proved, and REGENERATE `final_report.md` with the real PoC + embedded evidence.
     Goal: turn the noisy automated dump into a thorough, polished report a senior pentester would sign.
  Keep FALSE POSITIVES to one row each in the triage table.

If a `vapt-ticket-writer` skill is installed, use it to format section C in the operator's preferred style.
"""
    (pkg / "PROMPT.md").write_text(prompt, encoding="utf-8")


def _write_claude_md(pkg: Path) -> None:
    (pkg / "CLAUDE.md").write_text(
        "# iOS pentest evidence triage\n\n"
        "This directory is a TrashiOS AI-review package. When the user says to begin, follow "
        "`PROMPT.md` exactly:\n\n"
        "1. Load `findings.json` (each finding has an `id` and an `evidence` block listing its "
        "screenshots and log files).\n"
        "2. Work finding-by-finding: VIEW every screenshot in its evidence (see "
        "`screenshots/index.json`), READ its log files in `logs/`.\n"
        "3. Aggressively filter false positives.\n"
        "4. Write `final_report.md` using the operator's finding-field format (Severity / Status / "
        "Confidence / CVSS (estimated) / CVSS Vector (estimated) / Business Impact / Description / "
        "Proof of Concept / Remediation), and EMBED supporting screenshots inline with "
        "`![caption](screenshots/<file>)`.\n"
        "5. DRIVE automated live verification (the core of the job): ask the operator to connect the "
        "jailbroken iPhone, then for EVERY Likely / needs-validation finding run the proof yourself — "
        "reuse the TrashiOS bridges at the repo root `../../..` (IOSDevice, FridaBridge) or raw "
        "frida/ssh/sqlite3/idevicesyslog/otool/base64. Deep-dive (decode blobs & keychain item values, "
        "re-fire URL schemes LOGGED-OUT + screenshot, grep process memory), save fresh evidence into "
        "`screenshots/` and `logs/`, then upgrade confirmed findings and regenerate a polished "
        "`final_report.md` with the real PoC embedded.\n\n"
        "Prefer the `vapt-ticket-writer` skill for formatting if installed.\n",
        encoding="utf-8",
    )


def _write_runner(pkg: Path) -> None:
    script = pkg / "run_review.sh"
    script.write_text(
        "#!/usr/bin/env bash\n"
        "# Run Claude over this evidence package to produce final_report.md.\n"
        "set -euo pipefail\n"
        'cd "$(dirname "$0")"\n'
        'command -v claude >/dev/null 2>&1 || { echo "claude CLI not found on PATH"; exit 1; }\n'
        'echo "Running Claude over the review package (reads logs + views all screenshots; may take a few minutes)..."\n'
        'claude -p "$(cat PROMPT.md)" --permission-mode acceptEdits --output-format text\n'
        'echo\n'
        'echo "Done. Final report: $(pwd)/final_report.md"\n',
        encoding="utf-8",
    )
    try:
        os.chmod(script, 0o755)
    except OSError:
        pass


# ── optional auto-run (--ai-review) ──────────────────────────────

def run_claude_review(pkg: Path, console: Console) -> None:
    if not shutil.which("claude"):
        console.print("[yellow]`claude` CLI not found on PATH — skipping auto-review. "
                      f"Run it yourself: cd {pkg} && ./run_review.sh[/yellow]")
        return
    console.print("[cyan]Running Claude over the review package (views all screenshots; may take a few minutes)...[/cyan]")
    try:
        prompt = (pkg / "PROMPT.md").read_text(encoding="utf-8")
        subprocess.run(
            ["claude", "-p", prompt, "--permission-mode", "acceptEdits", "--output-format", "text"],
            cwd=str(pkg), timeout=1800,
        )
    except subprocess.TimeoutExpired:
        console.print("[yellow]Claude review timed out (30 min). The package is ready to re-run manually.[/yellow]")
        return
    final = pkg / "final_report.md"
    if final.exists():
        console.print(f"[green]✓ Final triaged report: {final}[/green]")
    else:
        console.print(f"[yellow]Claude finished but final_report.md not found — check output above. Package: {pkg}[/yellow]")


def print_next_steps(pkg: Path, config, console: Console) -> None:
    """End-of-run guidance: where the output is, the prompt to give the AI, and how to proceed."""
    final = pkg / "final_report.md"
    lines = [
        f"[bold]Operator:[/bold]      {os.environ.get('USER', '?')}",
        f"[bold]Target:[/bold]        {config.bundle_id}",
        f"[bold]Output dir:[/bold]    {config.output_dir.resolve()}",
        f"[bold]AI-review pkg:[/bold] {pkg.resolve()}",
    ]
    if final.exists():
        lines.append(f"[green]Final report already written:[/green] {final.resolve()}")
    lines += [
        "",
        "[bold]1) Hand the package to an AI to triage — pick one:[/bold]",
        f"   • Claude Code (best — it reads the screenshots and can verify on-device):",
        f"       [white]cd '{pkg}' && claude[/white]   [dim]then paste the prompt below (or just say: follow PROMPT.md)[/dim]",
        f"       [white]cd '{pkg}' && ./run_review.sh[/white]   [dim]headless → writes final_report.md[/dim]",
        f"   • Any other AI/chat: upload [white]PROMPT.md[/white] + [white]findings.json[/white] + the "
        f"[white]screenshots/[/white] and [white]logs/[/white] folders, then paste the prompt.",
        "",
        "[bold]2) Prompt to give the AI:[/bold]",
        f"   [italic]{STARTER_PROMPT}[/italic]",
        "",
        "[bold]3) Then:[/bold] review [white]final_report.md[/white]. For every 'Likely' finding the AI will "
        "OFFER to verify it live on the connected jailbroken iPhone (decode DB/keychain values, re-fire URL "
        "schemes logged-out, grep memory) and regenerate the report with a confirmed PoC + evidence.",
    ]
    console.print(Panel("\n".join(lines), title="Next steps — AI triage", style="cyan", expand=False))
