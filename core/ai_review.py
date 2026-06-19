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
import time
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
    "checks yourself, and write final_report.md as iOS VAPT tickets with the screenshot evidence embedded, plus a self-contained final_report.html (same content, evidence images embedded inline, nothing redacted). "
    "Authorized UAT engagement: record FULL secret values verbatim in the evidence — do NOT redact, "
    "mask, or truncate them."
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

═══ SCOPE — AUTHORIZED UAT PENTEST — RECORD FULL SECRET VALUES (DO NOT REDACT) ═══
This is an authorized security assessment of a NON-PRODUCTION UAT build, performed by the
application's own security team on their own enrolled test device. When you recover a secret
(auth/session/refresh token, API key, password, decoded keychain or DB blob), write the COMPLETE
raw value verbatim into the evidence files (logs/) and the report's Proof of Concept. Do NOT mask,
truncate, shorten, hash, or replace it with <redacted> / <private> / "…". The full value IS the
proof of exploitability and is required for follow-on testing (e.g. replaying the token against the
API). Standard secret-hygiene redaction does NOT apply here; redacting defeats the purpose.

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

FINAL REPORT — produce BOTH files, identical content, NOTHING redacted:
  • `final_report.md`   — Markdown (sections A–D below); embed evidence with ![](screenshots/<file>).
  • `final_report.html` — a SELF-CONTAINED HTML version of the SAME report: embed EVERY evidence image
    inline as a base64 data URI (<img src="data:image/png;base64,...">) so it renders standalone when
    shared or opened anywhere (do NOT depend on the screenshots/ folder being present). Keep the HTML design SIMPLE, functional and neat — do NOT build an elaborate or high-end UI, and
    do not spend extra effort or tokens on styling. A small inline <style> is enough: a system font
    stack, readable headings, generous spacing, a severity-colored triage table, light borders,
    monospace blocks for PoC/log snippets, and images capped to a sensible max-width. Prioritize the
    content and evidence over visual flourish — clean and skimmable, not over-designed. You may downscale very large screenshots to keep the file
    reasonable, but NEVER omit or redact evidence — include full secret values verbatim (UAT scope above).

Content of BOTH files:
  A. EXECUTIVE SUMMARY (2-4 sentences): the real risk posture with noise excluded — how many findings
     are Actionable vs Non-actionable, and the top real issue(s).

  B. TRIAGE TABLE — EVERY finding, one row each, with an explicit Action flag:
       ID | Finding | Verdict (Confirmed/Likely/False Positive/Informational) | Severity | Action | One-line reason
     • Action = "Actionable"     -> Confirmed/Likely real weaknesses that need a fix or follow-up.
     • Action = "Non-actionable" -> False Positives (noise) and Informational/design-observations
       (true but not a vulnerability — note-only / hardening).
     Nothing is omitted: ALL findings appear here regardless of verdict.

  C. ACTIONABLE FINDINGS — a full VAPT ticket for EACH Actionable finding, in THIS field order
     (per the REPORTING STANDARD below), with evidence images embedded:

        ### <n>. <Finding Title>
        - **Status:** Open
        - **Confidence:** Confirmed | Likely
        - **Severity (business-informed):** <Critical|High|Medium|Low>
        - **CVSS Severity:** <band derived from the score>
        - **CVSS Score:** <number> <Band>
        - **CVSS Vector:** `CVSS:3.1/...`   (the score MUST match this vector)
        - **CWE / OWASP:** <root-cause CWE-...> · MASVS-... · MASTG-...
        - **Affected:** <bundle id / file / URL scheme / keychain item / endpoint + host>
        - **Severity Justification:** <why this severity; device-local vs network reach; any chaining>
        - **Description:** <what it is + the EXACT evidence you saw (decoded values, log lines)>
        - **Impact:** <technical-consequence bullets — the data/types actually exposed>
        - **Business Impact:** <operational/reputational/financial bullets; note if jailbroken/physical access is required>
        - **Mitigation:** <concrete, code-level actions + expected hardened behavior — NOT "follow best practices">
        - **Proof of Concept:** <step-by-step with the real requests/values, and EMBED each supporting
              screenshot inline -> ![<caption>](screenshots/<file>)  (file + caption from screenshots/index.json)>
     IMAGES ARE REQUIRED wherever a finding has screenshot evidence.

  D. NON-ACTIONABLE ITEMS — list EVERY False Positive and Informational finding (do NOT drop them),
     ONE concise entry each (a line, not a ticket):
        - <id> <title> — <Verdict> — <one-line reason it needs no action>
     For Informational / design-observations, add a short one-line hardening suggestion where useful.
     Keep this section tight.

  E. AUTOMATED LIVE VERIFICATION & DEEP-DIVE — this is the core of the job, not an afterthought.
     Do NOT leave findings as "verify manually." Drive the verification yourself, end to end:
       i.   Ask the operator to connect the jailbroken iPhone over USB and confirm it's reachable
            (`idevice_id -l`, `frida-ps -U`). If a check needs a particular app state (e.g. logged
            OUT), ask them to set it, then continue automatically.
       ii.  For EVERY Likely / needs-validation finding, actually RUN the proof with the on-host
            tooling. Reuse the framework's bridges from the repo root — this package is at
            <repo>/output/<bundle>/ai_review, so the repo is `../../..`: `core.ios_device.IOSDevice`
            (SSH/scp/screencap/containers) and `core.frida_bridge.FridaBridge` (keychain_dump,
            open_url/open_urls, dump_memory, run_script) — or raw frida / ssh / sqlite3 /
            idevicesyslog / otool / plutil / base64.
       iii. DEEP-DIVE — don't stop at the first signal. Decode/parse blobs (sqlite3 + base64/plutil),
            re-fire URL schemes while LOGGED OUT and screenshot the result, dump & grep process memory,
            and for keychain DECODE THE ITEM VALUES to prove whether they're real secrets or SDK
            metadata. Chain it: a leaked token -> where is it used, is it still valid, what does it unlock?
       iv.  Capture fresh EVIDENCE — save new screenshots into `screenshots/` and command output into
            `logs/`, and embed/cite them.
       v.   For each confirmed check, upgrade the finding to CONFIRMED, move it to ACTIONABLE,
            re-derive CVSS from what you actually proved, and REGENERATE both report files.
     Goal: turn the noisy automated dump into a thorough, polished report a senior pentester would sign.

────────────────────────────────────────────────────────────────────────
REPORTING STANDARD (authoritative — applies to every ticket; no external skill required):
  • NEVER fabricate endpoints, payloads, tokens, roles, responses, or steps not in the evidence.
    Preserve the tester's real values verbatim (full, unredacted — UAT scope above).
  • CVSS: the numeric Score MUST match the CVSS:3.1 Vector exactly, and the Severity band MUST match
    the score. A vector with C:N/I:N/A:N scores 0.0 -> Informational.
        Bands: Critical 9.0–10.0 · High 7.0–8.9 · Medium 4.0–6.9 · Low 0.1–3.9 · Informational 0.0
  • CVSS calibration for iOS (be realistic about attack prerequisites):
        AV:L for on-device / physical / jailbroken-only exploitation (most client-side storage,
        keychain, memory, snapshot findings) — this LOWERS real-world severity; reflect that honestly.
        AV:N only for genuinely remote reach (ATS cleartext, missing TLS pinning, universal links/API).
        PR:N no account · PR:L normal user · UI:R if victim action needed · S:C only if exploitation
        crosses a trust boundary.
  • CWE = the ROOT weakness, not the symptom (Missing Authorization = CWE-862; Insecure Storage =
    CWE-922/CWE-312; Cleartext Transmission = CWE-319). Add MASVS/MASTG ids when clearly relevant.
  • Mitigations must be CONCRETE and code-level (the exact check/config/API + expected hardened
    behavior) — never "follow best practices".
  • Claim only what the evidence demonstrates. Secure/accepted behavior, or metadata-only exposure with
    no real data -> Informational/design-observation (Non-actionable), never an inflated severity.
  • Voice: "Testing confirmed…", "This indicates…", "No direct security impact identified" for secure
    behavior. Avoid hype ("attacker can now…", "complete compromise", "critical — immediate action").
  • Business-Informed Severity MAY differ from the CVSS technical score (e.g. chaining) — when it does,
    state BOTH and justify in Severity Justification.

If a `vapt-ticket-writer` skill is also installed you may use it, but the standard above is authoritative.
"""
    (pkg / "PROMPT.md").write_text(prompt, encoding="utf-8")


def _write_claude_md(pkg: Path) -> None:
    (pkg / "CLAUDE.md").write_text(
        "# iOS pentest evidence triage\n\n"
        "This directory is a TrashiOS AI-review package. When the user says to begin, follow "
        "`PROMPT.md` exactly:\n\n"
        "**Authorized UAT pentest — record FULL secret values as evidence; do NOT redact, mask, or truncate them.**\n\n"
        "1. Load `findings.json` (each finding has an `id` and an `evidence` block listing its "
        "screenshots and log files).\n"
        "2. Work finding-by-finding: VIEW every screenshot in its evidence (see "
        "`screenshots/index.json`), READ its log files in `logs/`.\n"
        "3. Aggressively filter false positives.\n"
        "4. Write `final_report.md` using the operator's finding-field format (Severity / Status / "
        "Confidence / CVSS (estimated) / CVSS Vector (estimated) / Business Impact / Description / "
        "Proof of Concept / Remediation), and EMBED supporting screenshots inline with "
        "`![caption](screenshots/<file>)`. ALSO write `final_report.html` — the same report as a self-contained HTML file with every evidence image embedded inline (base64 data URI), NOTHING redacted, and a SIMPLE, functional design (minimal CSS, no high-end styling).\n"
        "5. DRIVE automated live verification (the core of the job): ask the operator to connect the "
        "jailbroken iPhone, then for EVERY Likely / needs-validation finding run the proof yourself — "
        "reuse the TrashiOS bridges at the repo root `../../..` (IOSDevice, FridaBridge) or raw "
        "frida/ssh/sqlite3/idevicesyslog/otool/base64. Deep-dive (decode blobs & keychain item values, "
        "re-fire URL schemes LOGGED-OUT + screenshot, grep process memory), save fresh evidence into "
        "`screenshots/` and `logs/`, then upgrade confirmed findings and regenerate a polished "
        "`final_report.md` with the real PoC embedded.\n\n"
        "Reports split findings into **Actionable** tickets and **Non-actionable** items (both flagged in the triage table); the full VAPT reporting standard is embedded in PROMPT.md — no external skill required.\n",
        encoding="utf-8",
    )


def _write_runner(pkg: Path) -> None:
    script = pkg / "run_review.sh"
    script.write_text(
        "#!/usr/bin/env bash\n"
        "# Run Claude over this evidence package to produce final_report.md.\n"
        "set -euo pipefail\n"
        'cd "$(dirname "$0")"\n'
        'if [ -n "${TRASHIOS_REVIEW_CMD:-}" ]; then\n'
        '  echo "Running custom review command: $TRASHIOS_REVIEW_CMD"\n'
        '  case "$TRASHIOS_REVIEW_CMD" in\n'
        '    *"{prompt_file}"*) eval "${TRASHIOS_REVIEW_CMD//\\{prompt_file\\}/PROMPT.md}" ;;\n'
        '    *) eval "$TRASHIOS_REVIEW_CMD \\"$(cat PROMPT.md)\\"" ;;\n'
        '  esac\n'
        'else\n'
        '  command -v claude >/dev/null 2>&1 || { echo "claude not on PATH (or set TRASHIOS_REVIEW_CMD)"; exit 1; }\n'
        '  echo "Running Claude over the review package (reads logs + views all screenshots; a few minutes)..."\n'
        '  claude -p "$(cat PROMPT.md)" --permission-mode acceptEdits --output-format text\n'
        'fi\n'
        'echo\n'
        'echo "Done. Final report: $(pwd)/final_report.md"\n',
        encoding="utf-8",
    )
    try:
        os.chmod(script, 0o755)
    except OSError:
        pass


# ── optional auto-run (--ai-review) ──────────────────────────────

def run_claude_review(pkg: Path, console: Console, timeout_s: int = 1800) -> None:
    """Run an AI over the package to write final_report.md, with LIVE progress.

    Provider-agnostic: if $TRASHIOS_REVIEW_CMD is set, that command runs instead of
    the bundled `claude` CLI, so you can point the review at any agentic backend
    (e.g. aider on OpenRouter, an Ollama wrapper, a local script). Placeholders:
    {prompt_file} -> path to PROMPT.md, {prompt} -> its inlined text; if neither is
    present the PROMPT.md path is appended as the final argument.
    """
    prompt_path = pkg / "PROMPT.md"
    custom = os.environ.get("TRASHIOS_REVIEW_CMD")
    if custom:
        import shlex
        if "{prompt_file}" in custom:
            cmd = shlex.split(custom.replace("{prompt_file}", str(prompt_path)))
        elif "{prompt}" in custom:
            cmd = shlex.split(custom.replace("{prompt}", prompt_path.read_text(encoding="utf-8")))
        else:
            cmd = shlex.split(custom) + [str(prompt_path)]
        console.print(f"[cyan]Running custom review command ($TRASHIOS_REVIEW_CMD):[/cyan] [white]{custom}[/white]")
        try:
            subprocess.run(cmd, cwd=str(pkg), timeout=timeout_s)
        except FileNotFoundError:
            console.print(f"[yellow]Command not found: {cmd[0]!r}. Check $TRASHIOS_REVIEW_CMD.[/yellow]")
        except subprocess.TimeoutExpired:
            console.print(f"[yellow]Review command timed out ({timeout_s // 60} min).[/yellow]")
        _announce_final(pkg, console)
        return

    if not shutil.which("claude"):
        console.print("[yellow]`claude` CLI not found on PATH — skipping auto-review.\n"
                      f"  Run it yourself:  cd '{pkg}' && ./run_review.sh\n"
                      "  Or any backend:   set $TRASHIOS_REVIEW_CMD, or paste PROMPT.md into a cloud model "
                      "(see 'Next steps' below).[/yellow]")
        return

    _run_claude_streaming(pkg, prompt_path.read_text(encoding="utf-8"), console, timeout_s)
    _announce_final(pkg, console)


def _announce_final(pkg: Path, console: Console) -> None:
    final = pkg / "final_report.md"
    if final.exists():
        console.print(f"[green]✓ Final triaged report: {final}[/green]")
    else:
        console.print(f"[yellow]Finished, but final_report.md was not written — check the output above. "
                      f"Package: {pkg}[/yellow]")


def _tool_summary(inp: dict) -> str:
    for k in ("file_path", "path", "pattern", "command", "url", "description"):
        v = inp.get(k)
        if isinstance(v, str) and v:
            return (v[:70] + "…") if len(v) > 70 else v
    return ""


def _run_claude_streaming(pkg: Path, prompt: str, console: Console, timeout_s: int) -> None:
    """Run `claude` headless with stream-json so the operator SEES live activity —
    every tool the model runs, files it touches, and a final cost/duration line —
    instead of a silent terminal until the very end."""
    cmd = ["claude", "-p", prompt, "--permission-mode", "acceptEdits",
           "--output-format", "stream-json", "--verbose"]
    console.print("[cyan]Starting AI review — live activity below (runs for several minutes).[/cyan]")
    console.print("[dim]  A second Claude session is now working in this folder; leave it running.[/dim]\n")
    start = time.time()

    def _el() -> str:
        s = int(time.time() - start)
        return f"{s // 60}m{s % 60:02d}s"

    try:
        proc = subprocess.Popen(cmd, cwd=str(pkg), stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, text=True, bufsize=1)
    except FileNotFoundError:
        console.print("[yellow]`claude` could not be launched.[/yellow]")
        return

    n_tools = 0
    try:
        for line in proc.stdout:
            if time.time() - start > timeout_s:
                proc.kill()
                console.print(f"[yellow]Review exceeded {timeout_s // 60} min — stopped. Re-run ./run_review.sh.[/yellow]")
                break
            line = line.strip()
            if not line:
                continue
            try:
                ev = json.loads(line)
            except ValueError:
                continue
            typ = ev.get("type")
            if typ == "assistant":
                for b in ev.get("message", {}).get("content", []):
                    if b.get("type") == "tool_use":
                        n_tools += 1
                        console.print(f"  [dim]{_el()}[/dim] [cyan]●[/cyan] {b.get('name', 'tool')} "
                                      f"[dim]{_tool_summary(b.get('input', {}))}[/dim]")
                    elif b.get("type") == "text":
                        txt = " ".join(b.get("text", "").split())
                        if txt:
                            console.print(f"  [dim]{_el()}[/dim] [white]{txt[:140]}[/white]")
            elif typ == "result":
                dur = ev.get("duration_ms", 0) // 1000
                cost = ev.get("total_cost_usd")
                tail = f", ${cost:.3f}" if isinstance(cost, (int, float)) else ""
                console.print(f"\n  [green]✔ review finished[/green] [dim]({dur}s, {n_tools} tool calls{tail})[/dim]")
        proc.wait(timeout=10)
    except KeyboardInterrupt:
        proc.kill()
        console.print("[yellow]Interrupted — partial work left in the package.[/yellow]")
    except Exception as e:
        console.print(f"[yellow]Review stream ended: {e}[/yellow]")


def launch_claude_interactive(pkg: Path, console: Console) -> None:
    """Hand the terminal to an INTERACTIVE claude session in the package, seeded
    with the starter prompt. Unlike the headless path this can ask the operator
    questions mid-review ("connect the iPhone", "log the app out", "shall I verify
    this finding live?") and run the on-device verification with the operator in the
    loop — the whole point of the live-verification step. The tool stays alive while
    the session runs (device bridges stay up), and resumes when the operator exits.
    """
    if not shutil.which("claude"):
        console.print("[yellow]`claude` CLI not found on PATH. Start a session yourself:\n"
                      f"  cd '{pkg}' && claude[/yellow]")
        return
    console.print("[cyan]Launching an interactive Claude session in the evidence package…[/cyan]")
    console.print("[dim]  It can ask you to connect the iPhone / log the app out and verify findings live.\n"
                  "  Keep the phone plugged in. Type /exit (or Ctrl-D) when the report is done.[/dim]\n")
    try:
        # Positional prompt → interactive REPL seeded with it; acceptEdits so report/evidence
        # writes don't prompt, while device/bash actions still ask (operator stays in control).
        subprocess.run(["claude", STARTER_PROMPT, "--permission-mode", "acceptEdits"], cwd=str(pkg))
    except FileNotFoundError:
        console.print("[yellow]`claude` could not be launched.[/yellow]")
    except KeyboardInterrupt:
        pass
    _announce_final(pkg, console)


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
        "[bold]1) Hand the package to an AI to triage — pick a backend:[/bold]",
        "   • [bold]Claude Code[/bold] (best — reads the screenshots, can verify on-device):",
        f"       [white]cd '{pkg}' && claude[/white]   [dim]then say: follow PROMPT.md[/dim]",
        f"       [white]cd '{pkg}' && ./run_review.sh[/white]   [dim]headless → writes final_report.md[/dim]",
        "   • [bold]Any other agentic backend[/bold] (OpenRouter / Ollama / aider / custom CLI):",
        "       [white]export TRASHIOS_REVIEW_CMD='aider --message-file {prompt_file} --yes'[/white]",
        "       [dim]then ./run_review.sh (or re-run with --ai-review). {prompt_file}=PROMPT.md path, {prompt}=inlined text.[/dim]",
        "   • [bold]A plain cloud chat[/bold] (claude.ai / ChatGPT / OpenRouter web): paste [white]PROMPT.md[/white] + "
        "[white]report.md[/white].",
        "       [dim]Caveat: a non-agentic chat can triage the text but can't VIEW the screenshots or run the live "
        "on-device checks — use an agentic CLI above for the full job.[/dim]",
        "",
        "[bold]2) Prompt to give the AI:[/bold]",
        f"   [italic]{STARTER_PROMPT}[/italic]",
        "",
        "[bold]3) Then:[/bold] review [white]final_report.md[/white]. For every 'Likely' finding the AI will "
        "verify it live on the connected jailbroken iPhone (decode DB/keychain values, re-fire URL "
        "schemes logged-out, grep memory) and regenerate the report with a confirmed PoC + evidence.",
    ]
    console.print(Panel("\n".join(lines), title="Next steps — AI triage", style="cyan", expand=False))
