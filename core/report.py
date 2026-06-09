"""
Markdown report generator: compiles all phase findings into a single .md report.
"""

from __future__ import annotations
import json
import re
from datetime import datetime
from pathlib import Path

from core.config import Config


AI_PROMPT = """You are a senior mobile security engineer. Review the following iOS DAST/SAST findings,
assign a CVSS-style risk rating (Critical / High / Medium / Low / Info) to each finding,
map each to the relevant OWASP MASVS control, write an executive summary, and generate a Jira
ticket description for each High and Critical finding. Provide remediation recommendations for every finding."""

EXPECTED_PHASES = [
    "Phase I — App Binary Decryption",
    "Phase II — Static Binary & Info.plist Analysis",
    "Phase III — Local Data Storage Analysis",
    "Phase IV — Dump File Verification",
    "Phase V — Keychain Dump & Data Protection",
    "Phase VI — Backgrounding Snapshot Leakage",
    "Phase VII — Pasteboard Leakage",
    "Phase VIII — Device Log Monitoring",
    "Phase IX — Process Memory Analysis",
    "Phase X — URL Scheme / IPC Testing",
    "Phase XI — Post-Logout Access Control",
    "Phase XII — Backup Analysis",
    "Phase XIII — Runtime Hardening Assessment",
]

CVSS_BY_SEVERITY = {
    "Critical": ("9.0", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    "High": ("8.0", "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:L"),
    "Medium": ("5.5", "CVSS:3.1/AV:L/AC:L/PR:L/UI:R/S:U/C:L/I:L/A:N"),
    "Low": ("3.1", "CVSS:3.1/AV:L/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N"),
    "Info": ("0.0", "N/A"),
}


def _contextual_cvss(severity: str, title: str, detail: str) -> tuple[str, str]:
    """Derive context-aware CVSS vector based on finding type, not just severity."""
    text = f"{title}\n{detail}".lower()
    base_score, base_vector = CVSS_BY_SEVERITY.get(severity, ("0.0", "N/A"))

    if severity == "Info" or base_vector == "N/A":
        return base_score, base_vector

    # Adjust Attack Vector based on finding context
    if any(kw in text for kw in ["backup", "usb", "physical", "jailbroken", "jailbreak", "snapshot",
                                  "keychain", "local storage", "data container", "process memory", "pasteboard"]):
        # Physical / local access required (on-device artifacts, lock-screen, etc.)
        return base_score, base_vector.replace("AV:N", "AV:P")
    if any(kw in text for kw in ["url scheme", "deeplink", "universal link", "app extension",
                                  "reachable after logout", "token persists", "intent"]):
        # Local attack — requires a malicious app / interaction on the same device
        return base_score, base_vector.replace("AV:N", "AV:L")
    if any(kw in text for kw in ["cleartext", "http://", "network", "mitm", "ats", "arbitrary loads",
                                  "no certificate pinning", "no pinning", "tls"]):
        # Network-based attack
        return base_score, base_vector  # Already AV:N
    if any(kw in text for kw in ["sql injection", "path traversal"]):
        return base_score, base_vector.replace("AV:N", "AV:L")

    return base_score, base_vector


def _dedupe_findings(config: Config) -> dict[str, list[dict]]:
    """Merge duplicate findings by (phase, title, severity, status)."""
    deduped: dict[str, list[dict]] = {}
    grouped: dict[tuple[str, str, str, str], list[str]] = {}

    for phase_name, phase_findings in config.findings.items():
        for f in phase_findings:
            key = (phase_name, f["title"], f["severity"], f["status"])
            grouped.setdefault(key, []).append(f["detail"])

    for (phase_name, title, severity, status), details in grouped.items():
        merged_detail: str
        if len(details) == 1:
            merged_detail = details[0]
        else:
            variant_lines = [f"Variant {idx}: {d}" for idx, d in enumerate(details, 1)]
            merged_detail = "\n\n---\n\n".join(variant_lines)
        deduped.setdefault(phase_name, []).append(
            {
                "title": title,
                "severity": severity,
                "status": status,
                "detail": merged_detail,
                "occurrences": len(details),
            }
        )

    return deduped


def _confidence_for_finding(title: str, detail: str) -> str:
    text = f"{title}\n{detail}".lower()
    if any(k in text for k in ["not confirmed", "no evidence", "may indicate", "might"]):
        return "Needs manual validation"
    if any(k in text for k in ["confirmed", "verified via", "keychain dump", "syslog evidence",
                                "objection output", "otool", "extracted from container", "decrypted"]):
        return "Confirmed"
    return "Likely"


def _remediation_for_finding(title: str, detail: str) -> str:
    text = f"{title}\n{detail}".lower()
    if "url scheme" in text or "deeplink" in text or "universal link" in text or "app extension" in text:
        return (
            "Treat URL schemes / universal links as untrusted input. Authenticate and authorize every "
            "action reached via a deeplink server-side, validate and sanitize all parameters, and never "
            "perform state-changing or privileged actions from a scheme handler without an authenticated session."
        )
    if "reachable after logout" in text or "token persists" in text or "broken access control" in text \
            or "post-logout" in text or "session not terminated" in text:
        return (
            "Enforce server-side session validation on every privileged screen/API call. Invalidate the "
            "session token server-side on logout and delete it from the keychain and any plist/NSUserDefaults. "
            "Re-check auth state in viewWillAppear/viewDidLoad of sensitive view controllers."
        )
    if "keychain" in text and ("accessible" in text or "always" in text or "thisdeviceonly" in text or "access group" in text):
        return (
            "Store secrets with the strictest data-protection class that fits the use case "
            "(prefer kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly; never kSecAttrAccessibleAlways). "
            "Add `ThisDeviceOnly` so items do not migrate via iCloud/backup, and scope keychain-access-groups narrowly."
        )
    if "ats" in text or "arbitrary loads" in text or "cleartext" in text or "no certificate pinning" in text or "no pinning" in text:
        return (
            "Remove NSAllowsArbitraryLoads and per-domain ATS exceptions; require TLS 1.2+ for all endpoints. "
            "Implement certificate or public-key pinning for sensitive APIs and fail closed on validation errors."
        )
    if "pie" in text or "stack canary" in text or "arc not enabled" in text or "get-task-allow" in text:
        return (
            "Rebuild with default compiler hardening: PIE (-fPIC/-pie), stack canaries (-fstack-protector-all), "
            "and ARC enabled. Ship release builds without the get-task-allow entitlement so debuggers cannot attach."
        )
    if "snapshot" in text:
        return (
            "Mask sensitive UI before backgrounding: in applicationWillResignActive/sceneWillResignActive, "
            "cover the window with a blank/branded overlay or set isSecureTextEntry so the app-switcher snapshot leaks nothing."
        )
    if "pasteboard" in text:
        return (
            "Do not copy secrets to the general (system) pasteboard. Use a named/local pasteboard, set an "
            "expirationDate, and clear sensitive values; avoid auto-copying OTPs/tokens."
        )
    if "device log" in text or "syslog" in text or "nslog" in text or "sensitive data leaked" in text:
        return (
            "Remove sensitive fields from logs, use os_log with private formatting, and disable verbose logging "
            "in release builds. Add CI checks to block logging of tokens, PII, and credentials."
        )
    if "backup" in text or "not excluded from backup" in text:
        return (
            "Exclude secret files from backups with NSURLIsExcludedFromBackupKey, store secrets in the keychain "
            "(not flat files), and encrypt sensitive data at rest."
        )
    if "info.plist" in text or "file sharing" in text or "usage description" in text:
        return (
            "Harden Info.plist: disable UIFileSharingEnabled unless required, scope entitlements to the minimum, "
            "and provide accurate, minimal privacy usage-description strings only for capabilities actually used."
        )
    if "hardcoded secret" in text or "weak crypto" in text:
        return (
            "Remove hardcoded secrets from the binary; fetch credentials at runtime over an authenticated channel. "
            "Replace weak algorithms (DES/ECB/MD5/SHA1) with AES-GCM and SHA-256+."
        )
    return "Perform root-cause analysis, implement least-privilege controls, and re-run this phase to verify closure."


def _business_impact_for_finding(title: str, detail: str) -> str:
    text = f"{title}\n{detail}".lower()
    if "url scheme" in text or "deeplink" in text or "universal link" in text:
        return "Unvalidated deeplinks let other apps/links trigger privileged actions or inject input, abusing business logic."
    if "reachable after logout" in text or "token persists" in text or "access control" in text or "post-logout" in text:
        return "Unauthorized account access after logout can lead to privacy breach and account-takeover risk."
    if "keychain" in text:
        return "Weakly-protected keychain items can be recovered from a lost/stolen or jailbroken device, exposing credentials."
    if "ats" in text or "cleartext" in text or "pinning" in text:
        return "Cleartext or unpinned traffic can be intercepted/modified on hostile networks (MitM), leaking session data."
    if "snapshot" in text or "pasteboard" in text:
        return "Sensitive data cached in app-switcher snapshots or the system clipboard is readable by other apps/onlookers."
    if "device log" in text or "syslog" in text or "sensitive data leaked" in text:
        return "PII/token leakage in device logs can be harvested on a jailbroken/connected device, increasing data exposure."
    if "backup" in text:
        return "Backup exposure may allow offline extraction of local application data from an unencrypted iTunes/Finder backup."
    if "pie" in text or "canary" in text or "get-task-allow" in text:
        return "Missing binary hardening lowers the cost of reverse-engineering, tampering, and runtime exploitation."
    return "Security control weakness increases risk of confidentiality/integrity impact under adversarial conditions."


def _phase_coverage(config: Config, deduped_findings: dict[str, list[dict]]) -> list[dict]:
    executed_phases = {entry["phase"] for entry in config.commands_log}
    coverage: list[dict] = []
    for phase in EXPECTED_PHASES:
        ran = phase in executed_phases or phase in deduped_findings
        findings_count = len(deduped_findings.get(phase, []))
        status = "Skipped"
        if ran and findings_count > 0:
            status = "Executed (findings)"
        elif ran:
            status = "Executed (no findings)"
        coverage.append({"phase": phase, "status": status, "findings": findings_count})
    return coverage


def _jira_block(phase_name: str, finding: dict, cvss_score: str, remediation: str, description: str) -> str:
    return (
        f"Summary: {finding['title']}\n"
        f"Issue Type: Security Vulnerability\n"
        f"Priority: {finding['severity']}\n"
        f"Phase: {phase_name}\n"
        f"CVSS: {cvss_score}\n"
        f"Description: {description[:1200]}\n"
        f"Remediation: {remediation}\n"
        "Definition of Done: Fix deployed, regression test added, and DAST re-run confirms closure."
    )


def _extract_target_from_title(title: str) -> str:
    if ":" not in title:
        return ""
    return title.split(":", 1)[1].strip()


def _best_command_evidence(commands_log: list[dict], phase_name: str, finding: dict) -> str:
    """
    Pull the most relevant command evidence for sparse findings.
    Preference: phase + target component in cmd/stdout/stderr.
    """
    target = _extract_target_from_title(finding["title"]).lower()
    phase_entries = [e for e in commands_log if e.get("phase") == phase_name]
    if not phase_entries:
        return ""

    best = None
    best_score = -1
    for entry in phase_entries:
        cmd = entry.get("cmd", "")
        stdout = entry.get("stdout", "")
        stderr = entry.get("stderr", "")
        blob = f"{cmd}\n{stdout}\n{stderr}".lower()
        score = 0
        if target and target in blob:
            score += 5
        if "start" in finding["title"].lower() and "start" in cmd.lower():
            score += 2
        if "broadcast" in finding["title"].lower() and "broadcast" in cmd.lower():
            score += 2
        if "service" in finding["title"].lower() and "service" in cmd.lower():
            score += 2
        if score > best_score:
            best_score = score
            best = entry

    if not best:
        best = phase_entries[-1]
    cmd = best.get("cmd", "")
    stdout = (best.get("stdout") or "").strip()
    stderr = (best.get("stderr") or "").strip()
    rc = best.get("rc", 0)
    return (
        f"Fallback command evidence:\n"
        f"- cmd: {cmd}\n"
        f"- rc: {rc}\n"
        f"- stdout: {(stdout[:600] if stdout else '(empty)')}\n"
        f"- stderr: {(stderr[:600] if stderr else '(empty)')}"
    )


def _normalize_detail(phase_name: str, finding: dict, commands_log: list[dict]) -> str:
    """Fill sparse details with command evidence so findings remain reviewable."""
    detail = finding["detail"]
    sparse = False
    if not detail.strip():
        sparse = True
    if re.search(r"Output:\s*$", detail, re.IGNORECASE | re.MULTILINE):
        sparse = True
    if "Output:\n\n" in detail:
        sparse = True
    if sparse:
        fallback = _best_command_evidence(commands_log, phase_name, finding)
        if fallback:
            return (
                detail.rstrip() +
                "\n\nNo direct module output was captured for this finding. "
                "Use command/screenshot evidence below.\n\n" +
                fallback
            ).strip()
    return detail


def _screenshots_for_finding(
    screenshots: list[dict],
    phase_name: str,
    finding: dict,
    used_paths: set[str],
) -> list[dict]:
    """Strict screenshot matching: require target/component-level match first."""
    title = finding["title"].lower()
    target = _extract_target_from_title(finding["title"]).lower()
    detail = finding["detail"].lower()

    candidates: list[tuple[int, dict]] = []
    for ss in screenshots:
        if ss["phase"] != phase_name or ss["path"] in used_paths:
            continue
        caption = ss["caption"].lower()
        score = 0
        if target and target in caption:
            score += 10
        elif target:
            # strict mode: if finding has a clear target, do not map generic same-phase screenshots
            continue
        if "url scheme" in title and ("url" in caption or "scheme" in caption):
            score += 2
        if "deeplink" in title and "deeplink" in caption:
            score += 2
        if "snapshot" in title and "snapshot" in caption:
            score += 2
        if "post-logout" in title and "post-logout" in caption:
            score += 2
        if "logout" in title and "logout" in caption:
            score += 2
        for token in title.split():
            if len(token) > 10 and token in caption:
                score += 1
        if score > 0 and (caption in detail or target in detail or target in caption):
            score += 1
        if score > 0:
            candidates.append((score, ss))

    candidates.sort(key=lambda x: x[0], reverse=True)
    matched = [ss for _, ss in candidates[:3]]
    for ss in matched:
        used_paths.add(ss["path"])
    return matched


class ReportGenerator:
    def __init__(self, config: Config, device_info: dict):
        self.config = config
        self.device_info = device_info

    @staticmethod
    def _extract_entity_type(finding: dict) -> str | None:
        """Extract PII entity type from a Presidio-detected finding."""
        detail = finding.get("detail", "")
        if "Entity type:" in detail:
            match = re.search(r"Entity type:\s*(\S+)", detail)
            return match.group(1) if match else None
        title = finding.get("title", "")
        if title.startswith("PII detected:"):
            match = re.match(r"PII detected:\s*(\S+)", title)
            return match.group(1) if match else None
        return None

    @staticmethod
    def _extract_confidence_score(finding: dict) -> float | None:
        """Extract average confidence score from a Presidio-detected finding."""
        detail = finding.get("detail", "")
        match = re.search(r"Avg confidence:\s*([\d.]+)", detail)
        return float(match.group(1)) if match else None

    def generate(self) -> str:
        c = self.config
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        report_name = f"iOS_DAST_Report_{c.bundle_id}_{c.timestamp}.md"
        report_path = c.output_dir / report_name
        deduped_findings = _dedupe_findings(c)
        coverage = _phase_coverage(c, deduped_findings)

        sections: list[str] = []
        used_screenshot_paths: set[str] = set()

        # ── AI prompt ──
        if c.report_mode == "internal":
            sections.append(f"```\n{AI_PROMPT}\n```\n")

        # ── Header ──
        sections.append(f"# iOS DAST/SAST Report — `{c.bundle_id}`\n")
        sections.append(f"**Generated:** {now}  ")
        sections.append(f"**Device:** {self.device_info.get('model', 'N/A')} "
                        f"(iOS {self.device_info.get('ios_version', 'N/A')}, "
                        f"build {self.device_info.get('build', 'N/A')})  ")
        sections.append(f"**Device UDID:** `{c.device_id}`  ")
        if getattr(c, "capabilities", None) is not None:
            try:
                sections.append(f"**Device capabilities:** {c.capabilities.summary()}  ")
            except Exception:
                pass
        if c.ipa_path:
            sections.append(f"**IPA:** `{c.ipa_path}`  ")
        if getattr(c, "ipa_hash", None):
            sections.append(f"**IPA SHA-256:** `{c.ipa_hash}`  ")
        sections.append(f"**Pre-installed:** {'Yes' if c.is_preinstalled else 'No'}  ")
        sections.append(f"**Tested logged in:** {'Yes' if c.logged_in else 'No'}\n")

        # ── Executive Summary ──
        sections.append("---\n## Executive Summary\n")
        total = sum(len(v) for v in deduped_findings.values())
        raw_total = sum(len(v) for v in c.findings.values())
        severity_counts: dict[str, int] = {}
        confirmed_count = 0
        for phase_findings in deduped_findings.values():
            for f in phase_findings:
                sev = f["severity"]
                severity_counts[sev] = severity_counts.get(sev, 0) + 1
                if _confidence_for_finding(f["title"], f["detail"]) == "Confirmed":
                    confirmed_count += 1

        sections.append(f"A total of **{total}** finding(s) were identified across "
                        f"**{len([p for p in coverage if p['status'] != 'Skipped'])}** executed phase(s).\n")
        if raw_total != total:
            sections.append(
                f"Deduplication merged repeated entries: raw findings **{raw_total}** -> unique findings **{total}**.\n"
            )
        sections.append(f"Confirmed findings (high-confidence evidence): **{confirmed_count}**.\n")
        if severity_counts:
            sections.append("| Severity | Count |")
            sections.append("|----------|-------|")
            for sev in ["Critical", "High", "Medium", "Low", "Info"]:
                if sev in severity_counts:
                    sections.append(f"| {sev} | {severity_counts[sev]} |")
            sections.append("")

        sections.append("## Phase Coverage\n")
        sections.append("| Phase | Status | Findings |")
        sections.append("|-------|--------|----------|")
        for row in coverage:
            sections.append(f"| {row['phase']} | {row['status']} | {row['findings']} |")
        sections.append("")

        # ── PII Entity Summary (Presidio-detected findings only) ──
        pii_entities: dict[str, dict] = {}  # entity_type -> {count, severities, scores}
        for phase_findings in deduped_findings.values():
            for f in phase_findings:
                detail = f.get("detail", "")
                # Parse entity type from Presidio-style findings
                if "Entity type:" in detail:
                    entity_match = re.search(r"Entity type:\s*(\S+)", detail)
                    if entity_match:
                        etype = entity_match.group(1)
                        score_match = re.search(r"Avg confidence:\s*([\d.]+)", detail)
                        avg_score = float(score_match.group(1)) if score_match else 0.0
                        count_match = re.search(r"Occurrences:\s*(\d+)", detail)
                        count = int(count_match.group(1)) if count_match else 1
                        if etype not in pii_entities:
                            pii_entities[etype] = {"count": 0, "severity": f["severity"], "scores": []}
                        pii_entities[etype]["count"] += count
                        pii_entities[etype]["scores"].append(avg_score)
                elif f.get("title", "").startswith("PII detected:"):
                    # Parse from title format: "PII detected: ENTITY_TYPE (N occurrences)"
                    title_match = re.match(r"PII detected:\s*(\S+)\s*\((\d+)", f["title"])
                    if title_match:
                        etype = title_match.group(1)
                        count = int(title_match.group(2))
                        if etype not in pii_entities:
                            pii_entities[etype] = {"count": 0, "severity": f["severity"], "scores": []}
                        pii_entities[etype]["count"] += count

        if pii_entities:
            sections.append("## PII Entities Detected\n")
            sections.append("| Entity Type | Count | Highest Severity | Avg Confidence |")
            sections.append("|-------------|-------|------------------|----------------|")
            for etype, info in sorted(pii_entities.items(), key=lambda x: x[1]["count"], reverse=True):
                avg_conf = sum(info["scores"]) / len(info["scores"]) if info["scores"] else 0.0
                sections.append(f"| {etype} | {info['count']} | {info['severity']} | {avg_conf:.2f} |")
            sections.append("")

        # ── Per-phase findings ──
        sections.append("---\n## Detailed Findings\n")
        for phase_name in EXPECTED_PHASES:
            phase_findings = deduped_findings.get(phase_name, [])
            sections.append(f"### {phase_name}\n")
            phase_state = next((x for x in coverage if x["phase"] == phase_name), None)
            if phase_state and phase_state["status"] == "Skipped":
                sections.append("_Phase skipped in this execution._\n")
                continue
            if phase_state and phase_state["status"] == "Executed (no findings)":
                sections.append("_Executed: no findings detected in this phase._\n")
            else:
                for i, f in enumerate(phase_findings, 1):
                    normalized_detail = _normalize_detail(phase_name, f, c.commands_log)
                    cvss_score, cvss_vector = _contextual_cvss(f["severity"], f["title"], normalized_detail)
                    confidence = _confidence_for_finding(f["title"], normalized_detail)
                    remediation = _remediation_for_finding(f["title"], normalized_detail)
                    impact = _business_impact_for_finding(f["title"], normalized_detail)

                    sections.append(f"#### {i}. {f['title']}\n")
                    sections.append(f"- **Severity:** {f['severity']}")
                    sections.append(f"- **Status:** {f['status']}")
                    sections.append(f"- **Confidence:** {confidence}")
                    if confidence == "Confirmed":
                        sections.append("> **HIGHLIGHT: CONFIRMED EVIDENCE**")
                    sections.append(f"- **CVSS (estimated):** {cvss_score}")
                    sections.append(f"- **CVSS Vector (estimated):** `{cvss_vector}`")
                    if f.get("occurrences", 1) > 1:
                        sections.append(f"- **Occurrences merged:** {f['occurrences']}")
                    sections.append(f"- **Business Impact:** {impact}")
                    sections.append(f"- **Remediation:** {remediation}")
                    sections.append(f"- **Detail:**\n")
                    detail_text = normalized_detail
                    total_len = len(detail_text)
                    if total_len > 3000:
                        detail_text = detail_text[:3000] + f"\n\n[... truncated — {total_len - 3000} more characters omitted ...]"
                    sections.append(f"```\n{detail_text}\n```\n")
                    if f["severity"] in {"High", "Critical"}:
                        sections.append("- **Jira Draft:**")
                        sections.append("```")
                        sections.append(_jira_block(phase_name, f, cvss_score, remediation, normalized_detail))
                        sections.append("```\n")

                    matched_screenshots = _screenshots_for_finding(
                        c.screenshots,
                        phase_name,
                        {"title": f["title"], "detail": normalized_detail},
                        used_screenshot_paths,
                    )
                    if matched_screenshots:
                        sections.append("- **Screenshots (evidence):**")
                        for ss in matched_screenshots:
                            sections.append(f"  - {ss['caption']}")
                            sections.append(f"![{ss['caption']}]({ss['path']})")
                        sections.append("")

            # Keep any unmatched screenshots in the same phase section (no global screenshot section).
            phase_unmapped = [
                ss for ss in c.screenshots
                if ss["phase"] == phase_name and ss["path"] not in used_screenshot_paths
            ]
            if phase_unmapped:
                sections.append("**Additional evidence captured in this phase:**")
                for ss in phase_unmapped:
                    sections.append(f"- {ss['caption']}")
                    sections.append(f"![{ss['caption']}]({ss['path']})")
                    used_screenshot_paths.add(ss["path"])
                sections.append("")

        sections.append("---\n## Missing/Manual Steps Recommended\n")
        sections.append(
            "- Validate authorization on backend APIs directly (token replay / IDOR checks), not only via UI/URL-scheme launches."
        )
        sections.append("- Intercept TLS with a MitM proxy and confirm certificate/public-key pinning behavior (bypass with objection).")
        sections.append("- Statically reverse the decrypted binary (class-dump / Hopper / Ghidra) and correlate with dynamic leakage findings.")
        sections.append("- Re-test critical flows with non-owner / low-privileged roles where applicable.")
        sections.append("- Add negative-test evidence for blocked paths (proof of mitigation/denial).")
        sections.append("")

        # ── Commands log ──
        sections.append("---\n## Commands Executed\n")
        sections.append("<details><summary>Click to expand full command log</summary>\n")
        for entry in c.commands_log:
            sections.append(f"**Phase:** {entry['phase']}  ")
            sections.append(f"```bash\n$ {entry['cmd']}\n```")
            sections.append(f"- rc: `{entry.get('rc', 0)}`")
            if entry["stdout"]:
                stdout_trimmed = entry["stdout"][:2000]
                sections.append(f"```\n{stdout_trimmed}\n```")
            if entry["stderr"]:
                sections.append(f"**stderr:**\n```\n{entry['stderr'][:1000]}\n```")
            sections.append("")
        sections.append("</details>\n")

        # ── Risk summary table ──
        sections.append("---\n## Risk Summary\n")
        sections.append("| # | Finding | Phase | Severity | Status | Confidence |")
        sections.append("|---|---------|-------|----------|--------|------------|")
        idx = 1
        for phase_name, phase_findings in deduped_findings.items():
            for f in phase_findings:
                normalized_detail = _normalize_detail(phase_name, f, c.commands_log)
                confidence = _confidence_for_finding(f["title"], normalized_detail)
                confidence_cell = "**CONFIRMED**" if confidence == "Confirmed" else confidence
                sections.append(
                    f"| {idx} | {f['title']} | {phase_name} | {f['severity']} | {f['status']} | {confidence_cell} |"
                )
                idx += 1
        sections.append("")

        full_report = "\n".join(sections)
        try:
            report_path.parent.mkdir(parents=True, exist_ok=True)
            report_path.write_text(full_report, encoding="utf-8")
        except OSError as e:
            raise RuntimeError(f"Failed to write report to {report_path}: {e}") from e

        # ── JSON findings export ──
        json_findings = []
        for phase_name, phase_findings in deduped_findings.items():
            for f in phase_findings:
                normalized_detail = _normalize_detail(phase_name, f, c.commands_log)
                cvss_score, cvss_vector = _contextual_cvss(f["severity"], f["title"], normalized_detail)
                json_findings.append({
                    "phase": phase_name,
                    "title": f["title"],
                    "severity": f["severity"],
                    "status": f["status"],
                    "cvss_score": cvss_score,
                    "cvss_vector": cvss_vector,
                    "confidence": _confidence_for_finding(f["title"], normalized_detail),
                    "remediation": _remediation_for_finding(f["title"], normalized_detail),
                    "business_impact": _business_impact_for_finding(f["title"], normalized_detail),
                    "occurrences": f.get("occurrences", 1),
                    "detail": normalized_detail[:5000],
                    # PII entity metadata (populated for Presidio-detected findings)
                    "entity_type": self._extract_entity_type(f),
                    "confidence_score": self._extract_confidence_score(f),
                })

        json_export = {
            "bundle_id": c.bundle_id,
            "device_id": c.device_id,
            "ipa_hash": getattr(c, "ipa_hash", None),
            "timestamp": now,
            "total_findings": len(json_findings),
            "severity_counts": severity_counts,
            "findings": json_findings,
        }
        json_path = c.output_dir / f"findings_{c.bundle_id}_{c.timestamp}.json"
        try:
            json_path.write_text(json.dumps(json_export, indent=2, ensure_ascii=False), encoding="utf-8")
        except OSError:
            pass

        return str(report_path)
