"""
Shared utility functions used across multiple phases.
"""

from __future__ import annotations

import re
from core.config import SENSITIVE_PATTERNS, FALSE_POSITIVE_PREFIXES


def is_library_component(name: str) -> bool:
    """Check if a component name belongs to a known library/framework prefix."""
    return any(name.startswith(prefix) for prefix in FALSE_POSITIVE_PREFIXES)


def grep_sensitive_lines(text: str, max_lines: int = 200) -> str:
    """Run a case-insensitive regex search over a string for sensitive patterns.
    Returns matching lines joined by newline, capped at max_lines."""
    matches = []
    for line in text.splitlines():
        if re.search(SENSITIVE_PATTERNS, line, re.IGNORECASE):
            matches.append(line.strip())
        if len(matches) >= max_lines:
            break
    return "\n".join(matches)


# ── Presidio-aware scanning helpers ────────────────────────────

def presidio_scan_text(
    text: str,
    config,
    source_label: str = "",
    score_threshold: float = 0.4,
) -> list[dict]:
    """Scan text for PII using Presidio if available, else fall back to regex.

    Args:
        text: The text to analyze.
        config: Config object (checked for presidio_engine).
        source_label: Label for the source of the text (e.g. "logcat", "filesystem").
        score_threshold: Minimum confidence score for Presidio results.

    Returns:
        List of finding dicts with keys: entity_type, text, score, context, source, severity.
        Empty list if no findings.
    """
    if not text or not text.strip():
        return []

    engine = getattr(config, "presidio_engine", None)
    if engine is not None:
        try:
            return engine.analyze_text_for_findings(
                text,
                source_label=source_label,
                score_threshold=score_threshold,
            )
        except Exception:
            pass  # Fall through to regex

    # Regex fallback
    matches = grep_sensitive_lines(text)
    if matches:
        return [{
            "entity_type": "SENSITIVE_PATTERN",
            "text": matches,
            "score": 0.5,
            "context": "",
            "source": source_label,
            "severity": "High",
            "needs_validation": True,
        }]
    return []


def presidio_scan_file(
    file_path: str,
    config,
    source_label: str = "",
    score_threshold: float = 0.4,
) -> list[dict]:
    """Scan a file for PII using Presidio if available, else fall back to regex.

    Returns:
        List of finding dicts.
    """
    engine = getattr(config, "presidio_engine", None)
    if engine is not None:
        try:
            return engine.analyze_file(
                file_path,
                source_label=source_label,
                score_threshold=score_threshold,
            )
        except Exception:
            pass  # Fall through to regex

    # Regex fallback: read file and grep
    try:
        from pathlib import Path
        content = Path(file_path).read_text(encoding="utf-8", errors="replace")
        matches = grep_sensitive_lines(content)
        if matches:
            return [{
                "entity_type": "SENSITIVE_PATTERN",
                "text": matches,
                "score": 0.5,
                "context": "",
                "source": source_label or str(file_path),
                "severity": "High",
                "needs_validation": True,
            }]
    except Exception:
        pass
    return []


def presidio_findings_to_report(
    findings: list[dict],
    phase: str,
    config,
    fallback_title: str = "Sensitive data detected",
    fallback_detail: str = "",
) -> None:
    """Convert Presidio findings into config.add_finding() calls.

    Groups findings by entity type and creates one finding per type
    to avoid spamming the report with per-match entries.
    """
    if not findings:
        return

    # Group by entity_type
    grouped: dict[str, list[dict]] = {}
    for f in findings:
        entity = f.get("entity_type", "UNKNOWN")
        grouped.setdefault(entity, []).append(f)

    for entity_type, group in grouped.items():
        # Determine severity (highest in group)
        severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
        best_sev = min(group, key=lambda g: severity_order.get(g.get("severity", "Info"), 4))
        severity = best_sev.get("severity", "High")

        # Build detail text
        avg_score = sum(g.get("score", 0) for g in group) / len(group)
        source = group[0].get("source", "")

        if entity_type == "SENSITIVE_PATTERN":
            # Regex fallback — use original format
            title = fallback_title
            detail = fallback_detail or group[0].get("text", "")
        else:
            title = f"PII detected: {entity_type} ({len(group)} occurrence{'s' if len(group) > 1 else ''})"
            match_samples = []
            for g in group[:10]:
                matched = g.get("text", "")
                ctx = g.get("context", "")
                score = g.get("score", 0)
                match_samples.append(
                    f"  - [{score:.2f}] \"{matched}\"" +
                    (f"\n    Context: ...{ctx}..." if ctx and ctx != matched else "")
                )
            detail = (
                f"Entity type: {entity_type}\n"
                f"Source: {source}\n"
                f"Avg confidence: {avg_score:.2f}\n"
                f"Occurrences: {len(group)}\n\n"
                f"Sample matches:\n" + "\n".join(match_samples)
            )
            if len(group) > 10:
                detail += f"\n  ... and {len(group) - 10} more"

        config.add_finding(phase, title, severity, detail[:5000])
