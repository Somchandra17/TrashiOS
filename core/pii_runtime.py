"""
Runtime initialization for PII detection backends.
"""

from __future__ import annotations

from core.config import Config


def initialize_pii_detection(config: Config, use_presidio: bool, use_ner: bool, console) -> int:
    """Initialize and warm up the selected PII backend.

    Returns:
        0 when execution should continue.
        1 when execution must stop (strict --ner behavior).
    """
    if not (use_presidio or use_ner):
        console.print(
            "[dim]PII detection: regex-only (default). "
            "Use --presidio or --ner for enhanced detection.[/dim]"
        )
        return 0

    try:
        from core.presidio_engine import init_engine, is_available
    except Exception as e:
        if use_ner:
            console.print(f"[red]Failed to load Presidio engine: {e}[/red]")
            console.print(
                "[red]--ner requires Presidio + GLiNER and cannot fall back.[/red]\n"
                "  Install with: [white]pip install -r requirements-ner.txt[/white]\n"
                "  Or: [white]pip install \"presidio-analyzer[gliner]>=2.2.35\"[/white]"
            )
            return 1
        console.print(f"[red]Presidio initialization failed: {e}[/red]")
        console.print("[yellow]Falling back to regex-only PII scanning.[/yellow]")
        config.presidio_engine = None
        return 0

    if not is_available():
        if use_ner:
            console.print(
                "[red]presidio-analyzer is not installed.[/red]\n"
                "  Install with: [white]pip install -r requirements-ner.txt[/white]\n"
                "  Or: [white]pip install \"presidio-analyzer[gliner]>=2.2.35\"[/white]"
            )
            console.print("[red]--ner requested, aborting instead of degrading detection.[/red]")
            return 1
        console.print(
            "[red]presidio-analyzer is not installed.[/red]\n"
            "  Install with: [white]pip install -r requirements-presidio.txt[/white]\n"
            "  Or: [white]pip install presidio-analyzer>=2.2.35[/white]"
        )
        console.print("[yellow]Falling back to regex-only PII scanning.[/yellow]")
        return 0

    try:
        presidio_engine = init_engine(use_gliner=use_ner)
        _ = presidio_engine.analyzer
        config.presidio_engine = presidio_engine
    except (Exception, SystemExit) as e:
        # NB: spaCy's model auto-download fails via sys.exit() (a SystemExit, NOT an Exception),
        # so we must catch SystemExit here or --presidio/--ner would crash instead of degrading.
        config.presidio_engine = None
        reason = (f"spaCy NLP model unavailable / auto-download failed (exit {e})"
                  if isinstance(e, SystemExit) else str(e))
        if use_ner:
            console.print(f"[red]GLiNER/Presidio initialization failed: {reason}[/red]")
            console.print(
                "[red]--ner requires a working GLiNER backend and cannot fall back.[/red]\n"
                "  Install deps: [white]pip install -r requirements-ner.txt[/white]\n"
                "  And the spaCy model: [white]python3 -m spacy download en_core_web_lg[/white]"
            )
            return 1
        console.print(f"[red]Presidio initialization failed: {reason}[/red]")
        console.print("[yellow]Falling back to regex-only PII scanning. For full Presidio, install the "
                      "spaCy model: [white]python3 -m spacy download en_core_web_lg[/white][/yellow]")
        return 0

    if use_ner:
        console.print(
            "[green]PII detection: Presidio + GLiNER NER "
            "(urchade/gliner_multi_pii-v1) enabled[/green]"
        )
    else:
        console.print(
            "[green]PII detection: Presidio regex + checksum validators enabled[/green]"
        )
    return 0
