"""
Presidio PII detection engine with optional GLiNER NER backend.

This module wraps Microsoft Presidio's AnalyzerEngine and provides
a unified interface for PII scanning across all TrashDroid phases.

Usage:
    from core.presidio_engine import init_engine, get_engine

    # At startup (main.py):
    engine = init_engine(use_gliner=args.ner)

    # In any phase:
    engine = get_engine()
    findings = engine.analyze_text_for_findings(text, source_label="logcat")
"""

from __future__ import annotations

import logging
from typing import Optional

logger = logging.getLogger(__name__)

# ── Entity type → TrashDroid severity mapping ──────────────────
PII_ENTITY_SEVERITY: dict[str, str] = {
    # Financial
    "CREDIT_CARD": "Critical",
    "IBAN_CODE": "Critical",
    "US_BANK_NUMBER": "Critical",
    # Identity
    "US_SSN": "Critical",
    "US_PASSPORT": "Critical",
    "US_ITIN": "Critical",
    "US_DRIVER_LICENSE": "High",
    "MEDICAL_LICENSE": "High",
    "PERSON": "High",
    # Contact
    "EMAIL_ADDRESS": "High",
    "PHONE_NUMBER": "High",
    # Location / time
    "LOCATION": "Medium",
    "IP_ADDRESS": "Medium",
    "NRP": "Medium",
    "DATE_TIME": "Low",
    "URL": "Low",
    # Security (custom recognizers)
    "JWT": "Critical",
    "API_KEY": "Critical",
    "PRIVATE_KEY": "Critical",
    "AUTH_TOKEN": "Critical",
    "PASSWORD": "High",
    # Fallback
    "SENSITIVE_PATTERN": "High",
}

# Severity downgrade order for low-confidence findings
_SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Info"]


def _downgrade_severity(severity: str) -> str:
    """Downgrade severity by one level."""
    try:
        idx = _SEVERITY_ORDER.index(severity)
        return _SEVERITY_ORDER[min(idx + 1, len(_SEVERITY_ORDER) - 1)]
    except ValueError:
        return severity


# ── Check if Presidio is available ─────────────────────────────
_PRESIDIO_AVAILABLE = False
try:
    from presidio_analyzer import AnalyzerEngine, RecognizerResult  # noqa: F401
    from presidio_analyzer import Pattern, PatternRecognizer  # noqa: F401
    _PRESIDIO_AVAILABLE = True
except ImportError:
    pass


class PresidioEngine:
    """Lazy-initialized Presidio analyzer with optional GLiNER NER backend.

    The engine is only built on first use, so importing this module
    has zero cost when Presidio is not installed.
    """

    def __init__(self, use_gliner: bool = False):
        self._use_gliner = use_gliner
        self._analyzer: Optional[object] = None  # AnalyzerEngine once built

    @property
    def analyzer(self):
        """Lazily build and return the AnalyzerEngine."""
        if self._analyzer is None:
            self._analyzer = self._build_analyzer()
        return self._analyzer

    def _build_analyzer(self):
        """Create and configure the Presidio AnalyzerEngine."""
        if not _PRESIDIO_AVAILABLE:
            raise RuntimeError(
                "presidio-analyzer is not installed. "
                "Install with: pip install presidio-analyzer>=2.2.35"
            )

        from presidio_analyzer import AnalyzerEngine, Pattern, PatternRecognizer

        analyzer = AnalyzerEngine()

        # ── Custom security recognizers ────────────────────────

        # JWT Token
        jwt_recognizer = PatternRecognizer(
            supported_entity="JWT",
            name="JWT Recognizer",
            patterns=[
                Pattern(
                    name="JWT Token",
                    regex=r"eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+",
                    score=0.9,
                )
            ],
            context=["jwt", "token", "bearer", "authorization"],
        )

        # API Key patterns (AWS, GitHub, Google, generic)
        api_key_recognizer = PatternRecognizer(
            supported_entity="API_KEY",
            name="API Key Recognizer",
            patterns=[
                Pattern(name="AWS Access Key", regex=r"AKIA[0-9A-Z]{16}", score=0.9),
                Pattern(name="GitHub Token", regex=r"gh[pousr]_[A-Za-z0-9_]{36,}", score=0.9),
                Pattern(name="Google API Key", regex=r"AIza[0-9A-Za-z\-_]{35}", score=0.9),
                Pattern(
                    name="Generic API Key Assignment",
                    regex=r"(?i)(api[_\-]?key|apikey|api[_\-]?secret)\s*[=:]\s*['\"]?[A-Za-z0-9_\-]{20,}['\"]?",
                    score=0.6,
                ),
            ],
            context=["api", "key", "secret", "token", "credential"],
        )

        # Private Key blocks
        private_key_recognizer = PatternRecognizer(
            supported_entity="PRIVATE_KEY",
            name="Private Key Recognizer",
            patterns=[
                Pattern(
                    name="Private Key Block",
                    regex=r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
                    score=0.95,
                )
            ],
            context=["private", "key", "pem", "ssh", "certificate"],
        )

        # Auth token assignment patterns
        auth_token_recognizer = PatternRecognizer(
            supported_entity="AUTH_TOKEN",
            name="Auth Token Recognizer",
            patterns=[
                Pattern(
                    name="Bearer Token",
                    regex=r"(?i)bearer\s+[A-Za-z0-9\-_\.]{20,}",
                    score=0.8,
                ),
                Pattern(
                    name="Token Assignment",
                    regex=r"(?i)(auth_token|access_token|refresh_token|session_token)\s*[=:]\s*['\"]?[A-Za-z0-9\-_\.]{10,}['\"]?",
                    score=0.7,
                ),
            ],
            context=["auth", "token", "session", "bearer", "oauth"],
        )

        # Password assignment (value context, not just keyword)
        password_recognizer = PatternRecognizer(
            supported_entity="PASSWORD",
            name="Password Recognizer",
            patterns=[
                Pattern(
                    name="Password Assignment",
                    regex=r"(?i)(password|passwd|pwd)\s*[=:]\s*['\"]?[^\s'\"]{3,}['\"]?",
                    score=0.75,
                ),
            ],
            context=["password", "passwd", "pwd", "credential", "login"],
        )

        for recognizer in [
            jwt_recognizer,
            api_key_recognizer,
            private_key_recognizer,
            auth_token_recognizer,
            password_recognizer,
        ]:
            analyzer.registry.add_recognizer(recognizer)

        # ── Optional GLiNER NER backend ────────────────────────
        if self._use_gliner:
            try:
                try:
                    # Presidio >= 2.2.360
                    from presidio_analyzer.predefined_recognizers.ner.gliner_recognizer import (
                        GLiNERRecognizer,
                    )
                except ImportError:
                    # Older Presidio versions
                    from presidio_analyzer.predefined_recognizers.gliner_recognizer import (
                        GLiNERRecognizer,
                    )

                entities = [
                    "person", "email", "phone number", "credit card number",
                    "social security number", "iban", "date of birth",
                    "address", "passport number", "driver license number",
                    "bank account", "medical record", "insurance number",
                    "username", "password", "api key", "token", "url",
                    "ip address",
                ]
                try:
                    # Presidio >= 2.2.360
                    gliner_recognizer = GLiNERRecognizer(
                        supported_entities=entities,
                        model_name="urchade/gliner_multi_pii-v1",
                        threshold=0.3,
                    )
                except TypeError:
                    # Older Presidio versions
                    gliner_recognizer = GLiNERRecognizer(
                        model_path="urchade/gliner_multi_pii-v1",
                        entities=entities,
                        score_threshold=0.3,
                    )
                analyzer.registry.add_recognizer(gliner_recognizer)
                logger.info("GLiNER NER backend loaded (urchade/gliner_multi_pii-v1)")
            except ImportError:
                raise RuntimeError(
                    "GLiNER extras not installed. "
                    'Install with: pip install "presidio-analyzer[gliner]>=2.2.35"'
                )
            except Exception as e:
                raise RuntimeError(f"Failed to initialize GLiNER: {e}")

        return analyzer

    # ── Text analysis ──────────────────────────────────────────

    _CHUNK_SIZE = 2000
    _CHUNK_OVERLAP = 200

    def analyze_text(
        self,
        text: str,
        entities: list[str] | None = None,
        language: str = "en",
        score_threshold: float = 0.4,
    ) -> list:
        """Analyze text for PII entities.

        Handles large text by chunking into ≤2000-char segments with
        200-char overlap, then deduplicates results at boundaries.

        Returns:
            List of RecognizerResult with entity_type, start, end, score.
        """
        if not text or not text.strip():
            return []

        # Small text — single pass
        if len(text) <= self._CHUNK_SIZE:
            return self.analyzer.analyze(
                text=text,
                entities=entities,
                language=language,
                score_threshold=score_threshold,
            )

        # Large text — chunk with overlap
        all_results = []
        seen: set[tuple[str, int, int]] = set()  # (entity_type, start, end)

        offset = 0
        while offset < len(text):
            end = min(offset + self._CHUNK_SIZE, len(text))
            chunk = text[offset:end]

            chunk_results = self.analyzer.analyze(
                text=chunk,
                entities=entities,
                language=language,
                score_threshold=score_threshold,
            )

            for result in chunk_results:
                # Adjust positions to absolute offsets
                abs_start = result.start + offset
                abs_end = result.end + offset
                key = (result.entity_type, abs_start, abs_end)

                if key not in seen:
                    seen.add(key)
                    # Create new result with absolute positions
                    from presidio_analyzer import RecognizerResult
                    all_results.append(
                        RecognizerResult(
                            entity_type=result.entity_type,
                            start=abs_start,
                            end=abs_end,
                            score=result.score,
                        )
                    )

            # Advance with overlap
            if end >= len(text):
                break
            offset += self._CHUNK_SIZE - self._CHUNK_OVERLAP

        return all_results

    def analyze_text_for_findings(
        self,
        text: str,
        source_label: str = "",
        entities: list[str] | None = None,
        score_threshold: float = 0.4,
    ) -> list[dict]:
        """Analyze text and return finding-ready dicts.

        Returns list of dicts:
        {
            "entity_type": "CREDIT_CARD",
            "text": "4111-1111-1111-1111",
            "score": 0.85,
            "context": "...surrounding text...",
            "source": source_label,
            "severity": "Critical",
        }
        """
        results = self.analyze_text(
            text, entities=entities, score_threshold=score_threshold
        )

        findings: list[dict] = []
        for result in results:
            matched_text = text[result.start:result.end]

            # Extract context (±100 chars around match)
            ctx_start = max(0, result.start - 100)
            ctx_end = min(len(text), result.end + 100)
            context = text[ctx_start:ctx_end]

            # Map severity with confidence-based adjustment
            base_severity = PII_ENTITY_SEVERITY.get(result.entity_type, "Medium")
            if result.score < 0.5:
                severity = _downgrade_severity(_downgrade_severity(base_severity))
            elif result.score < 0.8:
                severity = _downgrade_severity(base_severity)
            else:
                severity = base_severity

            findings.append({
                "entity_type": result.entity_type,
                "text": matched_text,
                "score": round(result.score, 3),
                "context": context,
                "source": source_label,
                "severity": severity,
                "needs_validation": result.score < 0.5,
            })

        return findings

    def analyze_file(
        self,
        file_path: str,
        source_label: str = "",
        score_threshold: float = 0.4,
    ) -> list[dict]:
        """Analyze a file for PII entities.

        For binary or large files (>500KB), extracts strings first.
        Returns finding-ready dicts.
        """
        import subprocess
        from pathlib import Path

        path = Path(file_path)
        if not path.exists() or not path.is_file():
            return []

        file_size = path.stat().st_size
        label = source_label or path.name

        # Large or binary files: use strings extraction
        if file_size > 500 * 1024:
            try:
                result = subprocess.run(
                    ["strings", str(path)],
                    capture_output=True, text=True, timeout=60,
                )
                return self.analyze_text_for_findings(
                    result.stdout, source_label=label, score_threshold=score_threshold
                )
            except (subprocess.TimeoutExpired, FileNotFoundError):
                return []

        # Text files: read directly
        try:
            content = path.read_text(encoding="utf-8", errors="replace")
            return self.analyze_text_for_findings(
                content, source_label=label, score_threshold=score_threshold
            )
        except Exception:
            # Likely binary — fall back to strings
            try:
                import subprocess
                result = subprocess.run(
                    ["strings", str(path)],
                    capture_output=True, text=True, timeout=60,
                )
                return self.analyze_text_for_findings(
                    result.stdout, source_label=label, score_threshold=score_threshold
                )
            except Exception:
                return []


# ── Module-level singleton ─────────────────────────────────────

_engine: PresidioEngine | None = None


def init_engine(use_gliner: bool = False) -> PresidioEngine:
    """Initialize the global Presidio engine singleton.

    Call once from main.py during startup.
    """
    global _engine
    _engine = PresidioEngine(use_gliner=use_gliner)
    return _engine


def get_engine() -> PresidioEngine | None:
    """Get the global Presidio engine, or None if not initialized."""
    return _engine


def is_available() -> bool:
    """Check if presidio-analyzer is importable."""
    return _PRESIDIO_AVAILABLE
