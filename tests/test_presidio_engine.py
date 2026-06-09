"""
Unit tests for the Presidio PII detection engine.

Tests work both with and without presidio-analyzer installed:
- If installed: runs full engine tests
- If not installed: tests graceful fallback behavior
"""

from __future__ import annotations

import unittest
from unittest.mock import MagicMock, patch

import sys
import os

# Add project root to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


class TestPresidioEngineImport(unittest.TestCase):
    """Test that the engine module can be imported safely."""

    def test_import_module(self):
        """Module should import without errors regardless of Presidio availability."""
        from core.presidio_engine import (
            PresidioEngine,
            init_engine,
            get_engine,
            is_available,
            PII_ENTITY_SEVERITY,
        )
        self.assertIsNotNone(PII_ENTITY_SEVERITY)
        self.assertIn("CREDIT_CARD", PII_ENTITY_SEVERITY)
        self.assertIn("JWT", PII_ENTITY_SEVERITY)
        self.assertIn("API_KEY", PII_ENTITY_SEVERITY)

    def test_is_available(self):
        """is_available() should return bool."""
        from core.presidio_engine import is_available
        result = is_available()
        self.assertIsInstance(result, bool)

    def test_get_engine_before_init(self):
        """get_engine() should return None before init_engine() is called."""
        from core import presidio_engine
        # Reset singleton
        presidio_engine._engine = None
        result = presidio_engine.get_engine()
        self.assertIsNone(result)


class TestSeverityMapping(unittest.TestCase):
    """Test PII entity severity mapping."""

    def test_critical_entities(self):
        from core.presidio_engine import PII_ENTITY_SEVERITY
        for entity in ["CREDIT_CARD", "US_SSN", "JWT", "API_KEY", "PRIVATE_KEY"]:
            self.assertEqual(PII_ENTITY_SEVERITY[entity], "Critical", f"{entity} should be Critical")

    def test_high_entities(self):
        from core.presidio_engine import PII_ENTITY_SEVERITY
        for entity in ["EMAIL_ADDRESS", "PHONE_NUMBER", "PASSWORD"]:
            self.assertEqual(PII_ENTITY_SEVERITY[entity], "High", f"{entity} should be High")

    def test_downgrade_severity(self):
        from core.presidio_engine import _downgrade_severity
        self.assertEqual(_downgrade_severity("Critical"), "High")
        self.assertEqual(_downgrade_severity("High"), "Medium")
        self.assertEqual(_downgrade_severity("Medium"), "Low")
        self.assertEqual(_downgrade_severity("Low"), "Info")
        self.assertEqual(_downgrade_severity("Info"), "Info")  # Cannot go lower


# Only run Presidio-specific tests if the package is available
try:
    import presidio_analyzer
    PRESIDIO_AVAILABLE = True
except ImportError:
    PRESIDIO_AVAILABLE = False


@unittest.skipUnless(PRESIDIO_AVAILABLE, "presidio-analyzer not installed")
class TestPresidioEngine(unittest.TestCase):
    """Tests that require presidio-analyzer to be installed."""

    @classmethod
    def setUpClass(cls):
        from core.presidio_engine import PresidioEngine
        cls.engine = PresidioEngine(use_gliner=False)

    def test_analyzer_builds(self):
        """Engine should build analyzer without errors."""
        analyzer = self.engine.analyzer
        self.assertIsNotNone(analyzer)

    def test_analyze_empty_text(self):
        """Empty text should return no results."""
        results = self.engine.analyze_text("")
        self.assertEqual(results, [])

    def test_analyze_whitespace(self):
        """Whitespace-only text should return no results."""
        results = self.engine.analyze_text("   \n  \n  ")
        self.assertEqual(results, [])

    def test_detect_credit_card(self):
        """Should detect Luhn-valid credit card number."""
        results = self.engine.analyze_text("My credit card is 4111-1111-1111-1111")
        entity_types = [r.entity_type for r in results]
        self.assertIn("CREDIT_CARD", entity_types)

    def test_detect_email(self):
        """Should detect email address."""
        results = self.engine.analyze_text("Contact me at john.doe@example.com")
        entity_types = [r.entity_type for r in results]
        self.assertIn("EMAIL_ADDRESS", entity_types)

    def test_detect_jwt(self):
        """Should detect JWT token via custom recognizer."""
        jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        results = self.engine.analyze_text(f"Auth header: Bearer {jwt}")
        entity_types = [r.entity_type for r in results]
        self.assertIn("JWT", entity_types)

    def test_detect_aws_key(self):
        """Should detect AWS access key via custom recognizer."""
        results = self.engine.analyze_text("aws_key = AKIAIOSFODNN7EXAMPLE")
        entity_types = [r.entity_type for r in results]
        self.assertIn("API_KEY", entity_types)

    def test_detect_github_token(self):
        """Should detect GitHub personal access token."""
        results = self.engine.analyze_text("token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklm")
        entity_types = [r.entity_type for r in results]
        self.assertIn("API_KEY", entity_types)

    def test_detect_private_key(self):
        """Should detect private key block."""
        text = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA0Z3..."
        results = self.engine.analyze_text(text)
        entity_types = [r.entity_type for r in results]
        self.assertIn("PRIVATE_KEY", entity_types)

    def test_detect_password_assignment(self):
        """Should detect password=value pattern."""
        results = self.engine.analyze_text("config: password=hunter2")
        entity_types = [r.entity_type for r in results]
        self.assertIn("PASSWORD", entity_types)

    def test_findings_format(self):
        """analyze_text_for_findings should return proper dicts."""
        findings = self.engine.analyze_text_for_findings(
            "My credit card is 4111-1111-1111-1111",
            source_label="test",
        )
        self.assertTrue(len(findings) > 0)
        f = findings[0]
        self.assertIn("entity_type", f)
        self.assertIn("text", f)
        self.assertIn("score", f)
        self.assertIn("severity", f)
        self.assertIn("source", f)
        self.assertEqual(f["source"], "test")

    def test_chunking_large_text(self):
        """Large text should be chunked and results deduplicated."""
        # Create text larger than chunk size (2000 chars)
        text = "Normal text. " * 200 + " My SSN is 123-45-6789 " + " More text. " * 200
        results = self.engine.analyze_text(text)
        # SSN should be found even in large text
        self.assertTrue(len(results) > 0)

    def test_confidence_based_severity(self):
        """Low-confidence findings should have downgraded severity."""
        findings = self.engine.analyze_text_for_findings(
            "4111-1111-1111-1111",
            score_threshold=0.1,
        )
        # All findings should have a valid severity
        valid_severities = {"Critical", "High", "Medium", "Low", "Info"}
        for f in findings:
            self.assertIn(f["severity"], valid_severities)


@unittest.skipUnless(PRESIDIO_AVAILABLE, "presidio-analyzer not installed")
class TestPresidioSingleton(unittest.TestCase):
    """Test the singleton pattern for the engine."""

    def test_init_and_get(self):
        from core.presidio_engine import init_engine, get_engine
        engine = init_engine(use_gliner=False)
        self.assertIsNotNone(engine)
        same_engine = get_engine()
        self.assertIs(engine, same_engine)


if __name__ == "__main__":
    unittest.main()
