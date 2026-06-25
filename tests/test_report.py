"""
Characterization (golden-master) test for core.report.ReportGenerator.generate().

Builds a deterministic Config via the real public API (add_finding / log_command /
add_screenshot), patches the report clock, generates the report, and:
  (a) asserts the key structural headings, a seeded finding, an embedded screenshot,
      and the sibling findings_*.json (with the right total) are present;
  (b) compares the FULL Markdown byte-for-byte against a committed golden fixture
      (tests/fixtures/report_golden.md), bootstrapping the fixture on first run.

The byte-for-byte check is what lets generate() be refactored safely: the produced
report must stay identical before and after the split into private render helpers.
"""
from __future__ import annotations

import datetime as _dt
import json
import os
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.config import Config
from core.report import ReportGenerator

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "report_golden.md"

# Fixed clock so the "Generated:" line and the JSON timestamp are deterministic.
_FROZEN = _dt.datetime(2026, 1, 1, 0, 0, 0)

_DEVICE_INFO = {"model": "iPhone14,5", "ios_version": "16.7.2", "build": "20H115"}


def _build_config(output_dir: Path) -> Config:
    """Deterministic Config: fixed identifiers + a representative finding set that
    exercises confirmed/High (Jira), Info, Medium-with-screenshot, and a Presidio
    PII-style finding (entity table + JSON entity metadata)."""
    c = Config()
    c.bundle_id = "com.example.trashios"
    c.device_id = "00008030TESTUDID0001"
    c.timestamp = "20260101_000000"
    c.output_dir = output_dir
    c.screenshot_dir = output_dir / "screenshots"
    c.report_mode = "client"
    c.is_preinstalled = True
    c.logged_in = True

    kc = "Phase V — Keychain Dump & Data Protection"
    url = "Phase X — URL Scheme / IPC Testing"
    storage = "Phase III — Local Data Storage Analysis"

    c.add_finding(kc, "Token persists in keychain after logout", "High",
                  "Verified via keychain dump. A refresh_token entry survived logout.")
    c.add_finding(kc, "Keychain protection classes acceptable", "Info",
                  "All items use ThisDeviceOnly classes.")
    c.add_finding(url, "Custom URL scheme entry points exposed: myapp", "Medium",
                  "The app handles myapp:// deeplinks; payloads fired: myapp://dashboard.")
    c.add_finding(storage, "PII detected: EMAIL_ADDRESS (3 occurrences)", "High",
                  "Entity type: EMAIL_ADDRESS\nAvg confidence: 0.95\nOccurrences: 3\n\n"
                  "Sample matches:\n  - alice@example.com")

    c.log_command(kc, "frida: SecItemCopyMatching (all security classes)", "2 item(s)", "", 0)
    c.log_command(url, "uiopen myapp://dashboard", "launched", "", 0)

    c.add_screenshot("./screenshots/url_scheme_myapp_privileged.png",
                     "URL scheme: myapp://dashboard (privileged screen)", url)
    return c


class TestReportGolden(unittest.TestCase):
    def _generate(self, output_dir: Path) -> tuple[str, str]:
        c = _build_config(output_dir)
        gen = ReportGenerator(c, _DEVICE_INFO)
        with patch("core.report.datetime") as mock_dt:
            mock_dt.now.return_value = _FROZEN
            report_path = Path(gen.generate())
        return report_path.read_text(encoding="utf-8"), c.bundle_id + "_" + c.timestamp

    def test_structure_and_json_export(self):
        with TemporaryDirectory() as d:
            out = Path(d)
            md, stamp = self._generate(out)

            for heading in ("## Executive Summary", "## Phase Coverage",
                            "## Detailed Findings", "## Commands Executed", "## Risk Summary",
                            "## PII Entities Detected"):
                self.assertIn(heading, md, f"missing heading: {heading}")

            self.assertIn("Token persists in keychain after logout", md)   # seeded finding
            self.assertIn("![", md)                                        # embedded screenshot
            self.assertIn("HIGHLIGHT: CONFIRMED EVIDENCE", md)             # confidence path
            self.assertIn("Jira Draft", md)                                # High/Critical -> Jira

            json_path = out / f"findings_{stamp}.json"
            self.assertTrue(json_path.exists(), "sibling findings JSON not written")
            data = json.loads(json_path.read_text(encoding="utf-8"))
            self.assertEqual(data["total_findings"], 4)
            self.assertEqual(data["timestamp"], "2026-01-01 00:00:00")
            # PII entity metadata threaded into the JSON export
            self.assertTrue(any(f.get("entity_type") == "EMAIL_ADDRESS" for f in data["findings"]))

    def test_markdown_matches_golden(self):
        with TemporaryDirectory() as d:
            md, _ = self._generate(Path(d))
        if not FIXTURE.exists():
            FIXTURE.parent.mkdir(parents=True, exist_ok=True)
            FIXTURE.write_text(md, encoding="utf-8")
            self.skipTest(f"bootstrapped golden fixture at {FIXTURE} — re-run to enforce")
        expected = FIXTURE.read_text(encoding="utf-8")
        self.assertEqual(md, expected,
                         "generated report drifted from tests/fixtures/report_golden.md "
                         "(delete the fixture to re-bootstrap if the change is intentional)")


if __name__ == "__main__":
    unittest.main()
