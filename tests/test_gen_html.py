"""
Unit tests for the deterministic HTML report generator (core/templates/gen_html.py).

Runs the real script as a subprocess against a tiny fixture — no network, no device.
Covers the happy path (embedding + auto-derived stats/nav + self-validation) and the
hard-failure path (a referenced screenshot missing → exit 1 + visible placeholder).
"""
from __future__ import annotations

import base64
import subprocess
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

GEN_HTML = Path(__file__).resolve().parents[1] / "core" / "templates" / "gen_html.py"

try:
    import markdown  # noqa: F401
    _HAVE_MD = True
except ImportError:
    _HAVE_MD = False

# Smallest valid PNG (1x1, transparent) — avoids depending on Pillow to build a fixture.
_PNG_1x1 = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAAC0lEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg=="
)

_REPORT_MD = """# Test VAPT Report

## A. Executive Summary

One real issue confirmed.

## B. Triage Table

| ID | Finding | Verdict | Real Severity | Action | One-line reason |
|-------|----------------|----------------|----------------|----------------|------------------|
| F-001 | Token in DB | Confirmed | High | Actionable | plaintext token in sqlite |
| F-002 | Verbose logging | Informational | Informational | Non-actionable | debug noise |
| F-003 | JB detect bypass | False Positive | Informational | Non-actionable | scanner artifact |

## C. Findings

### 1. Token in DB

Proof of concept:

```
sqlite3 app.db "SELECT token FROM creds"
```

![DB token evidence](screenshots/eg.png)
"""


@unittest.skipUnless(_HAVE_MD, "the 'markdown' package is required for gen_html.py")
class TestGenHtml(unittest.TestCase):
    def _run(self, with_image: bool):
        """Build a fixture package in a temp dir and run gen_html.py over it."""
        tmp = Path(self._dir.name)
        (tmp / "final_report.md").write_text(_REPORT_MD, encoding="utf-8")
        shots = tmp / "screenshots"
        shots.mkdir(exist_ok=True)
        if with_image:
            (shots / "eg.png").write_bytes(_PNG_1x1)
        proc = subprocess.run([sys.executable, str(GEN_HTML), str(tmp)],
                              capture_output=True, text=True)
        html = (tmp / "final_report.html")
        return proc, (html.read_text(encoding="utf-8") if html.exists() else "")

    def setUp(self):
        self._dir = TemporaryDirectory()
        self.addCleanup(self._dir.cleanup)

    def test_happy_path_embeds_validates_and_derives(self):
        proc, html = self._run(with_image=True)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)

        # screenshot embedded as a data URI; no raw reference survives
        self.assertIn("data:image/", html)
        self.assertNotIn('src="screenshots/', html)
        self.assertNotIn('src="http', html)            # self-contained

        # one fenced block -> exactly one copy button, no leftovers
        self.assertEqual(html.count('class="copy"'), 1)
        self.assertNotIn("@@CODEBLOCK", html)
        self.assertNotIn("```", html)

        # triage table tagged + filter UI present
        self.assertIn('id="triage"', html)
        self.assertIn('class="filters"', html)

        # stats auto-derived from the 3 rows (no hardcoded numbers)
        self.assertIn("<b>3</b><span>Total findings</span>", html)
        self.assertIn("<b>1</b><span>Actionable</span>", html)
        self.assertIn("<b>1</b><span>High</span>", html)

        # nav auto-derived from the <h2> headings
        self.assertIn('<nav class="top">', html)
        self.assertIn("Executive Summary", html)

    def test_missing_screenshot_fails_loudly(self):
        proc, html = self._run(with_image=False)   # eg.png referenced but absent
        self.assertEqual(proc.returncode, 1)        # hard failure, not silent
        self.assertIn("FAIL", proc.stdout)
        self.assertIn("missing screenshot", html)   # visible placeholder still written
        self.assertIn("eg.png", html)


if __name__ == "__main__":
    unittest.main()
