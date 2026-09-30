"""
Unit tests for the numbered installed-app picker in phases/setup.py.
Prompts and device I/O are mocked.
"""

from __future__ import annotations

import os
import sys
import unittest
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from phases.setup import _select_installed_app, get_app_input

APPS = {
    "com.zeta.app": "Zeta",
    "com.alpha.app": "Alpha",
    "com.mid.app": "mid [beta]",  # brackets must not be parsed as rich markup
}
# Sorted by display name (case-insensitive): 1=Alpha, 2=mid [beta], 3=Zeta


class TestSelectInstalledApp(unittest.TestCase):
    def _pick(self, *answers):
        with patch("phases.setup.Prompt.ask", side_effect=list(answers)):
            return _select_installed_app(APPS)

    def test_number_selects_app_sorted_by_name(self):
        self.assertEqual(self._pick("1"), "com.alpha.app")
        self.assertEqual(self._pick("2"), "com.mid.app")
        self.assertEqual(self._pick("3"), "com.zeta.app")

    def test_manual_bundle_id_accepted_even_when_not_listed(self):
        self.assertEqual(self._pick("com.other.unlisted"), "com.other.unlisted")

    def test_surrounding_whitespace_is_ignored(self):
        self.assertEqual(self._pick("  2  "), "com.mid.app")

    def test_out_of_range_number_reprompts(self):
        self.assertEqual(self._pick("0", "4", "99", "3"), "com.zeta.app")

    def test_invalid_text_reprompts(self):
        self.assertEqual(self._pick("", "not a bundle id", "x", "1"), "com.alpha.app")


class TestGetAppInput(unittest.TestCase):
    def test_installed_apps_use_picker(self):
        device = SimpleNamespace(get_installed_apps=lambda include_system=False: APPS)
        with patch("phases.setup.Confirm.ask", return_value=True), \
                patch("phases.setup.Prompt.ask", side_effect=["1"]):
            self.assertEqual(get_app_input(device), (None, "com.alpha.app", True))

    def test_lists_system_registered_apps_but_hides_apple_builtins(self):
        """TrollStore/jailbreak installs are "System" apps: they must be listed (include_system)
        while com.apple.* built-ins are hidden, so the first entry is the third-party app."""
        calls = []

        def fake_list(include_system=False):
            calls.append(include_system)
            return {"com.apple.mobilemail": "Mail", "com.moveinsync.ets.uat": "MoveInSync UAT"}
        device = SimpleNamespace(get_installed_apps=fake_list)
        with patch("phases.setup.Confirm.ask", return_value=True), \
                patch("phases.setup.Prompt.ask", side_effect=["1"]):
            self.assertEqual(get_app_input(device), (None, "com.moveinsync.ets.uat", True))
        self.assertEqual(calls, [True])

    def test_only_apple_apps_falls_back_to_manual_entry(self):
        device = SimpleNamespace(get_installed_apps=lambda include_system=False: {"com.apple.Maps": "Maps"})
        with patch("phases.setup.Confirm.ask", return_value=True), \
                patch("phases.setup.Prompt.ask", side_effect=["com.apple.Maps"]):
            self.assertEqual(get_app_input(device), (None, "com.apple.Maps", True))

    def test_empty_app_list_falls_back_to_manual_entry(self):
        device = SimpleNamespace(get_installed_apps=lambda include_system=False: {})
        with patch("phases.setup.Confirm.ask", return_value=True), \
                patch("phases.setup.Prompt.ask", side_effect=["bad", "com.manual.app"]):
            self.assertEqual(get_app_input(device), (None, "com.manual.app", True))


if __name__ == "__main__":
    unittest.main()
