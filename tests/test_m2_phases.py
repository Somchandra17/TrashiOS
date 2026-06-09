"""
Unit tests for Milestone-2 phase pure-logic (no device needed):
backup Manifest.db parsing, dump_verify plist flattening + sqlite detection,
and decrypt tool discovery.
"""

from __future__ import annotations

import os
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from phases.dump_verify import _flatten, _is_sqlite
from phases.backup import _app_domain_files, _find_manifest
from phases import decrypt


class TestDumpVerifyHelpers(unittest.TestCase):
    def test_flatten_nested(self):
        flat = _flatten({"a": {"b": 1, "c": [10, 20]}, "d": "x"})
        self.assertEqual(flat["a.b"], 1)
        self.assertEqual(flat["a.c[0]"], 10)
        self.assertEqual(flat["a.c[1]"], 20)
        self.assertEqual(flat["d"], "x")

    def test_is_sqlite_detects_header(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "x.db"
            db.write_bytes(b"SQLite format 3\x00" + b"\x00" * 32)
            self.assertTrue(_is_sqlite(db))
            notdb = Path(tmp) / "y.realm"
            notdb.write_bytes(b"REALMnotsqlite")
            self.assertFalse(_is_sqlite(notdb))


class TestBackupManifestParse(unittest.TestCase):
    def test_app_domain_files_from_manifest(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manifest = root / "Manifest.db"
            con = sqlite3.connect(manifest)
            con.execute("CREATE TABLE Files (fileID TEXT, domain TEXT, relativePath TEXT, flags INTEGER)")
            con.execute("INSERT INTO Files VALUES (?,?,?,?)",
                        ("abcd1234ef", "AppDomain-com.example.app", "Documents/secrets.plist", 1))
            con.execute("INSERT INTO Files VALUES (?,?,?,?)",
                        ("zzzz", "AppDomain-com.other.app", "Documents/other.txt", 1))
            con.commit(); con.close()

            found, froot = _find_manifest(root)
            self.assertEqual(found, manifest)
            files = _app_domain_files(manifest, "com.example.app", froot)
            self.assertEqual(len(files), 1)
            rel, disk = files[0]
            self.assertEqual(rel, "Documents/secrets.plist")
            self.assertTrue(disk.endswith(os.path.join("ab", "abcd1234ef")))


class TestDecryptToolDiscovery(unittest.TestCase):
    def test_env_var_points_to_dump_py(self):
        with tempfile.TemporaryDirectory() as tmp:
            dump = Path(tmp) / "dump.py"
            dump.write_text("# stub")
            with patch.dict(os.environ, {"FRIDA_IOS_DUMP": str(dump)}):
                runner = decrypt._find_dump_tool()
            self.assertEqual(runner, ["python3", str(dump)])

    def test_none_when_absent(self):
        with patch.dict(os.environ, {}, clear=True), \
             patch("phases.decrypt.shutil.which", return_value=None):
            self.assertIsNone(decrypt._find_dump_tool())


if __name__ == "__main__":
    unittest.main()
