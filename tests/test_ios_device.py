"""
Unit tests for the iOS device bridge (IOSDevice) and runtime bridge (FridaBridge).
All device I/O is mocked — these validate parsing/argv-construction logic only.
"""

from __future__ import annotations

import os
import plistlib
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.ios_device import IOSDevice
from core.frida_bridge import FridaBridge, _strip_objection_noise, RuntimeResult


def _cp(stdout="", stderr="", rc=0, args=None):
    return subprocess.CompletedProcess(args or [], rc, stdout, stderr)


class TestIOSDeviceParsing(unittest.TestCase):
    @patch("core.ios_device.subprocess.run")
    def test_get_devices_parses_udids(self, run_mock):
        run_mock.return_value = _cp(stdout="abc123\ndef456\n")
        self.assertEqual(IOSDevice.get_devices(), ["abc123", "def456"])

    @patch("core.ios_device.subprocess.run")
    def test_get_device_info_maps_keys(self, run_mock):
        def side(argv, **kw):
            key = argv[argv.index("-k") + 1]
            return _cp(stdout={"ProductType": "iPhone10,3",
                               "ProductVersion": "16.5",
                               "BuildVersion": "20F66"}.get(key, ""))
        run_mock.side_effect = side
        info = IOSDevice(udid="u").get_device_info()
        self.assertEqual(info["model"], "iPhone10,3")
        self.assertEqual(info["ios_version"], "16.5")
        self.assertEqual(info["build"], "20F66")

    @patch("core.ios_device.subprocess.run")
    def test_get_installed_apps_parses_csv_and_dash(self, run_mock):
        run_mock.return_value = _cp(stdout=(
            'CFBundleIdentifier, CFBundleVersion, CFBundleDisplayName\n'
            'com.example.app, "1.0", "Example"\n'
            'com.other.app - Other App\n'
            'Total: 2\n'
        ))
        apps = IOSDevice().get_installed_apps()
        self.assertEqual(apps.get("com.example.app"), "Example")
        self.assertEqual(apps.get("com.other.app"), "Other App")
        self.assertNotIn("CFBundleIdentifier", apps)

    def test_get_bundle_id_from_ipa(self):
        with tempfile.TemporaryDirectory() as tmp:
            ipa = Path(tmp) / "app.ipa"
            with zipfile.ZipFile(ipa, "w") as zf:
                zf.writestr("Payload/Example.app/Info.plist",
                            plistlib.dumps({"CFBundleIdentifier": "com.example.app"}))
            self.assertEqual(IOSDevice.get_bundle_id_from_ipa(str(ipa)), "com.example.app")

    @patch("core.ios_device.subprocess.run")
    def test_shell_builds_ssh_argv(self, run_mock):
        captured = {}

        def side(argv, **kw):
            captured["argv"] = argv
            return _cp(stdout="uid=0(root)")
        run_mock.side_effect = side
        dev = IOSDevice(udid="u", ssh_pw="alpine", ssh_device_port=44, local_port=2222)
        dev._sshpass = None  # force key-auth argv shape (deterministic)
        dev._iproxy_proc = SimpleNamespace(poll=lambda: None)  # pretend tunnel already up
        out = dev.shell("id")
        argv = captured["argv"]
        self.assertIn("ssh", argv)
        self.assertIn("root@127.0.0.1", argv)
        self.assertEqual(argv[argv.index("-p") + 1], "2222")
        self.assertEqual(out.stdout, "uid=0(root)")

    @patch("core.ios_device.subprocess.run")
    def test_screencap_accepts_png(self, run_mock):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "shot.png"

            def side(argv, **kw):
                # emulate idevicescreenshot writing a PNG
                Path(argv[-1]).write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 200)
                return _cp(rc=0)
            run_mock.side_effect = side
            ok = IOSDevice(udid="u").screencap(str(out))
            self.assertTrue(ok)
            self.assertTrue(out.exists())

    @patch("core.ios_device.subprocess.run")
    def test_resolve_containers_uses_metadata_grep(self, run_mock):
        # Two shell calls: data-container grep, then bundle grep.
        outputs = [
            "/var/mobile/Containers/Data/Application/UUID-D/.com.apple.mobile_container_manager.metadata.plist\n",
            "/var/containers/Bundle/Application/UUID-B/Example.app/Info.plist\n",
        ]

        def side(argv, **kw):
            return _cp(stdout=outputs.pop(0))
        run_mock.side_effect = side
        dev = IOSDevice(udid="u")
        dev._sshpass = None
        dev._iproxy_proc = SimpleNamespace(poll=lambda: None)  # pretend tunnel already up
        data, bundle, exe = dev.resolve_containers("com.example.app")
        self.assertEqual(data, "/var/mobile/Containers/Data/Application/UUID-D")
        self.assertEqual(bundle, "/var/containers/Bundle/Application/UUID-B/Example.app")
        self.assertEqual(exe, "Example")


class TestFridaBridge(unittest.TestCase):
    def test_strip_objection_noise(self):
        raw = ("com.example.app on (iPhone: 16.5) [usb] # ios keychain dump\n"
               "Using USB device `iPhone`\n"
               "Account   Service   Data\n"
               "user      login     s3cr3t\n"
               "exit\n")
        clean = _strip_objection_noise(raw)
        self.assertIn("user      login     s3cr3t", clean)
        self.assertNotIn("Using USB device", clean)
        self.assertNotIn("[usb] #", clean)

    @patch("core.frida_bridge.subprocess.run")
    def test_objection_run_success_and_error(self, run_mock):
        bridge = FridaBridge(MagicMock(), "com.example.app")
        bridge._objection = "objection"  # pretend installed

        run_mock.return_value = _cp(stdout="user  login  token123", rc=0)
        ok = bridge._objection_run("ios keychain dump")
        self.assertTrue(ok.success)
        self.assertIn("token123", ok.stdout)

        run_mock.return_value = _cp(stdout="Failed to attach to process", rc=0)
        bad = bridge._objection_run("ios keychain dump")
        self.assertFalse(bad.success)

    def test_env_parses_columns(self):
        bridge = FridaBridge(MagicMock(), "com.example.app")
        with patch.object(bridge, "_objection_run", return_value=RuntimeResult(
            "objection", "env",
            "Name           Path\n"
            "BundlePath     /var/containers/Bundle/Application/UUID-B/Example.app\n"
            "DataDirectory  /var/mobile/Containers/Data/Application/UUID-D\n",
            "", True)):
            env = bridge.env()
        self.assertEqual(env.get("BundlePath"), "/var/containers/Bundle/Application/UUID-B/Example.app")
        self.assertEqual(env.get("DataDirectory"), "/var/mobile/Containers/Data/Application/UUID-D")


if __name__ == "__main__":
    unittest.main()
