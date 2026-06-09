# Changelog

All notable changes to TrashiOS are documented here.

## [0.2.1] — Polish + Frida 17 compatibility

### Fixed — Frida 17 broke every raw ObjC/Memory agent (root cause of "no screenshots", "memory dump empty", URLs not firing)
- **ObjC bridge:** Frida 17 removed the built-in `ObjC` global from raw scripts. Now prepend the
  compiled bridge from `frida_tools/bridges/objc.js` to every ObjC agent (`_with_objc`), restoring
  `ObjC.classes` on Frida 16 and 17. Fixes `open_url`/`open_urls`, `pasteboard_monitor`, `screenshot`.
- **API migrations in agents:** `Module.findExportByName` → `Module.findGlobalExportByName`;
  `Memory.readByteArray(ptr,n)` → `ptr.readByteArray(n)` (fixed the **memory dump** too);
  NativeFunction `'bool'` arg type → `'int'` (Frida 17 rejects `'bool'` — "expected an integer").
- **Screenshots now actually work.** `idevicescreenshot` needs a Developer Disk Image that isn't
  available for every iOS version (e.g. 16.7); `ScreenshotManager` now falls back to a
  **Frida-rendered screenshot** of the running app (UIKit render → PNG), which needs no DDI.
  `IOSDevice` also auto-mounts a matching Xcode DDI when one exists (`ideviceimagemounter mount`).
  Verified live: crisp 120 KB PNG; 25 MB memory dump.
- **Report hygiene:** scrub NUL/control bytes in `add_finding`/`log_command` so binary content pulled
  from the device (memory/strings) can't leak into the Markdown/JSON and turn the report into a
  "binary" file (which broke tooling/renderers).

### Verified end-to-end
Full 13-phase `--auto` run against `com.moveinsync.ets.uat` on the iPhone X (ssh/frida/root all ok):
**48 findings, 28 screenshots captured AND embedded** in the report (`![...](./screenshots/...)`),
each a real full-resolution (1125×2436) capture of the app.

### Polish
- **Memory phase (IX):** `dump_memory` now reports the real failure reason (attach refused / script
  destroyed by anti-tamper/MAM / no readable ranges) instead of a generic "empty", with an
  `exports_sync`→`exports` fallback and per-range resilience; the phase prints the reason.
- **URL phase (X):** Frida firing batched into a **single attach** for all URLs (`FridaBridge.open_urls`)
  — much faster and more reliable than per-URL attach; screenshots trimmed to base/privileged labels.
- **Live view:** `start_mirror` now shows a clear panel — the blurry first image is the Mac's webcam;
  switch the QuickTime source to the iPhone and set Quality to Maximum. Screenshots are full-res regardless.
- **Clean output:** suppressed the `pkg_resources is deprecated` / DeprecationWarning startup noise.
- **Snapshot phase (VI):** dropped the bogus auto-mode `SIGSTOP` (it doesn't trigger SpringBoard's snapshot);
  auto-mode now just pulls existing snapshots and notes that the real test is interactive.

## [0.2.0] — Milestone 2 (full parity, 13 phases)

Added the 7 remaining phases and renumbered into a coherent assessment order
(decrypt → static → storage → dump-verify → keychain → snapshot → pasteboard →
syslog → memory → URL/IPC → post-logout → backup → hardening).

### Added — phases
- **I — App Binary Decryption** (`frida-ios-dump` over the existing iproxy tunnel; gated by `--decrypt`).
- **IV — Dump File Verification** (per-table SQLite via stdlib `sqlite3`, binary-plist key/value extraction, SQLCipher/Realm detection).
- **VI — Backgrounding Snapshot Leakage** (`Library/Caches/Snapshots` pull + evidence).
- **VII — Pasteboard Leakage** (Frida `UIPasteboard.generalPasteboard` monitor).
- **IX — Process Memory Analysis** (Frida rw- range dump + Presidio scan; `lsof`/`netstat` for FDs/connections — the `/proc` replacement).
- **XII — Backup Analysis** (`idevicebackup2` + `Manifest.db` AppDomain parse + `NSURLIsExcludedFromBackupKey` check; gated by `--backup`).
- **XIII — Runtime Hardening Assessment** (SSL-pinning / jailbreak-detection / anti-debug posture via objection bypass observation).

### Added — runtime / CLI
- `FridaBridge.open_url` (fire URL schemes via `UIApplication openURL:` — replaces the `uiopen` dependency), `dump_memory`, and a raw-Frida `pasteboard_monitor`.
- CLI: `--track {all,static,dynamic}` (SAST/DAST filter), `--decrypt`, `--backup`.
- `start_mirror()` now opens a QuickTime "New Movie Recording" window (live device view); screenshots in Phases VI/X/XI are captured regardless of `uiopen`.

### Fixed
- `ideviceinstaller 1.2.0` CLI change (`list`/`install` subcommands; legacy `-l`/`-i` fallback).
- Keychain phase distinguishes a genuine empty keychain from an objection attach failure (e.g. Intune-MAM apps).

## [0.1.0] — MVP (iOS port of TrashDroid)

First release. An iOS SAST/DAST framework driven from macOS against a
USB-connected jailbroken iPhone, ported from the Android TrashDroid engine.

### Added — platform layers
- **`core/ios_device.py` (`IOSDevice`)** — the `ADB` replacement. Composes
  libimobiledevice CLIs + SSH-over-USB (`iproxy <local> <device:44>`) + Frida,
  with a capability ladder (`afc`/`ssh`/`frida`/`root`). Mirrors the ADB method
  surface (`shell`, `pull`/`pull_as_root`, `screencap`, `get_pid`, `launch_app`,
  `force_stop`, `list_dir`, `get_app_data_path`, …) plus iOS container resolution.
- **`core/frida_bridge.py` (`FridaBridge`)** — the `Drozer` replacement. Hybrid:
  objection (non-interactive) for keychain/plist/sqlite/pasteboard/SSL-pinning,
  raw Frida bindings for spawn/memory/custom hooks. Returns `RuntimeResult`
  (same shape as `DrozerResult`).

### Added — phases (MVP)
- **I — Static Binary & Info.plist Analysis** (SAST): ATS, URL schemes, file
  sharing, usage strings, entitlements (`get-task-allow`, keychain/app groups,
  associated domains), Mach-O hardening (PIE/canary/ARC/cryptid via `otool`),
  class-dump, embedded-secret scan.
- **II — Local Data Storage Analysis**: pulls the Data container, scans every
  store with the reused Presidio/regex engine.
- **III — Keychain Dump & Data Protection**: objection keychain dump +
  `kSecAttrAccessible*` weakness assessment.
- **IV — Device Log Monitoring**: `idevicesyslog` capture + secret/HTTP/SQL/exception scan.
- **V — URL Scheme / IPC Testing**: enumerate `CFBundleURLTypes`, fuzz `openURL`, screenshot.
- **VI — Post-Logout Access Control**: token persistence (keychain/plist) + deeplink replay after logout.

### Reused from TrashDroid (platform-agnostic)
- `Config` findings model, the CVSS/Markdown/JSON `ReportGenerator` (re-keyed to
  iOS findings + OWASP MASVS), the Presidio/GLiNER PII engines, the Presidio/regex
  scan helpers, the screenshot manager, and the idempotent runtime-cleanup manager.

### Notes
- palera1n SSH defaults: device port **44**, root password `alpine`
  (override with `--ssh-port` / `--ssh-pass`).
- `idevicescreenshot` output is normalized TIFF→PNG via `sips`.
- Tests: `tests/test_ios_device.py` (IOSDevice/FridaBridge parsing, mocked subprocess)
  and `tests/test_runtime_hardening.py` (PII init, syslog lifecycle, cleanup idempotency).

### Roadmap (Milestone 2)
- IPA decryption (`frida-ios-dump`), deep dump verification, process memory
  analysis (fridump), backup analysis (`idevicebackup2`), backgrounding-snapshot
  leakage, pasteboard leakage, runtime-hardening (SSL-pinning / jailbreak / anti-debug) assessment.
