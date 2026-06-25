<div>

```
,---------. .-------.       ____       .-'''-. .---.  .---..-./`)     ,-----.       .-'''-.  
\          \|  _ _   \    .'  __ `.   / _     \|   |  |_ _|\ .-.')  .'  .-,  '.    / _     \ 
 `--.  ,---'| ( ' )  |   /   '  \  \ (`' )/`--'|   |  ( ' )/ `-' \ / ,-.|  \ _ \  (`' )/`--' 
    |   \   |(_ o _) /   |___|  /  |(_ o _).   |   '-(_{;}_)`-'`"`;  \  '_ /  | :(_ o _).    
    :_ _:   | (_,_).' __    _.-`   | (_,_). '. |      (_,_) .---. |  _`,/ \ _/  | (_,_). '.  
    (_I_)   |  |\ \  |  |.'   _    |.---.  \  :| _ _--.   | |   | : (  '\_/ \   ;.---.  \  : 
   (_(=)_)  |  | \ `'   /|  _( )_  |\    `-'  ||( ' ) |   | |   |  \ `"/  \  ) / \    `-'  | 
    (_I_)   |  |  \    / \ (_ o _) / \       / (_{;}_)|   | |   |   '. \_/``".'   \       /  
    '---'   ''-'   `'-'   '.(_,_).'   `-...-'  '(_,_) '---' '---'     '-----'      `-...-'   
                                                                                             
```

**Automated iOS SAST/DAST Framework**

[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-3776AB?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![Platform](https://img.shields.io/badge/platform-macOS-000000?style=flat-square&logo=apple&logoColor=white)](#)
[![License: MIT](https://img.shields.io/badge/license-MIT-green?style=flat-square)](LICENSE)
[![Release](https://img.shields.io/badge/release-v1.0.0-success?style=flat-square)](CHANGELOG.md)
[![Changelog](https://img.shields.io/badge/changelog-CHANGELOG.md-blue?style=flat-square)](CHANGELOG.md)

---

</div>

## What is TrashiOS?

TrashiOS is a terminal-based automation framework for **static + dynamic security testing of iOS applications** — the iOS counterpart of [TrashDroid](https://github.com/Somchandra17/TrashDroid). Point it at an installed app (or an `.ipa`) on a **USB-connected jailbroken iPhone**, and it orchestrates `libimobiledevice`, **SSH-over-USB**, **Frida/objection**, and `otool`/`class-dump` across a multi-phase assessment — capturing screenshots and generating an **AI-ready Markdown report** with CVSS, OWASP MASVS mapping, remediation, and a command log.

> **TL;DR** — Plug in the phone, run it, feed the report to GPT/Claude for risk ratings and Jira tickets. Same workflow as TrashDroid, but for iOS.

Grounded in the **OWASP MASTG/MASVS** methodology.

---

## How it maps from Android (TrashDroid)

The Android attack surface (Intents/Binder: exported Activities/Services/Receivers/Providers) **does not exist on iOS**. TrashiOS replaces the two platform layers and re-grounds each test:

| TrashDroid (Android) | TrashiOS (iOS) | Notes |
|---|---|---|
| `adb` (`ADB` class) | **`IOSDevice`** — libimobiledevice + SSH-over-USB + Frida | The device layer |
| `drozer` (`Drozer` class) | **`FridaBridge`** — objection + raw Frida | The runtime layer |
| Drozer component testing | **URL scheme / IPC testing** | No exported components; the surface is custom URL schemes / Universal Links |
| Local file system analysis | **Local data storage** (`/var/mobile/Containers/Data/Application/<UUID>`) | Maps directly; same Presidio/regex scan engine |
| Logcat monitoring | **Device log monitoring** (`idevicesyslog`) | Maps directly |
| Manifest analysis | **Static binary & Info.plist analysis** | Info.plist + entitlements + **Mach-O hardening** (PIE/canary/ARC/cryptid) |
| Post-logout access control | **Post-logout access control** | Relaunch via URL scheme instead of `am start` |
| *(none)* | **Keychain dump & data-protection class** | iOS-critical, net-new |

---

## Prerequisites

### Host (macOS)

```bash
# libimobiledevice suite + SSH-over-USB tunnel
brew install libimobiledevice libusbmuxd ideviceinstaller

# runtime instrumentation
pip install -r requirements.txt          # rich + frida-tools + objection

# optional — ML-assisted PII detection (enables --presidio / --ner)
pip install -r requirements-presidio.txt # checksum-validated PII   (--presidio)
pip install -r requirements-ner.txt      # GLiNER NER backend       (--ner)

# non-interactive SSH password auth (or set up SSH keys instead)
brew install sshpass

# Mach-O / entitlement tools
xcode-select --install                    # otool, codesign
brew install class-dump                   # optional: ObjC headers
```

### Target device — jailbroken iPhone X (A11)

1. **Jailbreak** with [palera1n](https://github.com/palera1n/palera1n) (checkm8, iOS 15–16). On A11 you must **disable the device passcode** while jailbroken.
2. **OpenSSH** — palera1n exposes SSH on **port 44**, root password `alpine`.
3. **frida-server** — in Sileo add source `https://build.frida.re`, install *Frida*. Verify from the host with `frida-ps -U`.
4. **uikittools** (for `uiopen`, used by the URL-scheme phase).

---

## Quick Start

```bash
git clone https://github.com/Somchandra17/TrashiOS.git && cd TrashiOS
pip install -r requirements.txt

# plug in the phone, then:
idevice_id -l                  # confirm the UDID shows up
python main.py                 # interactive

# non-interactive against an installed app:
python main.py --auto --device <UDID> --bundle com.example.app

# run specific phases (2=static, 5=keychain, 10=URL schemes):
python main.py --phases 2,5,10 --bundle com.example.app
```

The framework starts the SSH-over-USB tunnel itself (`iproxy <local-port> <ssh-port>`). If your jailbreak uses port 22 (classic checkra1n) instead of 44, pass `--ssh-port 22`.

---

## CLI Reference

| Argument | Description |
|---|---|
| `--auto` | Non-interactive mode with sensible defaults |
| `--device UDID` | Device UDID from `idevice_id -l` |
| `--bundle ID` | Target bundle identifier |
| `--ipa PATH` | Path to `.ipa` (omit if pre-installed) |
| `--phases 2,5,10` | Comma-separated phase numbers (of 13) |
| `--track all\|static\|dynamic` | Run all phases, only SAST, or only DAST (default `all`) |
| `--decrypt` | Authorize FairPlay binary decryption in Phase I (off by default; authorized testing only) |
| `--backup` | Run the slow full device backup in Phase XII (off by default) |
| `--ai-review` | After the run, run the AI review **headless** (streams live activity) over `ai_review/` → `final_report.md` (+ auto-built `final_report.html`); honors `$TRASHIOS_REVIEW_CMD` |
| `--mirror` | Open the QuickTime live view without the y/n prompt (blurs anti-capture apps) |
| `--ssh-port N` | Device SSH port (palera1n=`44`, checkra1n=`22`; default `44`) |
| `--ssh-pass PW` | Device root SSH password (default `alpine`) |
| `--local-port N` | Local iproxy port for SSH (default `2222`) |
| `--report MODE` | `client` (default) or `internal` (includes the AI prompt header) |
| `--presidio` | Enable Presidio PII detection (regex + checksum validators) |
| `--ner` | Enable GLiNER NER backend (ML-based PII detection) |
| `--skip-preflight` | Skip host-tool checks |

---

## Test Phases (13 — full parity)

```
 Phase I    ─── App Binary Decryption                 (SAST)  frida-ios-dump  [--decrypt]
 Phase II   ─── Static Binary & Info.plist Analysis   (SAST)  otool/codesign/class-dump
 Phase III  ─── Local Data Storage Analysis           (DAST)  SSH pull + Presidio scan
 Phase IV   ─── Dump File Verification                (SAST)  sqlite3 + plist deep-dive
 Phase V    ─── Keychain Dump & Data Protection       (DAST)  objection + kSecAttrAccessible
 Phase VI   ─── Backgrounding Snapshot Leakage        (DAST)  Library/Caches/Snapshots
 Phase VII  ─── Pasteboard Leakage                    (DAST)  Frida UIPasteboard monitor
 Phase VIII ─── Device Log Monitoring                 (DAST)  idevicesyslog
 Phase IX   ─── Process Memory Analysis               (DAST)  Frida memory dump + lsof
 Phase X    ─── URL Scheme / IPC Testing              (DAST)  Frida openURL fuzzing
 Phase XI   ─── Post-Logout Access Control            (DAST)  token persistence + deeplinks
 Phase XII  ─── Backup Analysis                       (DAST)  idevicebackup2  [--backup]
 Phase XIII ─── Runtime Hardening Assessment          (DAST)  pinning/JB/anti-debug posture
```

Use `--track static` or `--track dynamic` to run only the SAST or DAST phases, or `--phases 2,5,10` to pick specific ones.

**Phase II** parses Info.plist (ATS / `NSAllowsArbitraryLoads`, URL schemes, file sharing, usage strings), entitlements (`get-task-allow`, keychain-access-groups, app-groups, associated-domains), and Mach-O hardening (PIE, stack canary, ARC, `cryptid`) via `otool`; scans the binary for embedded secrets.

**Phase V** dumps the keychain (objection) and flags weak `kSecAttrAccessible*` classes (`Always`, non-`ThisDeviceOnly`).

> **Phase I** (`--decrypt`) strips FairPlay DRM — off by default; authorized testing only. **Phase XII** (`--backup`) makes a full device backup and is slow (GBs) — off by default.

---

## Output Structure

```
output/<bundle_id>/
├── ai_review/                         # ★ self-contained folder to run `claude` on → final_report.md + .html
│   ├── PROMPT.md · CLAUDE.md          #   triage instructions (false-positive-first, VAPT tickets)
│   ├── findings.json · report.md      #   findings + human report
│   ├── screenshots/ (+ index.json)    #   PNG evidence (Claude VIEWS these — no PDF stripping)
│   ├── logs/                          #   full command log, syslog, keychain dump, grep hits
│   ├── run_review.sh                  #   one command → final_report.md (then auto-runs gen_html.py)
│   └── gen_html.py                    #   final_report.md → self-contained final_report.html (fixed B&W theme)
├── iOS_DAST_Report_<bundle>_<ts>.md   # human report
├── findings_<bundle>_<ts>.json        # machine-readable findings
├── screenshots/                       # device screenshots (Frida-rendered; idevicescreenshot when a DDI is mountable)
├── bundle/                            # pulled .app (Info.plist, binary, class-dump.txt)
├── bundle_decrypted/                  # decrypted .ipa/.app (Phase I, if --decrypt)
├── data_container/                    # pulled Data container (Documents, Library, ...)
├── keychain/                          # keychain.json / dump / values
├── snapshots/                         # backgrounding snapshots (Phase VI)
├── memory/                            # process memory dump (Phase IX)
├── backup/                            # device backup (Phase XII, if --backup)
└── syslog/                            # captured device logs
```

---

## AI Triage (false-positive filtering)

Automated tools over-report. Instead of converting the report to PDF (which strips the screenshots and raw logs an AI needs), every run drops a **self-contained `ai_review/` folder** an AI works on directly — it reads `findings.json` + `report.md` + the raw `logs/`, **views every screenshot as an image**, and writes a triaged `final_report.md` **plus a self-contained `final_report.html`** — built deterministically by the bundled [`gen_html.py`](docs/HTML_REPORT.md) (every screenshot embedded, copy buttons, a filterable triage table; the AI spends ~0 tokens on design) — as **iOS VAPT tickets**, aggressively filtering false positives (regex keyword hits, third-party-SDK artifacts, jailbreak-only items, OAuth redirect schemes, etc.).

At the end of an interactive run you choose how to triage:

| Choice | What it does |
|---|---|
| **1) Interactive `claude` session** (default) | Hands you a live session in the package — it can **ask you to connect the iPhone / log the app out and verify findings live** (decode DB & keychain values, re-fire URL schemes logged-out, grep memory), then regenerate the report with confirmed PoCs + embedded evidence. The device stays connected throughout. |
| **2) Headless `claude`** (`--ai-review`) | Unattended; **streams live activity** (each tool it runs + a cost/duration line) and writes `final_report.md`. No live Q&A. |
| **3) Custom / cloud command** | Runs `$TRASHIOS_REVIEW_CMD` instead of `claude` — point it at any agentic backend (OpenRouter via aider, an Ollama wrapper, …). |
| **4) Just show me the prompt** | Prints the prompt + paths to paste into any AI (claude.ai, ChatGPT, …). |

```bash
# unattended: headless review at the end of the run
python main.py --bundle com.example.app --ai-review

# any agentic backend (OpenRouter / Ollama / aider …):  {prompt_file}=PROMPT.md path, {prompt}=inlined text
export TRASHIOS_REVIEW_CMD='aider --message-file {prompt_file} --yes'
python main.py --bundle com.example.app --ai-review

# or run it yourself, any time:
cd output/com.example.app/ai_review && claude            # interactive — verifies on-device, can ask you questions
cd output/com.example.app/ai_review && ./run_review.sh   # headless → final_report.md + .html (honors $TRASHIOS_REVIEW_CMD)
```

> **Agentic vs. plain chat:** viewing screenshots and running live on-device verification needs a tool with filesystem/image access (Claude Code, aider). A plain cloud chat can still triage the text from `report.md` + `findings.json`, just without image viewing or a live PoC.

The triage prompt lives in `ai_review/PROMPT.md`; the full VAPT reporting standard (ticket field order, CVSS calibration, CWE root-cause selection) is embedded directly in it — no external skill or plugin is required.

---

## Status

**v1.0.0 — stable.** All 13 phases are implemented and validated end-to-end on a jailbroken iPhone X (A11, iOS 16.7.5), compatible with **Frida 17** (the ObjC bridge is loaded from `frida-tools` and the agents use the Frida 17 APIs). Possible future refinements: Universal Links / app-extension (`.appex`) testing in Phase X, a `keychain-dumper` SSH fallback for managed/anti-Frida apps in Phase V, bounding the Frida session teardown so heavy MAM/anti-instrumentation can't stall the memory phase, and a Jira/VAPT ticket exporter.

---

## Disclaimer

> **For authorized security testing only.** Use exclusively against applications you have explicit written permission to test. Decrypting App Store binaries (Milestone 2) strips DRM and must only be done on apps you are authorized to assess. Unauthorized testing is illegal and unethical.

---

<div align="center">

**Built by [0xs0m](https://somm.tf)**

</div>
