<div align="center">

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

**Automated iOS SAST/DAST framework**

[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-3776AB?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![Platform](https://img.shields.io/badge/platform-macOS-000000?style=flat-square&logo=apple&logoColor=white)](#)
[![License: MIT](https://img.shields.io/badge/license-MIT-green?style=flat-square)](LICENSE)
[![Release](https://img.shields.io/badge/release-v1.0.0-success?style=flat-square)](CHANGELOG.md)
[![Changelog](https://img.shields.io/badge/changelog-CHANGELOG.md-blue?style=flat-square)](CHANGELOG.md)

---

</div>

TrashiOS runs a static and dynamic security assessment of an iOS app from your terminal. You plug a jailbroken iPhone into your Mac, point the tool at an installed app (or an `.ipa`), and it works through thirteen phases — pulling the app's files, dumping the keychain, watching the pasteboard and the system log, firing custom URL schemes, checking the binary's hardening — and writes up what it found, with screenshots as evidence.

It's the iOS side of [TrashDroid](https://github.com/Somchandra17/TrashDroid). Same idea, same report format, different platform underneath. The methodology follows OWASP MASTG/MASVS.

One honest caveat before you start: almost everything here needs root on the device, so you need a jailbroken phone. Without a jailbreak you only get the handful of checks that work over plain `libimobiledevice`. And this is for apps you're authorized to test — see the [disclaimer](#disclaimer).

## Contents

- [How it relates to TrashDroid](#how-it-relates-to-trashdroid)
- [What you need](#what-you-need)
- [Install](#install)
- [Quick start](#quick-start)
- [CLI reference](#cli-reference)
- [The phases](#the-phases)
- [Where the output goes](#where-the-output-goes)
- [Reading the report](#reading-the-report)
- [Running against a vphone-cli virtual iPhone](#running-against-a-vphone-cli-virtual-iphone)
- [Troubleshooting](#troubleshooting)
- [Status and limits](#status-and-limits)
- [Disclaimer](#disclaimer)

## How it relates to TrashDroid

If you've used TrashDroid, most of this will feel familiar — the findings model, the CVSS/Markdown report, and the PII scan engine are the same code. What changes is the two platform layers underneath, because iOS doesn't have Android's attack surface.

There are no exported Activities, Services, Receivers, or Providers on iOS, so there's nothing for a drozer-style component sweep to enumerate. The `ADB` class becomes `IOSDevice`, which composes three transports: the `libimobiledevice` CLIs, an SSH-over-USB shell (tunnelled with `iproxy`), and Frida. The `Drozer` class becomes `FridaBridge`, which drives objection and raw Frida. The Android component tests are replaced by iOS-native ones: custom URL scheme / IPC testing, local data-storage analysis under the app's Data container, `idevicesyslog` monitoring, Info.plist + entitlements + Mach-O hardening analysis, and a keychain dump with a data-protection-class review that has no Android equivalent.

## What you need

### On your Mac

```bash
# libimobiledevice suite + the SSH-over-USB tunnel (iproxy)
brew install libimobiledevice libusbmuxd ideviceinstaller

# runtime instrumentation: rich + frida-tools + objection, plus the HTML report deps
pip install -r requirements.txt

# non-interactive SSH password auth (or set up SSH keys instead)
brew install sshpass

# Mach-O / entitlement tools
xcode-select --install       # otool, codesign
brew install class-dump      # optional: Objective-C headers
```

Two PII backends are optional. Install them only if you want the extra detection during the storage/memory/log scans; without them those phases fall back to the regex scanner.

```bash
pip install -r requirements-presidio.txt   # Presidio: regex + checksum validators   (--presidio)
pip install -r requirements-ner.txt        # GLiNER NER model, ~560 MB on first run   (--ner)
```

### On the iPhone

You need a jailbroken, checkm8-class device. It's been validated end to end on an iPhone X (A11, iOS 16.7.5), but any checkm8 device on a supported iOS should work.

1. **Jailbreak** with [palera1n](https://github.com/palera1n/palera1n) (checkm8, iOS 15–16). On an A11 device you have to **disable the passcode** while jailbroken — that's a checkm8 requirement, not a tool one.
2. **OpenSSH** — palera1n exposes SSH on device port **44**, root password `alpine`.
3. **frida-server** — in Sileo add the source `https://build.frida.re`, install *Frida*, then confirm it from your Mac with `frida-ps -U`.
4. **uikittools** — provides `uiopen`, which the URL-scheme phase uses to cold-launch schemes.

Missing SSH or Frida won't stop a run; the preflight prints what's reachable and the phases that need a transport quietly skip when it isn't there.

## Install

```bash
git clone https://github.com/Somchandra17/TrashiOS.git && cd TrashiOS
pip install -r requirements.txt
```

## Quick start

Plug in the phone, make sure it shows up, then run:

```bash
idevice_id -l                  # confirm the UDID appears
python main.py                 # interactive: pick the device and the app
```

In interactive mode, if the target app is already installed, you get a numbered list of the installed apps — enter a number, or type a bundle id by hand if it isn't listed. Apple's own `com.apple.*` built-ins are hidden from the list to cut the noise, but you can still type one in. Apps installed through TrollStore or the jailbreak register as "System" apps, so they show up in the list too.

For an unattended run against an installed app:

```bash
# all 13 phases, no prompts
python main.py --auto --device <UDID> --bundle com.example.app

# just a few phases (2 = static, 5 = keychain, 10 = URL schemes)
python main.py --phases 2,5,10 --bundle com.example.app
```

TrashiOS starts the SSH-over-USB tunnel itself (`iproxy <local-port> <device-port>`) and probes the device SSH port for you: it tries palera1n's port 44 first, then vphone-cli's dropbear on 22222, both with the `alpine` password, and keeps whichever answers. If you're on a classic checkra1n jailbreak that uses port 22, pass `--ssh-port 22` — the tool tries the port you name first. If the local tunnel port is already taken, it grabs a free one instead of routing you through a stale listener.

## CLI reference

| Flag | What it does |
|---|---|
| `--auto` | Non-interactive; sensible defaults for every prompt |
| `--device UDID` | Device UDID from `idevice_id -l` (skips the picker) |
| `--bundle ID` | Target bundle identifier (skips the picker) |
| `--ipa PATH` | Path to an `.ipa` to install; omit if the app is already on the device |
| `--phases 2,5,10` | Comma-separated phase numbers to run (default: all) |
| `--track {all,static,dynamic}` | Run every phase, only the SAST phases, or only the DAST phases (default: `all`) |
| `--decrypt` | Allow FairPlay binary decryption in Phase I — off by default; authorized testing only |
| `--backup` | Run the slow full device backup in Phase XII — off by default |
| `--ai-review` | After the run, drive `claude` headless over `ai_review/` to write `final_report.md` (+ `final_report.html`); honors `$TRASHIOS_REVIEW_CMD` |
| `--mirror` | Open the QuickTime live view without asking (see the warning below) |
| `--ssh-port N` | Device SSH port to try first (palera1n `44`, classic checkra1n `22`; default `44`) |
| `--ssh-pass PW` | Device root SSH password (default `alpine`) |
| `--local-port N` | Local `iproxy` port for the SSH tunnel (default `2222`) |
| `--report {client,internal}` | Report detail; `internal` adds the AI-prompt header (default `client`) |
| `--screenshot-delay S` | Seconds to wait before a screenshot (default `4.5`) |
| `--presidio` | Enable Presidio PII detection (regex + checksum validators) |
| `--ner` | Enable the GLiNER NER backend (implies `--presidio`) |
| `--skip-preflight` | Skip the host-tool availability checks |
| `--version` | Print the version and exit |

A note on `--mirror`: mirroring sets `UIScreen.isCaptured`, so apps with anti-screen-capture (Intune-MAM and similar) blur their UI while it's on — and the screenshots captured during the run get blurred with it. In interactive mode you're asked before it opens; leave it off if you want crisp evidence. Screenshots don't need it either way.

## The phases

```
 Phase I    ─── App Binary Decryption                 (SAST)  frida-ios-dump   [--decrypt]
 Phase II   ─── Static Binary & Info.plist Analysis   (SAST)  otool/codesign/class-dump
 Phase III  ─── Local Data Storage Analysis           (DAST)  SSH pull + PII scan
 Phase IV   ─── Dump File Verification                (SAST)  sqlite3 + plist deep-dive
 Phase V    ─── Keychain Dump & Data Protection       (DAST)  Frida + kSecAttrAccessible
 Phase VI   ─── Backgrounding Snapshot Leakage        (DAST)  Library/Caches/Snapshots
 Phase VII  ─── Pasteboard Leakage                    (DAST)  Frida UIPasteboard monitor
 Phase VIII ─── Device Log Monitoring                 (DAST)  idevicesyslog
 Phase IX   ─── Process Memory Analysis               (DAST)  Frida memory dump + lsof
 Phase X    ─── URL Scheme / IPC Testing              (DAST)  Frida/uiopen scheme firing
 Phase XI   ─── Post-Logout Access Control            (DAST)  token persistence + deeplinks
 Phase XII  ─── Backup Analysis                       (DAST)  idevicebackup2   [--backup]
 Phase XIII ─── Runtime Hardening Assessment          (DAST)  pinning/JB/anti-debug posture
```

`--track static` runs only the SAST phases, `--track dynamic` only the DAST ones, and `--phases 2,5,10` picks specific numbers.

A couple worth calling out:

- **Phase II** reads Info.plist (ATS and `NSAllowsArbitraryLoads`, declared URL schemes, file sharing, usage strings), the entitlements (`get-task-allow`, keychain-access-groups, app-groups, associated-domains), and the Mach-O hardening flags (PIE, stack canary, ARC, `cryptid`) via `otool`, and scans the binary for embedded secrets.
- **Phase V** dumps the keychain and flags weak `kSecAttrAccessible*` classes — the `Always` accessibility and anything that isn't `ThisDeviceOnly`.

Two phases are off by default because they're expensive or touch DRM. **Phase I** (`--decrypt`) strips FairPlay protection, so only run it on apps you're cleared to decrypt. **Phase XII** (`--backup`) makes a full device backup, which can be gigabytes and slow.

## Where the output goes

Everything from a run lands under `output/<bundle_id>/`:

```
output/<bundle_id>/
├── ai_review/                         # self-contained package to run an AI over → final_report.md + .html
│   ├── PROMPT.md · CLAUDE.md          #   triage instructions (false-positives first, VAPT tickets)
│   ├── findings.json · report.md      #   findings + the human report
│   ├── screenshots/ (+ index.json)    #   PNG evidence the AI views directly
│   ├── logs/                          #   full command log, syslog, keychain dump, grep hits
│   ├── run_review.sh                  #   one command → final_report.md (then runs gen_html.py)
│   └── gen_html.py                    #   final_report.md → self-contained final_report.html
├── iOS_DAST_Report_<bundle>_<ts>.md   # the human report
├── findings_<bundle>_<ts>.json        # the same findings, machine-readable
├── screenshots/                       # device screenshots (Frida-rendered, or idevicescreenshot when a DDI is mountable)
├── bundle/                            # the pulled .app (Info.plist, binary, class-dump.txt)
├── bundle_decrypted/                  # decrypted .app (Phase I, with --decrypt)
├── data_container/                    # the pulled Data container (Documents, Library, ...)
├── keychain/                          # keychain dump + parsed values
├── snapshots/                         # backgrounding snapshots (Phase VI)
├── memory/                            # process memory dump (Phase IX)
├── backup/                            # device backup (Phase XII, with --backup)
└── syslog/                            # captured device logs
```

The Markdown report (`iOS_DAST_Report_*.md`) is the thing to read first: an executive summary, phase coverage, the PII hits, a write-up per finding with contextual CVSS and remediation, the full command log, and a risk table. The JSON sibling carries the same findings for tooling.

## Reading the report

Automated tools over-report, so the raw report is a starting point, not a verdict. Rather than flatten it to a PDF — which strips the screenshots and raw logs an AI actually needs — every run drops a self-contained `ai_review/` folder. An agentic AI works on that folder directly: it reads `findings.json`, `report.md`, and the raw `logs/`, views each screenshot as an image, filters the false positives (regex keyword hits, third-party-SDK artifacts, jailbreak-only items, OAuth redirect schemes, and so on), and writes a triaged `final_report.md` as iOS VAPT tickets. It then runs the bundled [`gen_html.py`](docs/HTML_REPORT.md) to turn that into a single self-contained `final_report.html` — every screenshot embedded, copy buttons on code blocks, a filterable triage table. The HTML theme is fixed, so the AI spends no effort on design and the report looks the same every run.

At the end of an interactive run you choose how to triage:

1. **Interactive `claude` session** (default) — hands you a live session in the package. It can ask you to keep the iPhone connected, log the app out, and verify findings live (decode DB and keychain values, re-fire URL schemes while logged out, grep memory), then regenerate the report with confirmed PoCs. The device stays connected throughout.
2. **Headless `claude`** (`--ai-review`) — unattended; streams each tool it runs plus a cost/duration line, and writes `final_report.md`. No live back-and-forth.
3. **Custom / cloud command** — runs `$TRASHIOS_REVIEW_CMD` instead of `claude`, so you can point it at any agentic backend.
4. **Just show me the prompt** — prints the prompt and the paths to paste into any AI.

```bash
# unattended review at the end of a run
python main.py --bundle com.example.app --ai-review

# point it at any agentic backend ({prompt_file} = PROMPT.md path, {prompt} = inlined text)
export TRASHIOS_REVIEW_CMD='aider --message-file {prompt_file} --yes'
python main.py --bundle com.example.app --ai-review

# or run it yourself, later
cd output/com.example.app/ai_review && claude          # interactive, can verify on-device
cd output/com.example.app/ai_review && ./run_review.sh # headless → final_report.md + .html
```

Viewing screenshots and running live on-device verification needs a tool with filesystem and image access (Claude Code, aider). A plain cloud chat can still triage the text from `report.md` and `findings.json`, just without image viewing or a live PoC.

The triage prompt lives in `ai_review/PROMPT.md`, and the full VAPT reporting standard (ticket field order, CVSS calibration, CWE selection) is written into it — no external skill or plugin required.

## Running against a vphone-cli virtual iPhone

You don't strictly need physical hardware. If you run a jailbroken virtual iPhone through vphone-cli, TrashiOS reaches it the same way it reaches a cabled phone — the VM is exposed on the macOS side, so `idevice_id` and `iproxy` see it without extra setup.

The one difference is the SSH endpoint: vphone-cli's dropbear listens on device port **22222** (root, password `alpine`). You don't have to configure anything for that — the SSH probe already tries 22222 after 44 and keeps whichever answers. Dropbear also starts non-interactive sessions with a bare `PATH`, so basic tools like `id`, `ls`, and `cat` wouldn't be found; TrashiOS prepends the jailbreak tool directories (`/iosbinpack64/...` and `/var/jb/...`) to every remote command so they resolve.

## Troubleshooting

**Device not reachable via libimobiledevice.** This is the only hard stop. Make sure the phone is plugged in, unlocked, and that you accepted "Trust This Computer." Check with `idevice_id -l && ideviceinfo -k ProductType`.

**SSH-over-USB not available.** The filesystem, keychain, and runtime phases need it. Confirm the passcode is disabled (the A11 checkm8 requirement), that `sshpass` is installed for non-interactive login, and that the SSH port is right. You can test the tunnel by hand: `iproxy 2222 44` then `ssh root@127.0.0.1 -p 2222`.

**frida-server not reachable.** The keychain, memory, and runtime phases need it. Install Frida via Sileo (source `https://build.frida.re`) and verify with `frida-ps -U`.

**Screenshots look blurry.** That's the `--mirror` / QuickTime live view triggering an app's anti-screen-capture blur. Run without mirroring; the report screenshots come from Frida regardless.

**Screenshots fall back to Frida.** `idevicescreenshot` needs a Developer Disk Image for the device's iOS version. TrashiOS auto-mounts a matching one from Xcode when it can; when there's no match (common on point releases like 16.7), it renders the screenshot through Frida instead, which needs no DDI.

## Status and limits

Version 1.0.0 — all thirteen phases are implemented and validated end to end on a jailbroken iPhone X (A11, iOS 16.7.5), and it works with Frida 17 (the ObjC bridge is loaded from `frida-tools` and the agents use the Frida 17 APIs).

Known limits and likely next steps: Universal Links and app-extension (`.appex`) testing in Phase X, a `keychain-dumper` SSH fallback for Phase V on managed or anti-Frida apps, bounding the Frida session teardown so heavy MAM/anti-instrumentation can't stall the memory phase, and a Jira/VAPT ticket exporter.

## Disclaimer

**For authorized security testing only.** Use it only against apps you have explicit written permission to test. Decrypting App Store binaries (`--decrypt`, Phase I) strips DRM and must only be done on apps you're authorized to assess. Unauthorized testing is illegal and unethical.

---

<div align="center">

Built by [0xs0m](https://somm.tf)

</div>
