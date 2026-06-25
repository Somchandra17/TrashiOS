"""
Phase II — Static Binary & Info.plist Analysis  (the iOS "manifest" + binary hardening).

Obtains the app bundle (pulled from device over SSH, or unzipped from a local
IPA), then inspects:
  • Info.plist        — ATS / NSAllowsArbitraryLoads, CFBundleURLTypes, file sharing,
                        background modes, privacy usage strings.
  • Entitlements      — get-task-allow (debuggable), keychain-access-groups,
                        app-groups, associated-domains (wildcard).
  • Mach-O hardening  — PIE, stack canary, ARC, LC_ENCRYPTION_INFO cryptid.
  • Embedded secrets  — strings/Presidio scan over the binary.

Grounded in OWASP MASTG-TEST-0024 (ATS), -0001/-0002 (binary protections),
-0089 (entitlements), MASVS-CODE / MASVS-NETWORK / MASVS-PLATFORM.
"""

from __future__ import annotations

import plistlib
import shutil
import subprocess
import zipfile
from pathlib import Path

from rich.console import Console

from core.config import Config, INFO_PLIST_SECURITY_FLAGS, ENTITLEMENT_RISK_KEYS, MACHO_HARDENING_CHECKS
from core.ios_device import IOSDevice
from utils.helpers import presidio_scan_file, presidio_findings_to_report

console = Console()
PHASE = "Phase II — Static Binary & Info.plist Analysis"


def run_static_binary_analysis(config: Config, device: IOSDevice) -> None:
    console.print(f"\n[bold cyan]═══ {PHASE} ═══[/bold cyan]\n")

    app_dir = _obtain_app_bundle(config, device)
    if not app_dir:
        console.print("[red]Could not obtain the app bundle (no SSH and no local IPA). Skipping.[/red]")
        config.add_finding(PHASE, "Static analysis skipped — app bundle unavailable", "Info",
                           "Neither an SSH-reachable bundle container nor a local IPA was available to analyze.")
        return

    console.print(f"  [green]App bundle:[/green] {app_dir}")

    info_plist = app_dir / "Info.plist"
    plist = _load_plist(info_plist)
    executable = plist.get("CFBundleExecutable") if plist else None
    config.executable_name = executable or config.executable_name
    binary = (app_dir / executable) if executable else _guess_binary(app_dir)

    _analyze_info_plist(config, plist, info_plist)
    _analyze_entitlements(config, app_dir, binary)
    _analyze_macho_hardening(config, binary)
    _scan_binary_secrets(config, binary)
    _classdump(config, app_dir, binary)

    console.print(f"\n[green]✓ {PHASE} complete.[/green]")


# ── obtain the .app bundle (SSH pull preferred, IPA unzip fallback) ──

def _obtain_app_bundle(config: Config, device: IOSDevice) -> Path | None:
    dest = config.output_dir / "bundle"
    dest.mkdir(parents=True, exist_ok=True)

    # 1) Local IPA → unzip Payload/*.app
    if config.ipa_path and Path(config.ipa_path).exists():
        try:
            with zipfile.ZipFile(config.ipa_path) as zf:
                zf.extractall(dest)
            payload = dest / "Payload"
            apps = list(payload.glob("*.app")) if payload.exists() else []
            if apps:
                config.log_command(PHASE, f"unzip {config.ipa_path}", f"extracted to {apps[0]}")
                return apps[0]
        except Exception as e:
            console.print(f"  [yellow]IPA unzip failed: {e}[/yellow]")

    # 2) Pull the bundle container over SSH
    bundle_remote = config.bundle_container or device.get_bundle_container(config.bundle_id)
    if bundle_remote and device.caps.ssh:
        console.print(f"  [cyan]Pulling app bundle over SSH:[/cyan] {bundle_remote}")
        out = device.pull_as_root(bundle_remote, str(dest))
        config.log_command(PHASE, f"scp -r {bundle_remote} -> {dest}", out)
        apps = list(dest.glob("*.app"))
        if apps:
            return apps[0]
    return None


def _load_plist(path: Path) -> dict | None:
    if not path.exists():
        return None
    try:
        with open(path, "rb") as fh:
            return plistlib.load(fh)
    except Exception:
        # binary plist that plistlib can't parse directly — convert with plutil
        try:
            xml = subprocess.run(["plutil", "-convert", "xml1", "-o", "-", str(path)],
                                 capture_output=True, timeout=30)
            return plistlib.loads(xml.stdout)
        except Exception:
            return None


def _guess_binary(app_dir: Path) -> Path | None:
    # The Mach-O usually shares the .app base name.
    cand = app_dir / app_dir.name.replace(".app", "")
    if cand.exists():
        return cand
    # else first executable-looking file
    for f in app_dir.iterdir():
        if f.is_file() and f.stat().st_mode & 0o111:
            return f
    return None


# ── Info.plist ──────────────────────────────────────────────────

def _analyze_info_plist(config: Config, plist: dict | None, info_path: Path) -> None:
    if not plist:
        console.print("  [yellow]Info.plist not readable.[/yellow]")
        return
    console.print("  [cyan]Analyzing Info.plist...[/cyan]")
    config.log_command(PHASE, f"parse {info_path}", f"keys: {len(plist)}")

    # App Transport Security
    ats = plist.get("NSAppTransportSecurity", {}) or {}
    if ats.get("NSAllowsArbitraryLoads") is True:
        flag = INFO_PLIST_SECURITY_FLAGS["NSAllowsArbitraryLoads"]
        config.add_finding(PHASE, "ATS arbitrary loads enabled (NSAllowsArbitraryLoads=true)",
                           flag["risk"], flag["desc"] + "\n\nFrom Info.plist NSAppTransportSecurity.")
    for k in ("NSAllowsArbitraryLoadsForMedia", "NSAllowsArbitraryLoadsInWebContent"):
        if ats.get(k) is True:
            flag = INFO_PLIST_SECURITY_FLAGS[k]
            config.add_finding(PHASE, f"ATS exception: {k}=true", flag["risk"], flag["desc"])
    exceptions = ats.get("NSExceptionDomains", {}) or {}
    for domain, rules in exceptions.items():
        if isinstance(rules, dict):
            if rules.get("NSExceptionAllowsInsecureHTTPLoads") is True:
                config.add_finding(PHASE, f"ATS exception domain allows insecure HTTP: {domain}",
                                   "Medium",
                                   f"Domain '{domain}' permits cleartext HTTP via NSExceptionAllowsInsecureHTTPLoads.")
            tls = rules.get("NSExceptionMinimumTLSVersion")
            if tls and str(tls) < "TLSv1.2":
                config.add_finding(PHASE, f"ATS exception domain lowers TLS: {domain} ({tls})",
                                   "Medium", f"Domain '{domain}' allows minimum TLS {tls} (< TLSv1.2).")

    # File sharing / open-in-place
    if plist.get("UIFileSharingEnabled") is True:
        flag = INFO_PLIST_SECURITY_FLAGS["UIFileSharingEnabled"]
        config.add_finding(PHASE, "iTunes/Finder file sharing enabled (UIFileSharingEnabled)",
                           flag["risk"], flag["desc"])
    if plist.get("LSSupportsOpeningDocumentsInPlace") is True:
        flag = INFO_PLIST_SECURITY_FLAGS["LSSupportsOpeningDocumentsInPlace"]
        config.add_finding(PHASE, "App supports opening documents in place", flag["risk"], flag["desc"])

    # URL schemes (feeds the URL-scheme/IPC phase)
    url_types = plist.get("CFBundleURLTypes", []) or []
    schemes: list[str] = []
    for ut in url_types:
        schemes.extend(ut.get("CFBundleURLSchemes", []) or [])
    if schemes:
        config.add_finding(PHASE, f"Custom URL scheme(s) declared: {', '.join(schemes)}",
                           "Info",
                           "Declared CFBundleURLTypes (external entry points). These are fuzzed in the "
                           "URL Scheme / IPC phase for unauthenticated actions and parameter injection:\n  - "
                           + "\n  - ".join(schemes))

    # Background modes
    bg = plist.get("UIBackgroundModes", []) or []
    if bg:
        config.add_finding(PHASE, f"Background modes declared: {', '.join(bg)}", "Info",
                           "Review for sensitive activity while backgrounded: " + ", ".join(bg))

    # Privacy usage descriptions (informational inventory)
    usage = {k: v for k, v in plist.items() if k.endswith("UsageDescription")}
    if usage:
        detail = "\n".join(f"  {k}: {v}" for k, v in usage.items())
        config.add_finding(PHASE, f"Declared privacy usage descriptions ({len(usage)})", "Info",
                           "Capabilities requested (verify each is actually used / least-privilege):\n" + detail)

    min_os = plist.get("MinimumOSVersion") or plist.get("LSMinimumSystemVersion")
    if min_os:
        config.log_command(PHASE, "MinimumOSVersion", str(min_os))


# ── Entitlements ────────────────────────────────────────────────

def _analyze_entitlements(config: Config, app_dir: Path, binary: Path | None) -> None:
    if not shutil.which("codesign"):
        console.print("  [yellow]codesign not found — skipping entitlements.[/yellow]")
        return
    target = str(binary or app_dir)
    try:
        r = subprocess.run(["codesign", "-d", "--entitlements", ":-", target],
                           capture_output=True, text=True, timeout=30)
    except Exception as e:
        console.print(f"  [yellow]codesign failed: {e}[/yellow]")
        return

    raw = r.stdout or r.stderr
    config.log_command(PHASE, f"codesign -d --entitlements :- {target}", raw[:2000])
    ent = {}
    try:
        # entitlements come out as an XML plist (may have a leading binary blob header)
        start = raw.find("<?xml")
        if start >= 0:
            ent = plistlib.loads(raw[start:].encode())
    except Exception:
        ent = {}

    if not ent:
        return
    console.print("  [cyan]Analyzing entitlements...[/cyan]")

    if ent.get("get-task-allow") is True:
        risk, desc = ENTITLEMENT_RISK_KEYS["get-task-allow"]
        config.add_finding(PHASE, "Debuggable binary — get-task-allow=true", risk,
                           desc + " A debugger (lldb/Frida) can attach to the release app.")

    groups = ent.get("keychain-access-groups", []) or []
    if groups:
        risk, desc = ENTITLEMENT_RISK_KEYS["keychain-access-groups"]
        sev = "Medium" if (len(groups) > 1 or any("*" in g for g in groups)) else "Low"
        config.add_finding(PHASE, f"Keychain access group(s): {len(groups)}", sev,
                           desc + "\n  - " + "\n  - ".join(groups))

    app_groups = ent.get("com.apple.security.application-groups", []) or []
    if app_groups:
        risk, desc = ENTITLEMENT_RISK_KEYS["com.apple.security.application-groups"]
        config.add_finding(PHASE, f"App-group container sharing ({len(app_groups)})", risk,
                           desc + "\n  - " + "\n  - ".join(app_groups))

    assoc = ent.get("com.apple.developer.associated-domains", []) or []
    if assoc:
        risk, desc = ENTITLEMENT_RISK_KEYS["com.apple.developer.associated-domains"]
        wildcard = any("*" in a for a in assoc)
        sev = "High" if wildcard else risk
        config.add_finding(PHASE,
                           "Wildcard associated domain" if wildcard else f"Associated domains ({len(assoc)})",
                           sev, desc + "\n  - " + "\n  - ".join(assoc))


# ── Mach-O hardening ────────────────────────────────────────────

def _analyze_macho_hardening(config: Config, binary: Path | None) -> None:
    if not binary or not binary.exists():
        console.print("  [yellow]Main binary not located — skipping Mach-O hardening checks.[/yellow]")
        return
    if not shutil.which("otool"):
        console.print("  [yellow]otool not found — skipping Mach-O hardening checks (install Xcode CLT).[/yellow]")
        return
    console.print("  [cyan]Checking Mach-O hardening (otool)...[/cyan]")

    def otool(args: list[str]) -> str:
        try:
            return subprocess.run(["otool", *args, str(binary)],
                                  capture_output=True, text=True, timeout=60).stdout
        except Exception:
            return ""

    hv = otool(["-hv"])
    iv = otool(["-Iv"])
    lc = otool(["-l"])
    config.log_command(PHASE, f"otool -hv/-Iv/-l {binary.name}", (hv[:400] + "\n...\n" + iv[:400]))

    if "PIE" not in hv:
        c = MACHO_HARDENING_CHECKS["PIE"]
        config.add_finding(PHASE, "Missing PIE (no ASLR)", c["risk"], c["desc"])
    if "stack_chk" not in iv:
        c = MACHO_HARDENING_CHECKS["STACK_CANARY"]
        config.add_finding(PHASE, "Missing stack canary", c["risk"], c["desc"])
    if "_objc_release" not in iv:
        c = MACHO_HARDENING_CHECKS["ARC"]
        config.add_finding(PHASE, "ARC not detected", c["risk"], c["desc"])

    # Encryption (cryptid): 1 = FairPlay-encrypted (static reverse blocked until decrypted).
    cryptid = None
    for line in lc.splitlines():
        if "cryptid" in line:
            try:
                cryptid = int(line.strip().split()[-1])
            except ValueError:
                pass
            break
    if cryptid == 1:
        config.add_finding(PHASE, "Binary still FairPlay-encrypted (cryptid=1)", "Info",
                           "The Mach-O __TEXT is encrypted; class-dump/strings on it are limited. "
                           "Decrypt with frida-ios-dump (Milestone 2) for full static reverse-engineering.")
    elif cryptid == 0:
        config.log_command(PHASE, "LC_ENCRYPTION_INFO cryptid", "0 (decrypted)")


# ── Embedded secrets (strings / Presidio over the binary) ───────

def _scan_binary_secrets(config: Config, binary: Path | None) -> None:
    if not binary or not binary.exists():
        return
    console.print("  [cyan]Scanning binary for embedded secrets...[/cyan]")
    findings = presidio_scan_file(str(binary), config, source_label=f"binary:{binary.name}")
    if findings:
        presidio_findings_to_report(
            findings, PHASE, config,
            fallback_title="Hardcoded secret in binary",
            fallback_detail="The compiled binary contains strings matching sensitive patterns (verify manually).",
        )
    else:
        console.print("    [green]No high-signal secrets found in binary strings.[/green]")


# ── class-dump (optional) ───────────────────────────────────────

def _classdump(config: Config, app_dir: Path, binary: Path | None) -> None:
    if not binary or not shutil.which("class-dump"):
        return
    console.print("  [cyan]Dumping Objective-C class headers (class-dump)...[/cyan]")
    out_path = config.output_dir / "bundle" / "class-dump.txt"
    try:
        r = subprocess.run(["class-dump", str(binary)], capture_output=True, text=True, timeout=120)
        if r.stdout.strip():
            out_path.write_text(r.stdout, encoding="utf-8")
            config.log_command(PHASE, f"class-dump {binary.name}", f"{len(r.stdout.splitlines())} lines -> {out_path}")
            console.print(f"    [green]Headers written to {out_path}[/green]")
        else:
            console.print("    [yellow]class-dump produced no output (binary likely still encrypted).[/yellow]")
    except Exception as e:
        console.print(f"    [yellow]class-dump failed: {e}[/yellow]")
