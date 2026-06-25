# iOS DAST/SAST Report — `com.example.trashios`

**Generated:** 2026-01-01 00:00:00  
**Device:** iPhone14,5 (iOS 16.7.2, build 20H115)  
**Device UDID:** `00008030TESTUDID0001`  
**Pre-installed:** Yes  
**Tested logged in:** Yes

---
## Executive Summary

A total of **4** finding(s) were identified across **3** executed phase(s).

Confirmed findings (high-confidence evidence): **1**.

| Severity | Count |
|----------|-------|
| High | 2 |
| Medium | 1 |
| Info | 1 |

## Phase Coverage

| Phase | Status | Findings |
|-------|--------|----------|
| Phase I — App Binary Decryption | Skipped | 0 |
| Phase II — Static Binary & Info.plist Analysis | Skipped | 0 |
| Phase III — Local Data Storage Analysis | Executed (findings) | 1 |
| Phase IV — Dump File Verification | Skipped | 0 |
| Phase V — Keychain Dump & Data Protection | Executed (findings) | 2 |
| Phase VI — Backgrounding Snapshot Leakage | Skipped | 0 |
| Phase VII — Pasteboard Leakage | Skipped | 0 |
| Phase VIII — Device Log Monitoring | Skipped | 0 |
| Phase IX — Process Memory Analysis | Skipped | 0 |
| Phase X — URL Scheme / IPC Testing | Executed (findings) | 1 |
| Phase XI — Post-Logout Access Control | Skipped | 0 |
| Phase XII — Backup Analysis | Skipped | 0 |
| Phase XIII — Runtime Hardening Assessment | Skipped | 0 |

## PII Entities Detected

| Entity Type | Count | Highest Severity | Avg Confidence |
|-------------|-------|------------------|----------------|
| EMAIL_ADDRESS | 3 | High | 0.95 |

---
## Detailed Findings

### Phase I — App Binary Decryption

_Phase skipped in this execution._

### Phase II — Static Binary & Info.plist Analysis

_Phase skipped in this execution._

### Phase III — Local Data Storage Analysis

#### 1. PII detected: EMAIL_ADDRESS (3 occurrences)

- **Severity:** High
- **Status:** Open
- **Confidence:** Likely
- **CVSS (estimated):** 8.0
- **CVSS Vector (estimated):** `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:L`
- **Business Impact:** Security control weakness increases risk of confidentiality/integrity impact under adversarial conditions.
- **Remediation:** Perform root-cause analysis, implement least-privilege controls, and re-run this phase to verify closure.
- **Detail:**

```
Entity type: EMAIL_ADDRESS
Avg confidence: 0.95
Occurrences: 3

Sample matches:
  - alice@example.com
```

- **Jira Draft:**
```
Summary: PII detected: EMAIL_ADDRESS (3 occurrences)
Issue Type: Security Vulnerability
Priority: High
Phase: Phase III — Local Data Storage Analysis
CVSS: 8.0
Description: Entity type: EMAIL_ADDRESS
Avg confidence: 0.95
Occurrences: 3

Sample matches:
  - alice@example.com
Remediation: Perform root-cause analysis, implement least-privilege controls, and re-run this phase to verify closure.
Definition of Done: Fix deployed, regression test added, and DAST re-run confirms closure.
```

### Phase IV — Dump File Verification

_Phase skipped in this execution._

### Phase V — Keychain Dump & Data Protection

#### 1. Token persists in keychain after logout

- **Severity:** High
- **Status:** Open
- **Confidence:** Confirmed
> **HIGHLIGHT: CONFIRMED EVIDENCE**
- **CVSS (estimated):** 8.0
- **CVSS Vector (estimated):** `CVSS:3.1/AV:P/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:L`
- **Business Impact:** Unauthorized account access after logout can lead to privacy breach and account-takeover risk.
- **Remediation:** Enforce server-side session validation on every privileged screen/API call. Invalidate the session token server-side on logout and delete it from the keychain and any plist/NSUserDefaults. Re-check auth state in viewWillAppear/viewDidLoad of sensitive view controllers.
- **Detail:**

```
Verified via keychain dump. A refresh_token entry survived logout.
```

- **Jira Draft:**
```
Summary: Token persists in keychain after logout
Issue Type: Security Vulnerability
Priority: High
Phase: Phase V — Keychain Dump & Data Protection
CVSS: 8.0
Description: Verified via keychain dump. A refresh_token entry survived logout.
Remediation: Enforce server-side session validation on every privileged screen/API call. Invalidate the session token server-side on logout and delete it from the keychain and any plist/NSUserDefaults. Re-check auth state in viewWillAppear/viewDidLoad of sensitive view controllers.
Definition of Done: Fix deployed, regression test added, and DAST re-run confirms closure.
```

#### 2. Keychain protection classes acceptable

- **Severity:** Info
- **Status:** Open
- **Confidence:** Likely
- **CVSS (estimated):** 0.0
- **CVSS Vector (estimated):** `N/A`
- **Business Impact:** Weakly-protected keychain items can be recovered from a lost/stolen or jailbroken device, exposing credentials.
- **Remediation:** Store secrets with the strictest data-protection class that fits the use case (prefer kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly; never kSecAttrAccessibleAlways). Add `ThisDeviceOnly` so items do not migrate via iCloud/backup, and scope keychain-access-groups narrowly.
- **Detail:**

```
All items use ThisDeviceOnly classes.
```

### Phase VI — Backgrounding Snapshot Leakage

_Phase skipped in this execution._

### Phase VII — Pasteboard Leakage

_Phase skipped in this execution._

### Phase VIII — Device Log Monitoring

_Phase skipped in this execution._

### Phase IX — Process Memory Analysis

_Phase skipped in this execution._

### Phase X — URL Scheme / IPC Testing

#### 1. Custom URL scheme entry points exposed: myapp

- **Severity:** Medium
- **Status:** Open
- **Confidence:** Likely
- **CVSS (estimated):** 5.5
- **CVSS Vector (estimated):** `CVSS:3.1/AV:L/AC:L/PR:L/UI:R/S:U/C:L/I:L/A:N`
- **Business Impact:** Unvalidated deeplinks let other apps/links trigger privileged actions or inject input, abusing business logic.
- **Remediation:** Treat URL schemes / universal links as untrusted input. Authenticate and authorize every action reached via a deeplink server-side, validate and sanitize all parameters, and never perform state-changing or privileged actions from a scheme handler without an authenticated session.
- **Detail:**

```
The app handles myapp:// deeplinks; payloads fired: myapp://dashboard.
```

- **Screenshots (evidence):**
  - URL scheme: myapp://dashboard (privileged screen)
![URL scheme: myapp://dashboard (privileged screen)](./screenshots/url_scheme_myapp_privileged.png)

### Phase XI — Post-Logout Access Control

_Phase skipped in this execution._

### Phase XII — Backup Analysis

_Phase skipped in this execution._

### Phase XIII — Runtime Hardening Assessment

_Phase skipped in this execution._

---
## Missing/Manual Steps Recommended

- Validate authorization on backend APIs directly (token replay / IDOR checks), not only via UI/URL-scheme launches.
- Intercept TLS with a MitM proxy and confirm certificate/public-key pinning behavior (bypass with objection).
- Statically reverse the decrypted binary (class-dump / Hopper / Ghidra) and correlate with dynamic leakage findings.
- Re-test critical flows with non-owner / low-privileged roles where applicable.
- Add negative-test evidence for blocked paths (proof of mitigation/denial).

---
## Commands Executed

<details><summary>Click to expand full command log</summary>

**Phase:** Phase V — Keychain Dump & Data Protection  
```bash
$ frida: SecItemCopyMatching (all security classes)
```
- rc: `0`
```
2 item(s)
```

**Phase:** Phase X — URL Scheme / IPC Testing  
```bash
$ uiopen myapp://dashboard
```
- rc: `0`
```
launched
```

</details>

---
## Risk Summary

| # | Finding | Phase | Severity | Status | Confidence |
|---|---------|-------|----------|--------|------------|
| 1 | Token persists in keychain after logout | Phase V — Keychain Dump & Data Protection | High | Open | **CONFIRMED** |
| 2 | Keychain protection classes acceptable | Phase V — Keychain Dump & Data Protection | Info | Open | Likely |
| 3 | Custom URL scheme entry points exposed: myapp | Phase X — URL Scheme / IPC Testing | Medium | Open | Likely |
| 4 | PII detected: EMAIL_ADDRESS (3 occurrences) | Phase III — Local Data Storage Analysis | High | Open | Likely |
