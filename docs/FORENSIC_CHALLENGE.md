# Ghost Privacy — $50K Forensic Challenge (Authoritative Scope)

This document defines the **single authoritative scope** for the Ghost Privacy forensic challenge.

## Goal

Demonstrate recovery of **message plaintext** from a Ghost session **after the session is ended**, under the conditions defined below.

Ghost is designed so that:

- Plaintext is encrypted/decrypted on the client.
- The server only handles ciphertext delivery and minimal session metadata.
- Post-session recoverability is **minimized under normal operating conditions**, but not eliminated under all adversaries.

## What “success” means

A valid finding must include all of the following:

- Recovery of **user message plaintext** that was exchanged within a real Ghost session.
- Recovery occurs **after** the user has ended the session (triggering teardown/cleanup).
- Recovery method is **reproducible** by an independent verifier.

## In scope (normal operating conditions)

The challenge is scoped to **application-level** and **standard forensic tooling** where the browser/OS is not assumed to be compromised.

- **Device state**:
  - No malware, no keylogger, no remote admin tooling.
  - No kernel-level instrumentation.
  - No deliberate memory-dump tooling executed during the session.

- **Browser state**:
  - No malicious extensions with DOM access.
  - No custom instrumented browser build.

- **Network state**:
  - Standard network conditions; TLS applies.
  - Tor is allowed but not required.

## Out of scope (explicit exclusions)

These are excluded because they are outside what a browser/PWA can reliably control.

- OS-level or physical acquisition that can trivially capture volatile data:
  - **RAM capture** during or immediately after the session.
  - Cold boot attacks.
  - DMA attacks.

- OS behavior outside app control:
  - Swap/pagefile/hibernation artifacts.
  - Crash dumps.

- Compromised endpoint scenarios:
  - Keylogging.
  - Screen recording/screenshot capture.
  - Malicious recipient intentionally capturing plaintext.

If a recovery depends on any of the above, it does not count as a challenge win.

## Test environment requirements (for verification)

To be verifiable, include:

- OS + version, browser + version.
- Ghost version (commit hash/tag) and deployment target.
- Exact steps to reproduce.
- Any scripts/tools used.

## Rules

- No exploitation of the operating system (no privilege escalation, kernel drivers, or rootkits).
- No browser modification or extension-based DOM extraction.
- No supply-chain compromise (modifying the Ghost build or hosting).
- You may use standard user-space forensic tools that analyze:
  - Browser profile data.
  - File system artifacts that are produced by normal operation.
  - System logs available to a normal user.

## Reporting

Submit:

- A clear write-up with reproduction steps.
- Evidence showing:
  - session creation
  - message exchange
  - session end
  - recovered plaintext after end

Security reports should follow the private disclosure process in `SECURITY.md`.

## Verification procedure (maintainers)

To validate a submission, maintainers will:

- Check out the exact commit/tag referenced by the report.
- Reproduce the session flow as described.
- Run local verification:
  - `npm test`
  - `npm run integrity`
- Compare recovered plaintext against claimed session messages and timestamps.

## Notes on claims and limitations

- Ghost makes **scoped** claims: “RAM-only under normal operation” and “best-effort cleanup.”
- A browser-native app cannot guarantee zero recoverability against advanced local forensics or a compromised OS.
