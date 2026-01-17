# Release Verification

This document explains how to verify a downloaded release file matches the published SHA-256 hash.

Release builds also enforce runtime integrity checks. If integrity verification fails at runtime, the app performs a secure purge and exits.

## What you verify

- **File integrity**: The bytes you downloaded match the expected SHA-256 value.
- **Trusted source**: You compare against the hashes published at:
  - `/releases/hashes.txt`

## Step 1: Download the release

Download the file from the official downloads page (or directly from `/releases/`).

## Step 2: Compute SHA-256 locally

### Windows (PowerShell)

```powershell
Get-FileHash .\GhostPrivacy-Setup.exe -Algorithm SHA256
```

### macOS

```bash
shasum -a 256 GhostPrivacy-Setup.exe
```

### Linux

```bash
sha256sum GhostPrivacy-Setup.exe
```

## Step 3: Compare with published hashes

Open:

- `/releases/hashes.txt`

Confirm:

- The **filename** matches
- The **SHA-256** matches exactly

If the hash does not match, do not run the file.

## Build provenance verification (recommended)

Release artifacts are produced by GitHub Actions release workflows and include a signed build provenance attestation.

Verify that the artifact you downloaded was built by the official repository workflow for the tag.

Prerequisite:

- Install GitHub CLI (`gh`).

Example (verify an installer / APK file):

```bash
gh attestation verify <PATH_TO_FILE> --repo Lucieran-Raven/ghost-privacy
```

Notes:

- This checks that GitHub has a provenance attestation for the file and that it matches the repository.
- Do this before (or alongside) SHA-256 verification.

## Runtime integrity verification (release builds)

Release builds must pass build integrity verification at startup.

- Android verifies the APK signing certificate SHA-256 against the expected value embedded at build time.
- Desktop verifies the installer/app code signature against the expected signer certificate SHA-256 embedded at build time.

If verification is skipped or fails in a release/native build, the app treats the build as untrusted and exits after purging sensitive state.

## Integrity suite (optional)

If you are building from source, you can run the integrity verification suite:

```bash
npx tsx scripts/verify_integrity.ts
```

Expected output includes an integrity hash:

```text
🔒 INITIATING GHOST INTEGRITY PROTOCOL...
...
INTEGRITY_HASH_SHA256=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
✅ INTEGRITY VERIFIED. SYSTEM GREEN. (N/N)
```
