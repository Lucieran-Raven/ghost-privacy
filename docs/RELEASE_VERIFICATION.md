# Release Verification

This document explains how to verify a downloaded release file matches the published SHA-256 hash.

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
