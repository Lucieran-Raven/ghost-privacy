# Install Guide

This guide covers common installation friction points and how to verify downloads.

## Windows (Desktop)

### Install

- If you see **Windows SmartScreen**:
  - Click **More info**
  - Click **Run anyway**

### Verify SHA-256

1. Download the installer (example: `GhostPrivacy-Setup.exe`).
2. Open PowerShell in the download folder and run:

```powershell
Get-FileHash .\GhostPrivacy-Setup.exe -Algorithm SHA256
```

3. Compare the hash output with the published hash in:

- `/releases/hashes.txt`

## Android (APK)

### Install

- If Android blocks the APK:
  - Settings → Security (or Privacy/Security)
  - Enable **Install unknown apps** for the browser or file manager you used

### Verify SHA-256

- Use the published SHA-256 from `/releases/hashes.txt`.
- If you have a computer available, verify the downloaded APK from your PC:

```bash
sha256sum GhostPrivacy.apk
```

## Web (PWA)

### Install

- **Chrome / Chromium (Desktop/Android)**:
  - Open the site
  - Use the **Install** button in the address bar or the browser menu
- **Safari (iOS)**:
  - Share → **Add to Home Screen**

### Verify SHA-256

Web installs are delivered by the browser. For verifiable releases, prefer Desktop/Android binaries and follow:

- `docs/RELEASE_VERIFICATION.md`
