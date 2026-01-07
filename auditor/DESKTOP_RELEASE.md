# Desktop Release (Windows) — Direct Download

This project is a web app (PWA) that can also be packaged as a Windows desktop app using Tauri.

This repository is configured for **Option 1: web-loaded desktop shell**.

- The desktop app opens the production website URL in a native window.
- This allows instant updates via web deploys without shipping a new installer.
- It requires network access (offline mode depends on the web app/PWA behavior).

This document explains:

- how to build the Windows installer locally
- how to publish Windows installers from GitHub Actions
- how to host the installer on your own website (no Microsoft Store required)

## Local build (Windows)

Prerequisites:

- Node.js 20+
- Rust toolchain (via rustup)
- Visual Studio Build Tools (C++ build tools) if Rust needs them

Commands:

```bash
npm ci
npm run tauri:build
```

## Option 1: Web-loaded URL

The desktop window loads the production site URL configured here:

- `src-tauri/tauri.conf.json` -> `app.windows[0].url`

Example:

- `https://ghostprivacy.netlify.app`

Installer output paths:

- MSI: `src-tauri/target/release/bundle/msi/*.msi`
- EXE (NSIS): `src-tauri/target/release/bundle/nsis/*.exe`

## CI build + GitHub Release assets (recommended)

Workflow:

- `.github/workflows/tauri-windows-release.yml`

Trigger:

- Push a git tag like `v0.1.0`.

Result:

- GitHub Actions builds the Windows installer.
- The `.msi` / `.exe` are uploaded:
  - as **workflow artifacts**
  - as **GitHub Release assets** for that tag

## Hosting the installer on your website

You can distribute without the Microsoft Store:

- Upload the `.msi` or `.exe` to a static path on your website (e.g. `/downloads/ghost-privacy-setup.exe`).
- Add a "Download for Windows" link/button to your site.

## Important notes (Windows)

- Windows SmartScreen warnings are common for unsigned apps.
- If you want fewer warnings, use code signing (Authenticode) and sign the installer.
- Always publish SHA-256 checksums alongside downloads for user verification.
