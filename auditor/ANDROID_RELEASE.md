# Android Release (APK) — Direct Download

This repository can be packaged as an Android app using **Capacitor**.

This is configured as a **web-loaded shell**:

- The Android app loads the production website URL inside a native WebView.
- Web updates ship instantly via web deploys (no need to publish a new APK for every web change).

## Local build (Windows)

Prerequisites:

- Node.js 20+
- Android Studio (for Android SDK)
- JDK 17

Notes:

- Android builds require a valid Android SDK path.
- The project uses `android/local.properties` (generated locally) to point Gradle to your SDK.

Commands:

```bash
npm ci
npm run build
npx cap sync android
```

Build APK:

```bash
cd android
./gradlew assembleDebug
```

APK output:

- `android/app/build/outputs/apk/debug/app-debug.apk`

## CI build + GitHub Release assets (recommended)

Workflow:

- `../.github/workflows/capacitor-android-release.yml`

Trigger:

- Push a git tag like `v0.1.0`.

Result:

- GitHub Actions builds the Android APK.
- The APK is uploaded:
  - as a workflow artifact
  - as a GitHub Release asset
- A `.sha256` checksum file is also attached to the release.

## Website distribution (no Play Store)

You can distribute without Google Play:

- Host the `.apk` file on your website (e.g. `/downloads/ghost-privacy.apk`).
- Host the `.sha256` file next to it.

Important notes:

- Android will show warnings for sideloaded APKs ("Install unknown apps" / Play Protect).
- That is expected for direct downloads outside the Play Store.
