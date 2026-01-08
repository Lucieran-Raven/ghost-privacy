# Ghost Privacy — Layer 0–2 Parity Audit Report

This report documents the Layer 0–2 hardening work and the CI/verification guarantees that make the security posture consistent across **Web (PWA)**, **Desktop (Tauri)**, and **Android (Capacitor)**.

## Scope (Layers 0–2)

- Layer 0: `src/utils/algorithms/**` (pure crypto/session/encoding primitives)
- Layer 1: Platform wrappers and platform security surfaces:
  - Web/PWA: `public/sw.js`, `public/_headers`
  - Desktop/Tauri: `src-tauri/**`, `src/utils/runtime.ts` wrappers
  - Android/Capacitor: `android/**` native WebView + network security policy
- Layer 2: Shared infrastructure (builds/tests/audits/CI + backend edge functions)
  - CI: `.github/workflows/*.yml`
  - Auditor bundle: `auditor/**`, `scripts/**`, `src/test/**`
  - Backend: `supabase/functions/**`, `supabase/migrations/**`

## Cross-platform invariants (what must stay true)

- Layer 0 remains **platform-agnostic** (no `window`, `document`, `atob/btoa`, `tauriInvoke`, global `crypto`, `fetch`, etc.)
- Platform wrappers (Layer 1) must be **thin** and must not introduce persistence or secret leakage.
- CSP and network policies are **equivalent in intent** across Web and Desktop.
- CI must **fail closed** on any deviation from the security controls.

## What CI now proves (Layer 2)

On every push/PR:

- Web/shared TS:
  - `npm test` (includes:
    - Layer-0 purity guard
    - deniable encryption tests
    - constant-time helper tests
    - forensic regression checks)
  - `npm run integrity` (standalone integrity hashing)
  - `npm run lint`
  - `npm run build`

- Desktop/Tauri:
  - `cargo test --locked` in `src-tauri`

- Android/Capacitor:
  - Build web assets
  - `npx cap sync android`
  - `./gradlew assembleRelease`

Additionally (security workflow):

- CSP validation fails if:
  - `unsafe-eval` or `unsafe-inline` appears
  - Web CSP (`public/_headers`) and Tauri CSP (`src-tauri/tauri.conf.json`) drift

## Hardening timeline (commits)

Repository: https://github.com/Lucieran-Raven/ghost-privacy

Layer 3 report:

- `auditor/LAYER3_REPORT.md`

### Layer 0 — Core algorithms hardened

- `e5a77d7` — Layer0: enforce platform-agnostic crypto/session primitives
- `2a5919d` — Layer0: add purity guard test
- `990aab6` — Layer0: harden ghost id generation and deniable decrypt input limits
- `61acf89` — Layer0: harden deniable decrypt bounds and add tamper tests
- `5e31801` — Layer0: add constant-time compare helper and use in session cache

### Layer 1 — Platform wrappers hardened (strict mode)

- `d1a0465` — Tauri: strict input validation for vault and channel commands
- `897e09c` — Web/PWA: strict no-store SW + app shell cache headers
- `791c5f1` — Android: strict TLS-only network config + WebView hardening

### Layer 2 — Shared infrastructure hardened

- `a35f248` — CI: add Tauri cargo tests and Android assembleRelease smoke build
- `c5876a0` — Layer2: pin toolchain and enforce Web/Tauri CSP parity
- `22bb13b` — Auditor: extend forensic regression checks to Android native layer
- `fa77a35` — Backend: fail-closed capability verification + constant-time checks

## Notes / remaining risks

- Web/PWA and JS runtime limitations mean “zero post-session plaintext recovery” cannot be guaranteed against advanced local forensics (OS swap/hibernation, browser internals, immutable JS strings, etc.).
- The mitigations here focus on:
  - avoiding app-level persistence
  - minimizing obvious artifacts
  - failing closed on session binding and capability misuse
  - enforcing parity across platforms via CI

## How to reproduce verification locally

- `npm ci`
- `npm test`
- `npm run integrity`
- `npm run lint`
- `npm run build`

Desktop (Tauri):
- `cd src-tauri`
- `cargo test --locked`

Android (Capacitor):
- `npx cap sync android`
- `cd android`
- `./gradlew assembleRelease`
