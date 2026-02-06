# Ghost Privacy Refactor Summary

## Scope

This change set hardens and decomposes the prior monolithic `ChatInterface.tsx` into a modular architecture while preserving existing behavior and security invariants.

## New/Updated Modules

- `src/components/Ghost/ChatInterfaceShell.tsx`
  - Presentational/orchestration layer.
  - Owns UI rendering and wires together hooks.

- `src/components/Ghost/ChatInterface.tsx`
  - Compatibility shim.
  - Re-exports `ChatInterfaceShell` as the default export so existing imports remain valid.

- `src/components/Ghost/hooks/useChatTransport.ts`
  - Session lifecycle: init, key exchange, realtime wiring, send/receive, termination, cleanup.

- `src/components/Ghost/hooks/useMediaVoice.ts`
  - Voice/media orchestration around `useVoiceMessaging`.

- `src/components/Ghost/hooks/useFileTransfers.ts`
  - File/video transfer protocol, ACKs, TTL cleanup, and native drop behavior.

- `src/components/Ghost/hooks/useQuarantine.ts`
  - Window/tab visibility lifecycle, beforeunload, pagehide/unload cleanup, and content-protection toggles.

## Audit-Friendly Renames

- `src/utils/trapAudio.ts` -> `src/utils/honeypotAudio.ts`
- `src/utils/algorithms/deception/trapAudio.ts` -> `src/utils/algorithms/deception/honeypotAudio.ts`
- `src/components/Ghost/FakeTwoFactorModal.tsx` -> `src/components/Ghost/SimulatedTwoFactorModal.tsx`
- `src/components/Ghost/FakeAdminPanel.tsx` -> `src/components/Ghost/SimulatedAdminConsole.tsx`
- `src/components/Ghost/FakeApiDocs.tsx` -> `src/components/Ghost/SimulatedApiDocs.tsx`
- `src/components/Ghost/FakeDebugConsole.tsx` -> `src/components/Ghost/SimulatedDebugConsole.tsx`
- `src/components/Ghost/FakeFileUpload.tsx` -> `src/components/Ghost/SimulatedFileUpload.tsx`

## CI / Tooling

- CI lint remains **errors-only** via `--quiet`.
- Added `npm run typecheck` (full app typecheck) and wired it into CI/security workflows.

## Verification

Run locally:

- `npm test`
- `npm run build`
- `npm run typecheck`

## Notes

- No functional changes are intended; changes are refactor + naming clarity.
