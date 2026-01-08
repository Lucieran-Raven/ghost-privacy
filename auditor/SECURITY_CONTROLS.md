# Security Controls (Code Map)

This is a code-level map of core security controls.

## Session capability tokens

- Frontend input enforcement:
  - `src/components/Ghost/SessionCreator.tsx`
  - `src/utils/algorithms/session/accessCode.ts`

- Backend enforcement (service-side verification):
  - `supabase/functions/validate-session/index.ts`
  - `supabase/functions/extend-session/index.ts`
  - `supabase/functions/delete-session/index.ts`

## Token-derived realtime channels

- Derivation algorithm:
  - `src/utils/algorithms/session/realtimeChannel.ts`

- Channel usage:
  - `src/lib/realtimeManager.ts`
  - `src/components/Ghost/ChatInterface.tsx`

## IP binding

- Shared security primitives:
  - `supabase/functions/_shared/security.ts`

- Enforced in edge functions:
  - `supabase/functions/validate-session/index.ts`
  - `supabase/functions/extend-session/index.ts`
  - `supabase/functions/delete-session/index.ts`

## Desktop CSP hardening

- `src-tauri/tauri.conf.json`

## RAM-only guarantees

- Message queue:
  - `src/utils/clientMessageQueue.ts`

- Key manager:
  - `src/utils/sessionKeyManager.ts`

Core algorithms verified
Tauri desktop: RAM-only, no disk writes
