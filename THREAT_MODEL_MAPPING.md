# Ghost Privacy Threat Model Mapping

This document maps high-level security claims to concrete enforcement points in the codebase and the tests that validate them.

## Claims -> Enforcement -> Tests

### Capability token required for session access
- **Claim**: Joining a session requires possession of a secret capability token.
- **Enforcement (frontend)**:
  - `src/components/Ghost/SessionCreator.tsx`
    - Guests must provide `sessionId.capabilityToken`.
    - Uses `parseAccessCode()`.
  - `src/utils/algorithms/session/accessCode.ts`
    - Strict parsing/validation of full access code.
- **Enforcement (backend)**:
  - `supabase/functions/validate-session/index.ts`
  - `supabase/functions/extend-session/index.ts`
  - `supabase/functions/delete-session/index.ts`
    - Uses `verifyCapabilityHash()` against stored `capability_hash`.
- **Tests**:
  - `src/utils/algorithms/session/accessCode.test.ts`

### Token-derived realtime channels
- **Claim**: Realtime message channels are unguessable without the capability token.
- **Enforcement**:
  - `src/utils/algorithms/session/realtimeChannel.ts`
    - Channel name derived via HMAC-style derivation.
  - `src/lib/realtimeManager.ts`
    - Uses derived channel name when calling `supabase.channel(...)`.
  - `src/components/Ghost/ChatInterface.tsx`
    - Passes capability token into `RealtimeManager`.
- **Tests**:
  - `src/utils/algorithms/session/realtimeChannel.test.ts`

### IP binding / anti-hijacking
- **Claim**: Session access is bound to the creator IP (and guest IP after first bind).
- **Enforcement**:
  - `supabase/functions/_shared/security.ts`
    - `getClientIpHashHex`, `parseSessionIpHash`, `buildSessionIpHashBytea`
  - `supabase/functions/validate-session/index.ts`
    - Enforces IP hash for host/guest; binds guest IP on first join.
  - `supabase/functions/extend-session/index.ts`
    - Requires IP hash match before extending.
  - `supabase/functions/delete-session/index.ts`
    - Requires IP hash match before deletion.
- **Tests**:
  - Not covered by Node unit tests (Deno edge runtime). Recommend running Supabase function tests in CI later.

### Desktop hardening (Tauri CSP)
- **Claim**: Desktop shell prevents webview injection from escalating into native.
- **Enforcement**:
  - `src-tauri/tauri.conf.json` (CSP enabled)
- **Tests**:
  - Manual verification recommended (CSP violations should block inline/eval scripts).
