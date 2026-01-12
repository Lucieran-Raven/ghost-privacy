# Security Controls (Code Map)

This document maps core security claims to their enforcement points in the codebase.  
All controls are implemented identically across Web, Desktop (Tauri), and Android (Capacitor).

## Session Capability Tokens
Joining a session requires a secret capability token. Possession proves authorization.

**Frontend enforcement**:  
- `src/components/Ghost/SessionCreator.tsx` → validates access code format  
- `src/utils/algorithms/session/accessCode.ts` → strict parsing of `sessionId.capabilityToken`

**Backend enforcement**:  
- `supabase/functions/validate-session/index.ts` → verifies `capability_hash`  
- `supabase/functions/extend-session/index.ts` → requires valid token  
- `supabase/functions/delete-session/index.ts` → requires valid token

**Test coverage**:  
- `src/utils/algorithms/session/accessCode.test.ts`

## Token-Derived Realtime Channels
Message channels are unguessable without the capability token.

**Implementation**:  
- `src/utils/algorithms/session/realtimeChannel.ts` → derives channel name from token  
- `src/lib/realtimeManager.ts` → uses derived channel for Supabase subscription  
- `src/components/Ghost/ChatInterface.tsx` → passes token to realtime manager

**Test coverage**:  
- `src/utils/algorithms/session/realtimeChannel.test.ts`

## IP Binding (Anti-Hijacking)
Ghost uses client IP hashing for rate limiting. Session authorization is enforced via the capability token.

**Shared primitives**:  
- `supabase/functions/_shared/security.ts` → `getClientIpHashHex`

**Enforcement**:  
- `supabase/functions/create-session/index.ts` → calls `increment_rate_limit` with `p_ip_hash`

## Desktop CSP Hardening
Tauri desktop app prevents script injection escalation.

**Configuration**:  
- `src-tauri/tauri.conf.json` → Content Security Policy enabled

## Web CSP Hardening
Web deployment sets security headers at the edge.

**Configuration**:
- `netlify.toml` → Content Security Policy + security headers

## Replay Suppression (Realtime)
Incoming realtime payloads are rejected if they are replays or malformed.

**Implementation**:
- `src/lib/realtimeManager.ts` → `shouldAcceptIncoming` validates type, nonce, timestamp, size, replay TTL

**Test coverage**:
- `src/lib/realtimeManager.test.ts`

## Build Integrity Verification
Build pipelines verify integrity inputs used by security-critical configuration.

**Implementation**:
- `scripts/verify_integrity.ts` → integrity hash over selected config/security inputs

**CI enforcement**:
- `.github/workflows/ci.yml` → `npm run integrity`

## RAM-Only Guarantees
Messages and keys exist only in memory — never persisted intentionally.

**Core components**:  
- `src/utils/clientMessageQueue.ts` → messages stored in ephemeral `Map`  
- `src/utils/sessionKeyManager.ts` → keys zeroized via `nuclearPurge()` on session end
