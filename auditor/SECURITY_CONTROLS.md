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
Session access is bound to the creator’s IP hash. Guest IP is bound on first join.

**Shared primitives**:  
- `supabase/functions/_shared/security.ts` → `getClientIpHashHex`, `buildSessionIpHashBytea`

**Enforcement**:  
- `supabase/functions/validate-session/index.ts` → enforces host/guest IP hash match  
- `supabase/functions/extend-session/index.ts` → requires IP hash match  
- `supabase/functions/delete-session/index.ts` → requires IP hash match

## Desktop CSP Hardening
Tauri desktop app prevents script injection escalation.

**Configuration**:  
- `src-tauri/tauri.conf.json` → Content Security Policy enabled

## RAM-Only Guarantees
Messages and keys exist only in memory — never persisted intentionally.

**Core components**:  
- `src/utils/clientMessageQueue.ts` → messages stored in ephemeral `Map`  
- `src/utils/sessionKeyManager.ts` → keys zeroized via `nuclearPurge()` on session end
