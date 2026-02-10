# Ethics & Opt-Out (Research Features)

Ghost includes optional "Ghost Mirage" research/defense features (honeypot and honeytoken handling).

This document describes the **default behavior**, **what data is processed**, and the **user opt-out/opt-in controls**.

## Default behavior

- Research features are disabled by default unless explicitly enabled.
- When disabled:
  - No honeypot edge function call is performed.
  - No trap UI is shown.
  - Honeytoken session IDs are treated as invalid access codes.

## Data handling (when research features are enabled)

Ghost Mirage is designed to minimize collection.

- **Client -> Server request**: the client may call the Supabase Edge Function `detect-honeypot`.
- **Request fields**:
  - `sessionId`: the user-supplied session identifier being checked.
  - `accessorFingerprint` (optional): a client-generated fingerprint used for anti-abuse / binding in the broader session system.
- **Server-side processing**:
  - The edge function returns only a boolean and coarse trap type (`explicit_trap`, `dead_session`, `unknown`).
  - It does not request or receive message content.

### Retention / logging notes

- Ghost does not intentionally store honeypot interaction transcripts.
- **Operational logs may exist** at the platform/infrastructure layer (Supabase/hosting/CDN) according to their standard policies. Treat this as a known limitation.

## Enablement

### Build-time default

Set:

- `VITE_ENABLE_RESEARCH_FEATURES=true`

### Runtime toggle

The Session UI exposes a toggle controlling whether research features are enabled.

## User safety principles

- Research features are intended as **defensive deception** and should not be enabled by default in at-risk deployments.
- Users should be able to make an informed choice; operators should document whether research features are enabled in their build.

## Code locations

- State + helpers: `src/utils/researchFeatures.ts`
- Join flow enforcement: `src/components/Ghost/SessionCreator.tsx`
- Honeypot request gate: `src/lib/honeypotService.ts`
