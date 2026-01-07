# Ethics & Opt-Out (Research Features)

Ghost includes optional "Ghost Mirage" research/defense features (honeypot and honeytoken handling).

## Default behavior

- Research features are disabled by default unless explicitly enabled.
- When disabled:
  - No honeypot edge function call is performed.
  - No trap UI is shown.
  - Honeytoken session IDs are treated as invalid access codes.

## Enablement

### Build-time default

Set:

- `VITE_ENABLE_RESEARCH_FEATURES=true`

### Runtime toggle

The Session UI exposes a toggle controlling whether research features are enabled.

## Code locations

- State + helpers: `src/utils/researchFeatures.ts`
- Join flow enforcement: `src/components/Ghost/SessionCreator.tsx`
- Honeypot request gate: `src/lib/honeypotService.ts`
