# Reproducible Security Tests

## Why this is reproducible

- Dependency graph is pinned via `package-lock.json`.
- CI uses `npm ci` (lockfile strict) instead of `npm install`.

## Local run

```bash
npm ci
npm test
npm run lint
npm run build
```

## Test suite layout

- Unit/security tests (Vitest):
  - `src/utils/algorithms/session/accessCode.test.ts`
  - `src/utils/algorithms/session/realtimeChannel.test.ts`
  - `src/test/forensicArtifacts.test.ts`

- Standalone cryptographic integrity suite:
  - `scripts/verify_integrity.ts`
  - Run: `npm run integrity`
