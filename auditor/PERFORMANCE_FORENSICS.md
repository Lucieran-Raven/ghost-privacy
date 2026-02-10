# Performance & Forensics Testing

## Performance (repeatable)

Benchmarks are provided for security-critical pure functions.

- Run:

```bash
npm run bench
```

## Forensics (regression detection)

A unit test fails the build if non-comment application code re-introduces disk persistence primitives.

- `src/test/forensicArtifacts.test.ts`

## Evidence handling (recommended)

When collecting evidence for a regression or a security report, preserve reproducibility and minimize contamination:

- Capture the exact repository state:
  - `git rev-parse HEAD`
  - tag name (if applicable)
- Record toolchain versions:
  - `node --version`
  - `npm --version`
- Record OS + browser version (if the issue is client/runtime dependent)

## Chain of custody (minimum fields)

For each collected artifact (logs, screenshots, build outputs, memory dumps if applicable), record:

- Artifact identifier (filename)
- Source system (hostname/device)
- Collector (person)
- Date/time (with timezone)
- Hash (SHA-256)
- Storage location
- Transfers (who/when/how)

## Integrity verification

For release builds, attach cryptographic checksums and integrity attestations:

- `npm run integrity` → produces an integrity hash based on security/config inputs
- Release artifacts should include `.sha256` checksum files (GitHub Actions workflows attach these)
