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
