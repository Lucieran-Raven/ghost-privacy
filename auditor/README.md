# Auditor Package

This folder contains a reproducible, auditor-friendly security verification bundle.

## Quick start (reproducible)

1) Install with lockfile fidelity:

```bash
npm ci
```

2) Run security unit tests:

```bash
npm test
```

3) Run lint + build verification:

```bash
npm run lint
npm run build
```

4) Run the standalone integrity suite:

```bash
npm run integrity
```

## What to read

- `../THREAT_MODEL_MAPPING.md`
- `SECURITY_CONTROLS.md`
- `REPRODUCIBLE_TESTS.md`
- `ETHICS_OPTOUT.md`
- `PERFORMANCE_FORENSICS.md`
- `DESKTOP_RELEASE.md`

## CI

GitHub Actions workflow: `../.github/workflows/ci.yml`
