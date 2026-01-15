# 🤝 Contributing to Ghost Privacy

Thank you for your interest in contributing to Ghost Privacy — an open-source, ephemeral messaging tool built for real-world privacy.

## 🛡️ Core Principles

- **No persistence**: Never store messages, keys, or session secrets to disk (browser storage, files).
- **No telemetry**: Never add analytics, logs, or data collection.
- **Layer 0 purity**: Keep `src/utils/algorithms/**` platform-agnostic and side-effect free.
- **Fail-closed**: All security checks must default to `false` on error or ambiguity.
- **Honesty**: Never overclaim capabilities. Document limits clearly.

## 🧪 Development Setup

Ghost uses Vite, React, and Supabase.

```bash
# Install dependencies
npm install

# Start development server
npm run dev

🔍 Verification Guide
To validate Ghost’s security properties:

RAM-only storage:
Check src/utils/clientMessageQueue.ts — messages stored only in Map, never persisted.
Check src/utils/sessionKeyManager.ts — keys zeroized via nuclearPurge().
Zero server logs:
Inspect supabase/functions/*/index.ts — no console.log statements.
CORS is strict allowlist; unknown origins rejected.
IP binding:
See supabase/functions/validate-session/index.ts — enforces host_ip_hash match.
Rate limiting:
Migration 20260105000000_fix_rate_limits_schema.sql ensures atomic, per-IP limits.
