# 🤝 Contributing to Ghost Privacy

Thank you for your interest in contributing.

**Join the Alliance of Minds - Where Academic Excellence Meets AI Innovation**

Ghost Privacy is built through unprecedented collaboration between Malaysia's top university talent and the world's leading AI models. We welcome contributors who share our vision: building real-world privacy solutions through technical excellence and practical security engineering.

---

## 🌟 Our Development Philosophy

### **"Break Myths, Face Reality"**
We don't build academic exercises - we solve real-world privacy problems. Our AI partners help us understand what's actually possible in modern security engineering, not what sounds good in theory.

## Core contribution rules

1. **No persistence**: Do not introduce disk persistence for messages/session secrets.
2. **No telemetry/logging**: Do not add analytics or logs that could expose user data.
3. **Layer 0 purity**: Keep `src/utils/algorithms/**` platform-agnostic.
4. **Fail-closed design**: All validation must default to `false` on errors.
5. **Submit a pull request**: Provide a clear description of the problem your PR solves and the technical details of your implementation.

### Documentation & Translation
Helping us make Ghost more accessible to global audiences is highly encouraged. Please ensure translations maintain the precise technical meaning of security terms.

## Development Setup

Ghost uses Vite, React, and Supabase.

```bash
# Install dependencies
npm install

# Start development server
npm run dev
```

## Verification Guide

To prove Ghost’s security properties yourself:

### RAM-Only Storage
- Check `src/utils/clientMessageQueue.ts`: messages stored in `Map` only, never persisted.
- Check `src/utils/sessionKeyManager.ts`: keys stored in JavaScript heap only, with `nuclearPurge()`.

### Zero Server Logs
- Inspect all files in `supabase/functions/*/index.ts`: no `console.log`/`console.error` statements.
- Check CORS: strict allowlist, fail-closed on unknown origins.

### IP Binding Enforcement
- In `supabase/functions/validate-session/index.ts`: `getClientIpHash()` and matching logic.
- In `supabase/functions/create-session/index.ts`: stores `host_ip_hash` on session creation.

### Rate Limit Atomicity
- Migration `supabase/migrations/20260105000000_fix_rate_limits_schema.sql` ensures `UNIQUE(ip_hash, action, window_start)`.

## Licensing

By contributing to Ghost Privacy, you agree that your contributions will be licensed under the **GNU Affero General Public License v3.0 (AGPL-3.0)**.
