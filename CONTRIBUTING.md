# 🤝 Contributing to Ghost Privacy

Thank you for your interest in contributing to Ghost Privacy — an open-source, ephemeral messaging tool built for real-world privacy.

## 🛡️ Core Principles

- **No persistence**: Never store messages, keys, or session secrets to disk (localStorage, IndexedDB, files).
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
