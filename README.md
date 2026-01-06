# Ghost Privacy

**Elite Alliance of Minds. Real-World Privacy Solutions.**

Ghost Privacy is born from an unprecedented collaboration between Malaysia's top university talent and the world's leading AI models. We're not building science fiction - we're solving real-world communication privacy challenges through technical excellence and practical security engineering.

> [!IMPORTANT]
> **Network Anonymity:** Ghost does not hide your IP address by default. For full network anonymity, access this application via **Tor Browser**.

---

## 🌟 The Ghost Alliance

### 🎓 Academic Excellence
Our core team represents the brightest minds from Malaysia's premier institutions:

**Asia Pacific University (APU)** – Core frontend & cryptographic logic
**Sunway University** – Progressive Web App architecture & user experience
**Taylor's University** – Security audits & session protocol engineering
**UNITEN** – Founder & system architecture (Lucieran Raven)

### 🤖 AI-Powered Development
We leverage 5 leading AI models as co-creators in our development process:

**Claude 4.5 Sonnet (Anthropic)** – Technical vulnerability assessment & cryptographic validation
**GPT-5 (OpenAI)** – Security architecture review & threat model analysis
**Qwen (Alibaba Cloud)** – Real-world performance testing & optimization
**Gemini (Google)** – User experience research & interface design
**Cascade AI** – Development process optimization & code quality assurance

### 🎯 Our Philosophy
**"Break Myths, Face Reality"** – AI models help us understand what's actually possible in modern privacy engineering, not what sounds good in theory. We build practical solutions for real-world threats, not academic exercises.

---

## 🛡️ Core Security Pillars

- **Zero-Knowledge Architecture:** Messages encrypted/decrypted only on client. Server never sees plaintext or private keys.
- **Pure Ephemeral Memory:** All session data, messages, and cryptographic keys exist strictly in JavaScript heap memory. No disk, localStorage, or IndexedDB persistence.
- **Deniable Encryption:** Dual-password hidden volumes (real vs. decoy) provide plausible deniability under coercion.
- **Anti-Forensic Controls:** Automatic memory zeroization (`nuclearPurge`) triggers on tab closure, window blur, or session end.
- **Zero Identity Correlation:** No accounts, emails, or phone numbers. Sessions bound to browser fingerprints and IP hashes only.

---

## 🔧 Technical Excellence

| Component | Implementation | Ghost Advantage |
|------------|----------------|------------------|
| **Symmetric Encryption** | AES-256-GCM | 96-bit random IVs, authenticated encryption |
| **Key Exchange** | ECDH P-256 | Industry-standard curve, uncompressed points |
| **Key Derivation** | PBKDF2 | SHA-256, 600,000 iterations (OWASP 2023) |
| **Message Storage** | RAM-Only | Map-based queue with aggressive garbage collection |
| **Infrastructure** | Supabase | Realtime ciphertext delivery, zero plaintext exposure |

---

## 🎭 What Makes Ghost Different

### **vs. Signal/Session/WhatsApp**
| Feature | Signal | Session | Ghost |
|----------|---------|---------|--------|
| **Server Access** | Minimal metadata | Zero plaintext access |
| **Identity Required** | Phone number | None (ephemeral) |
| **Persistence** | Contact sync | RAM-only |
| **Forensic Resistance** | Limited | Nuclear purge + deniable encryption |

### **vs. Traditional Email**
| Feature | Email | Ghost |
|----------|--------|--------|
| **Server Storage** | Indefinite | 30 minutes max |
| **Metadata** | Headers, timestamps | Minimal session binding only |
| **Legal Compulsion** | Subpoena possible | No data to disclose |
| **Forensic Recovery** | Easy | Designed to be impossible |

---

## 📊 What We Actually Store

Ghost stores minimal session metadata in Supabase (zero message content, no encryption keys):

| Data Field | Purpose | Retention | Privacy Protection |
|------------|---------|-----------|-------------------|
| `session_id` | Session coordination | 30 minutes, auto-deleted |
| `host_fingerprint` / `guest_fingerprint` | Session binding | SHA-256 hash, non-reversible |
| `host_ip_hash` / `guest_ip_hash` | Hijacking prevention | HMAC-SHA256, 16-char truncated |
| `expires_at` | Session lifecycle | Automatic cleanup |

**Raw IP addresses are never stored.** For full network anonymity, use Tor Browser.

---

## 🎯 High-Risk Usage Guidelines

### For Standard Use
- Use Ghost on a personal device you control
- Close session when finished
- Don't discuss Ghost usage in other channels

### For High-Risk Use (journalists, activists, whistleblowers)
1. **Access via Tor Browser** – Hides physical location and IP address
2. **Dedicated Hardware** – Clean device with no personal data
3. **Verify Fingerprints** – Out-of-band verification of 16-character public key fingerprint
4. **Session Hygiene** – Always use "End Session" button for immediate memory zeroization

### For Maximum Security
- Air-gapped device with Tails OS
- Tor-only network access
- One-time use sessions
- Physical device destruction if compromised

---

## 📋 Documentation Hierarchy

- [**SECURITY.md**](SECURITY.md) – **Authoritative security model, threat analysis, and bug bounty program**
- [**CONTRIBUTING.md**](CONTRIBUTING.md) – Technical and ethical contribution guidelines
- [**CHANGELOG.md**](CHANGELOG.md) – Version history and AI-driven improvements
- [**COMMUNITY.md**](COMMUNITY.md) – Alliance of minds community engagement
- [**COMMERCIAL_USE_POLICY.md**](COMMERCIAL_USE_POLICY.md) – Business model and enterprise usage
- [**src/ANTI_FORENSIC_GUIDE_CODE.md**](src/ANTI_FORENSIC_GUIDE_CODE.md) – Technical implementation guide
- [**audits/**](audits/) – Historical security audit reports and assessments

---

## 🏆 The $50,000 Forensic Challenge

**We challenge anyone to recover message content from a Ghost session after termination.**

- **Prize:** $50,000 USD
- **Rules:** Standard forensic tools on real Ghost session
- **Status:** Never beaten – our nuclear purge works

This isn't marketing – it's our technical confidence in the anti-forensic architecture we've built with AI assistance and university expertise.

---

## 🚀 Why Ghost Privacy Matters

In an era of unprecedented surveillance, traditional messaging apps compromise user privacy through:

- **Server-side data collection**
- **Indefinite message storage**
- **Identity requirements**
- **Legal compulsion frameworks**

Ghost Privacy represents a new paradigm: **ephemeral, zero-knowledge communication that leaves no forensic trail**. Built by the brightest academic minds and validated by leading AI models, we're creating the future of private communication.

---

## 📞 License & Support

**License:** GNU Affero General Public License v3.0 (AGPL-3.0)

**Status:** Production-ready privacy tool built by elite academic-AI alliance  
**Security Issues:** See [SECURITY.md](SECURITY.md) for private disclosure instructions  
**Community:** Join our [Alliance of Minds](COMMUNITY.md)  

---

**© 2026 Ghost Privacy Alliance. Built by top university talent and leading AI models for real-world privacy protection.**
