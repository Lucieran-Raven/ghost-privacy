# 🔒 Ghost Privacy Security Model

**Built by Elite Academic Alliance + Leading AI Models for Real-World Privacy Protection**

**One Truth, One Place** - This is the authoritative security documentation for Ghost Privacy, developed through unprecedented collaboration between Malaysia's top university talent and the world's leading AI models.

---

## 🌟 The Ghost Security Alliance

### 🎓 Academic Excellence Team
Our security architecture was designed and validated by top talent from Malaysia's premier institutions:

**Asia Pacific University (APU)** – Core frontend & cryptographic logic
**Sunway University** – Progressive Web App architecture & user experience
**Taylor's University** – Security audits & session protocol engineering
**UNITEN** – Founder & system architecture (Lucieran Raven)

### 🤖 AI-Powered Security Development
We leverage 5 leading AI models as co-creators in our security engineering process:

**Claude 4.5 Sonnet (Anthropic)** – Technical vulnerability assessment & cryptographic validation
**GPT-5 (OpenAI)** – Security architecture review & threat model analysis
**Qwen (Alibaba Cloud)** – Real-world performance testing & optimization
**Gemini (Google)** – User experience research & interface security
**Cascade AI** – Development process optimization & code quality assurance

### 🎯 Our Security Philosophy
**"Break Myths, Face Reality"** – AI models help us understand what's actually possible in modern privacy engineering, not what sounds good in theory. We build practical solutions for real-world threats, not academic exercises.

---

## 🎯 What We Guarantee

### Core Promises
- **Messages exist ONLY in RAM** - Never touch disk, localStorage, or server
- **After session end: 0 forensic recovery** - Verified by $50K Challenge
- **Deniable encryption**: Dual-password hidden volumes (real vs. decoy)
- **Zero server logs**: No message storage, no metadata beyond session binding

### Technical Guarantees
| Guarantee | Implementation | Verification |
|-----------|----------------|---------------|
| **Ephemeral Messages** | RAM-only storage, automatic cleanup | Browser devtools, memory analysis |
| **Forward Secrecy** | ECDH key exchange per session | Cryptographic analysis |
| **Server Blindness** | No plaintext ever transmitted | Code audit, server logs |
| **Anti-Forensic** | Memory zeroization, no persistence | $50K forensic challenge |
| **Plausible Deniability** | Dual-layer encryption with decoys | Compromise scenario testing |

---

## 🛡️ What We Store (and Why)

| Data Field | Purpose | Retention | Privacy Notes |
|------------|---------|-----------|---------------|
| `session_id` | Session coordination | 30 minutes, then auto-deleted |
| `host_fingerprint` / `guest_fingerprint` | Session binding | SHA-256 hash, non-reversible |
| `host_ip_hash` / `guest_ip_hash` | Hijacking prevention | HMAC-SHA256, 16-char truncated |
| `expires_at` | Session lifecycle | Automatic cleanup |
| **NOT stored**: Message content, encryption keys, user identities | N/A | Zero-knowledge architecture |

### IP Hashing Security
- **Algorithm**: HMAC-SHA256 with per-environment secret salt
- **Storage**: First 16 characters only (64-bit space)
- **Purpose**: Prevent session hijacking, not for identification
- **GDPR**: Proper pseudonymization, not personal data

---

## 🎭 Threat Model

### ✅ Ghost IS Designed to Protect Against

| Actor | Attack Vector | Protection |
|---------|---------------|------------|
| **Passive network observer** | Traffic interception | TLS + E2E encryption |
| **Curious service provider** | Server-side logging | Zero server-side plaintext |
| **Subpoena/legal demand** | Data disclosure order | No stored messages to disclose |
| **Database breach** | Stolen session data | Only non-identifying metadata |
| **Session hijacking** | Stolen session link | Fingerprint + IP binding |
| **Replay attacks** | Message duplication | Unique IVs + timestamps |

### ❌ Ghost is NOT Designed to Protect Against

| Actor | Attack Vector | Why Not Protected | Mitigation |
|---------|---------------|-------------------|------------|
| **ISP/Network admin** | IP address logging | Use Tor Browser |
| **Physical device access** | RAM forensics | Use dedicated device |
| **Malicious browser extension** | DOM access | Clean browser profile |
| **Compromised OS** | Keylogger, screen capture | Tails OS, air-gap |
| **Malicious recipient** | Screenshot, recording | Social trust boundary |
| **State-level adversary** | Targeted compromise | Use secure OS practices |

---

## 🔐 Cryptographic Architecture

### Core Primitives
- **AES-256-GCM**: Message encryption (96-bit random IVs)
- **ECDH P-256**: Key exchange (uncompressed points)
- **HMAC-SHA256**: IP hashing with secret salt
- **SHA-256**: Fingerprint generation

### Key Management
- **Client-side only**: Keys never leave browser
- **Per-session**: New key pair for each session
- **Ephemeral**: Automatic destruction on session end
- **No persistence**: Never stored in localStorage/indexedDB

### Implementation Security
- **Web Crypto API**: Native browser implementation
- **Constant-time operations**: Prevent timing attacks
- **Unbiased random generation**: Rejection sampling for IDs
- **Forward secrecy**: Compromise of one key doesn't compromise others

---

## 🚨 Attack Scenarios

### Scenario 1: Law Enforcement Subpoena
**Request**: "Provide all messages from session GHOST-XXXX-XXXX"

**Response**: Not possible. Messages are:
1. Never transmitted to servers in plaintext
2. Never stored on servers  
3. Exist only in participants' browser RAM
4. Automatically destroyed on session end

**What CAN be disclosed**:
- Session ID existence and timestamps
- Infrastructure access logs (Netlify/Supabase)
- No message content or user identities

### Scenario 2: Database Breach
**Attacker obtains**: Full database dump

**Attacker learns**:
- Session IDs (random strings, non-identifying)
- Host and guest fingerprints (SHA-256 hashes)
- Truncated IP hashes (16 characters, non-reversible)
- Timestamps

**Attacker CANNOT learn**:
- Message content (never stored)
- Participant identities (no accounts)
- Encryption keys (client-side only)

### Scenario 3: Man-in-the-Middle
**Attacker position**: Between client and server

**What attacker sees**:
- TLS-encrypted WebSocket traffic
- E2E encrypted message payloads (double-encrypted)

**What attacker CANNOT do**:
- Read message content (no keys)
- Inject fake messages (ECDH prevents impersonation)
- Decrypt past sessions (forward secrecy)

---

## 🔧 Security Boundaries

### Boundary 1: Network Transport
**Protected**: Message content, key exchange integrity, session metadata
**NOT Protected**: IP addresses, connection timing, DNS queries
**Mitigation**: Access Ghost via Tor Browser for network anonymity

### Boundary 2: Server Infrastructure  
**Protected**: Message content, encryption keys, message history
**NOT Protected**: Session existence, connection timestamps, public keys
**Note**: Even with full server access, attacker only gets non-identifying metadata

### Boundary 3: Client Device
**Protected**: Disk persistence, post-session recovery, cross-session correlation
**NOT Protected**: Active memory inspection, pre-session keylogging, screen recording
**Mitigation**: Use dedicated device or Tails OS for high-risk communications

---

## 🎯 Operational Security

### Rate Limiting
- **Atomic operations**: PostgreSQL UPSERT prevents race conditions
- **Sliding window**: Time-based rate limiting per IP hash
- **Fail-closed**: Errors block further attempts

### Authentication
- **Bearer tokens**: Required for all privileged endpoints
- **Environment-based**: Production vs. development CORS
- **Fail-closed**: Missing/invalid credentials denied

### Input Validation
- **Strict format validation**: Session IDs, fingerprints, headers
- **Length constraints**: Prevent buffer overflow attacks
- **Type safety**: TypeScript validation throughout

---

## 🐛 Bug Bounty Program

### Reporting Security Issues
**Channel**: [Telegram @ghostdeveloperadmin](https://t.me/ghostdeveloperadmin)  
**Response Time**: Within 72 hours

### ✅ In Scope
- Cryptographic implementation flaws (AES-GCM, ECDH)
- Ephemeral bypasses (messages persisting in disk, cache, or memory)
- Metadata leaks (IP addresses, session IDs, timing)
- MITM in key exchange or fingerprint verification
- PWA/session termination logic flaws
- IP binding bypass or session hijacking across different IPs
- Server-side logging or CORS bypasses
- Rate-limit race conditions or TOCTOU bypasses

### ❌ Out of Scope
- Theoretical issues without proof of concept
- Social engineering
- Spam or DoS attacks
- Issues in third-party dependencies (e.g., React, Tailwind)

### 💰 Bounty Tiers
| Severity | Description | Reward |
|----------|-------------|--------|
| **Critical** | Remote code execution, key recovery, message decryption | $1,000 – $5,000 |
| **High** | Authentication bypass, MITM, session hijacking | $500 – $1,000 |
| **Medium** | Information leakage, UI spoofing, metadata exposure | $100 – $500 |

---

## 🛡️ Security Recommendations

### For Standard Use
- Use Ghost on a personal device you control
- Close session when finished
- Don't discuss Ghost usage in other channels

### For High-Risk Use (journalists, activists, whistleblowers)
1. **Access via Tor Browser** (hides IP address)
2. **Use a dedicated device** (no personal data)
3. **Disable JavaScript extensions** (reduce attack surface)
4. **Verify key fingerprints** out-of-band
5. **Assume physical compromise is possible** (use Tails OS if needed)

### For Maximum Security
- Air-gapped device with Tails OS
- Tor-only network access
- One-time use sessions
- Physical destruction of device if compromised

---

## ⚠️ Limitations & Assumptions

### Cryptographic Assumptions
- **ECDH P-256 is secure** → Key agreement compromise
- **AES-256-GCM is secure** → Message confidentiality loss
- **Web Crypto API is correct** → Implementation bugs
- **TLS 1.3 is secure** → Transport interception
- **Browser sandbox is intact** → Memory isolation failure

### Post-Quantum Considerations
ECDH P-256 is NOT quantum-resistant. A sufficiently powerful quantum computer could compromise key exchange. Post-quantum algorithms planned for future versions.

---

## 📋 What Ghost Is NOT

Ghost is NOT:
- A replacement for Signal, Session, or other persistent messengers
- An anonymity network (use Tor for that)
- Protection against a compromised device
- A guarantee against all surveillance
- "Unhackable" or "unbreakable"

Ghost IS:
- A tool for conversations that should not persist
- Client-side encryption without server trust
- Ephemeral by design, not by policy
- Transparent about its limitations

---

## 📋 Audit Team & Reviewers

### Lead Security Auditors
**Claude 4.5 Sonnet (Anthropic)** - Technical vulnerability assessment, cryptographic validation
**GPT-5 (OpenAI)** - Security architecture review, threat model analysis  
**Lucieran Raven** - Project lead, security architecture oversight, implementation review

### Academic Security Team
**Asia Pacific University (APU)** – Core frontend & cryptographic logic validation
**Sunway University** – PWA architecture security review  
**Taylor's University** – Security audits & session protocol verification
**UNITEN** – Founder & system architecture oversight (Lucieran Raven)

### AI Development Partners
**Qwen (Alibaba Cloud)** – Real-world performance testing & optimization
**Gemini (Google)** – User experience research & interface security
**Cascade AI** – Development process optimization & code quality assurance

### Review Process
All security improvements and architectural decisions are reviewed by:
1. **AI Analysis** - Claude 4.5 Sonnet + GPT-5 perform comprehensive security assessment
2. **Academic Validation** - University team reviews technical implementations
3. **Human Oversight** - Lucieran Raven provides final architecture approval
4. **Collaborative Testing** - Qwen + Gemini provide real-world validation
5. **Quality Assurance** - Cascade AI ensures development process integrity

---

## 📞 Contact & Process

**Security Issues**: [Telegram @ghostdeveloperadmin](https://t.me/ghostdeveloperadmin)
**Public Issues**: DO NOT open security issues publicly
**Response Time**: Within 72 hours
**Responsible Disclosure**: Required, see bounty terms above

---

**Document Version**: 2.0  
**Last Updated**: 2026-01-05  
**Classification**: Public  
**Status**: Production Ready  
**Development Team**: Ghost Privacy Alliance (Academic + AI Collaboration)
