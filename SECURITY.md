# 🔒 Ghost Privacy Security Model

**Authoritative security documentation**  
Last updated: 2026-01-11 | Version: 2.1

## 🎯 What We Guarantee

### Core Promises
- **No intentional plaintext persistence** — Ghost does not intentionally write plaintext messages or raw keys to disk or to the server; encryption/decryption is performed in memory.
- **Best-effort post-session cleanup** — in-app zeroization reduces recoverability under normal conditions; OS/browser behavior can still create artifacts outside application control.
- **Plausible deniability (UI/decoy modes)** — optional decoy/simulation features may reduce immediate suspicion, but Ghost does not claim cryptographic deniable encryption.
- **No server-side plaintext by design** — plaintext messages and private keys are not required for server operation; servers are intended to handle ciphertext and minimal session metadata.

### Technical Guarantees
| Guarantee | Implementation | Verification |
|----------|----------------|--------------|
| Ephemeral Key Exchange | In-memory `Map`, `nuclearPurge()` on close (best-effort cleanup) | DevTools memory inspection |
| Forward Secrecy | Per-session ECDH key exchange | Cryptographic analysis |
| Server Blindness | Ciphertext-only delivery | Code audit, server logs |
| Anti-Forensic | Best-effort zeroization of keys/buffers + regression tests against disk persistence primitives | Code audit + `src/test/forensicArtifacts.test.ts` |
| Plausible Deniability | Optional decoy/simulation UI (when enabled) | Coercion scenario testing |

### Platform Parity
Ghost delivers identical security across all platforms:
- **Web (PWA)**: Runs in browser with aggressive cleanup
- **Desktop (Tauri)**: Dedicated OS process, no extensions, strict CSP
- **Android (Capacitor)**: Isolated app sandbox, no Play Store telemetry

All share the same security-critical core (`src/utils/algorithms/`) — no drift.

## ⚠️ Limits & Assumptions

### Assumptions
- Runs on non-compromised OS/browser
- No malicious extensions with DOM access
- Device not monitored by malware

### Known Limitations
- **OS swap/crash dumps**: May page memory to disk (outside app control)
- **RAM forensics**: Cold-boot attacks possible with physical access
- **Recipient risk**: Screenshots, recording by chat partner
- **Infrastructure logs**: Netlify/Supabase may log request metadata (not message content)

### Network Anonymity
- **Clearnet exposes IP** — always use **Tor Browser** for anonymity
- **.onion service pending deployment** (funding required)

> 💡 **Ghost is designed to protect against state-level device seizure.**  
> Ghost is designed to *reduce* post-session recoverability through a memory-first architecture and best-effort cleanup, but it does **not** guarantee resistance to all forensic methods. For network anonymity, use **Tor Browser**.

## 🛡️ What We Store (and Why)

| Field | Purpose | Retention |
|------|--------|----------|
| `session_id` | Session coordination | Expires after 10 min (extendable) |
| `capability_hash` | Session access control | Rotated on delete, expires with session |
| `ip_hash` | Rate limiting | HMAC-SHA256, stored in `rate_limits` only |

Pinned in-memory: Partner public-key fingerprints (TOFU) used to detect key changes during the session.

**Not intended to be stored (by Ghost application design)**: Message content, raw encryption keys, user identities.

## 🎭 Threat Model

### Threat actors
- **Law enforcement (LEO) / legal compulsion**: subpoenas, warrants, device seizure.
- **Cloud provider / platform operator**: hosting/CDN/Supabase operators and their logs.
- **Network attacker**: passive metadata collection and active MITM attempts.
- **Malware / compromised client**: keyloggers, screen capture, memory inspection.
- **Insider**: malicious maintainer, compromised build pipeline, dependency supply chain.
- **User error**: sharing access codes, failing to verify fingerprints, unsafe device practices.
- **Counterparty risk**: recipient screenshots/recording/social engineering.

### Deniable vs verifiable
- **Verifiable properties (we can meaningfully audit)**:
  - Server-side plaintext is not required for operation, and Ghost is designed for ciphertext-only delivery.
  - The application avoids intentional persistence of plaintext and raw keys (see disk rules below).
  - Security-critical claims are mapped to code and tests (see `auditor/SECURITY_CONTROLS.md`).
- **Deniability scope (limited)**:
  - Ghost does not claim cryptographic deniable encryption.
  - Any decoy/simulation behavior is optional and documented (see `docs/ETHICS_OPTOUT.md`).

### Cryptographic trust boundaries
- **Client device is the trust anchor**: keys are generated and used on the client.
- **Server is untrusted for confidentiality**: it may be observed/compromised without revealing plaintext.
- **First-contact key exchange is the main integrity risk**: if fingerprints are not verified out-of-band, a network attacker can attempt a MITM.

### What must never hit disk (by design)
Ghost treats the following as **must not be intentionally persisted** (no logs, no browser storage, no filesystem writes, no analytics payloads):
- Plaintext messages.
- Raw session keys / shared secrets / private keys.
- Capability tokens / access codes.

This is enforced by policy and by regression tests that fail the build if disk persistence primitives are reintroduced (see `src/test/forensicArtifacts.test.ts`).

### Failure policy (fail-closed vs fail-open)
- **Fail-closed**:
  - Session create/join/extend/delete without a valid capability token.
  - Encryption/decryption errors (do not send; do not display corrupted plaintext).
  - Rate limiting enforcement failures (prefer blocking over bypass).
- **Fail-open (best-effort)**:
  - Memory cleanup/zeroization routines: the session should still terminate even if cleanup is partial; limitations are documented.

### ✅ Protected Against
- **Post-session recovery from Ghost-controlled persistence paths** (memory-first design; best-effort cleanup)
- **Session hijacking** (unguessable capability token + unguessable channel name)
- **MITM** (when fingerprints are verified or pinned)
- **Server compromise** (no plaintext stored)
- **Legal subpoena for message content** (no message content to disclose from Ghost servers)

> ⚠️ **High-risk conversations:** Always verify fingerprints out-of-band (phone/in-person). Pinning detects later changes during the session, but first contact is only as safe as your verification.

### ❌ Not Protected Against
- **Clearnet IP exposure** → **use Tor Browser**
- **Malware/keyloggers** → **use clean device**
- **Screen recording** → **social trust boundary**

## 🧾 Key Fixes Implemented

- **Voice encryption**: No key export in `src/utils/algorithms/encryption/voice.ts`  
- **IP hashing**: HMAC-based IP hashing used for rate limiting (no session IP binding)  
- **Non-extractable keys**: ECDH shared secrets are used client-side and are not intended to be persisted or exported by Ghost  
- **Replay suppression**: Drops duplicate `(senderId, nonce)`  
- **File transfer hardening**: Caps on chunks, size, metadata  
- **UI artifact reduction**: Revokes object URLs, clipboard auto-clear  
- **Build integrity checks**: `npm run integrity` verifies repository integrity inputs prior to release  

## 🧪 Claim → Enforcement → Tests

### Capability token required for session access
- **Frontend**: `src/components/Ghost/SessionCreator.tsx`, `src/utils/algorithms/session/accessCode.ts`  
- **Backend**: `supabase/functions/validate-session/index.ts`, `supabase/functions/extend-session/index.ts`, `supabase/functions/delete-session/index.ts`  
- **Tests**: `src/utils/algorithms/session/accessCode.test.ts`

### Token-derived realtime channels
- **Implementation**: `src/utils/algorithms/session/realtimeChannel.ts`, `src/lib/realtimeManager.ts`  
- **Tests**: `src/utils/algorithms/session/realtimeChannel.test.ts`

### IP hashing (rate limiting)
Ghost currently uses client IP hashing for rate limiting. Session authorization is enforced via the capability token.

- **Shared**: `supabase/functions/_shared/security.ts` → `getClientIpHashHex`  
- **Enforcement**: `supabase/functions/create-session/index.ts` → rate limiting via `increment_rate_limit`  

### Desktop CSP hardening
- **Config**: `src-tauri/tauri.conf.json`

### Memory-first guarantees
- **Core**: `src/utils/clientMessageQueue.ts`, `src/utils/sessionKeyManager.ts`

## 🧪 Transparent Deception & Research Layer

Ghost includes clearly labeled decoy and simulation components used for user safety and research transparency.

- **What it does**: Presents decoy content and simulation UI to support plausible deniability  
- **What it does not do**:  
  - Does not collect or store user message content  
  - Does not collect or transmit user identity data  
  - Does not add telemetry/analytics  

If any research telemetry is introduced in the future, it must be:  
- Explicitly opt-in  
- Non-identifying  
- Documented here  

## 🔐 Cryptographic Architecture

### Core Primitives
- **AES-256-GCM**: Message encryption (96-bit random IVs)
- **ECDH P-256**: Key exchange (uncompressed points)
- **HMAC-SHA256**: IP hashing with secret salt
- **SHA-256**: Fingerprint generation

### Key Management
- **Client-side only**: Keys are generated and used on the client; the system is designed so servers do not require access to raw keys
- **Per-session**: New key pair for each session
- **Ephemeral**: Cleared on session end (best-effort cleanup; OS/browser behavior may still create artifacts outside app control)
- **No intentional persistence**: Not intended to be stored in disk-backed browser storage

### Implementation Security
- **Web Crypto API**: Native browser implementation
- **Constant-time operations**: Prevent timing attacks
- **Unbiased random generation**: Rejection sampling for IDs
- **Forward secrecy**: Compromise of one key doesn't compromise others

## 🚨 Attack Scenarios

### Scenario 1: Law Enforcement Subpoena
**Request**: "Provide all messages from session GHOST-XXXX-XXXX"  
**Response**: Ghost servers are not designed to provide plaintext message history. Messages are:  
- Not intended to be transmitted to servers in plaintext  
- Not intended to be stored on servers (ciphertext relay design)  
- Handled on participant devices in memory during the session (best-effort cleanup applies)  
- Cleared on session end (best-effort; OS/browser behavior may still create artifacts outside app control)  

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

**Attacker is not expected to learn (from Ghost-controlled server storage paths)**:  
- Message content (not intended to be stored)  
- Participant identities (no accounts)  
- Encryption keys (client-side only)  

### Scenario 3: Man-in-the-Middle
**Attacker position**: Between client and server  
**What attacker sees**:  
- TLS-encrypted WebSocket traffic  
- E2E encrypted message payloads (double-encrypted)  

**What attacker is not expected to do (assuming endpoint integrity and verified keys)**:  
- Read message content (no keys)  
- Inject fake messages (ECDH prevents impersonation)  
- Decrypt past sessions (forward secrecy)  

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

## 🐛 Bug Bounty Program

**Reporting Security Issues**  
**Channel**: [Telegram @ghostdeveloperadmin](https://t.me/ghostdeveloperadmin)  
**Response Time**: Within 72 hours

### ✅ In Scope
- Cryptographic implementation flaws (AES-GCM, ECDH)
- Ephemeral bypasses (messages persisting in disk, cache, or memory)
- Metadata leaks (IP addresses, session IDs, timing)
- MITM in key exchange or fingerprint verification
- PWA/session termination logic flaws
- Session hijacking (including cases triggered by network changes)
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

## ⚠️ Limitations & Assumptions

### Cryptographic Assumptions
- **ECDH P-256 is secure** → Key agreement compromise
- **AES-256-GCM is secure** → Message confidentiality loss
- **Web Crypto API is correct** → Implementation bugs
- **TLS 1.3 is secure** → Transport interception
- **Browser sandbox is intact** → Memory isolation failure

### Post-Quantum Considerations
ECDH P-256 is NOT quantum-resistant. A sufficiently powerful quantum computer could compromise key exchange. Post-quantum algorithms planned for future versions.

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

## 📞 Contact & Process

**Security Issues**: [Telegram @ghostdeveloperadmin](https://t.me/ghostdeveloperadmin)  
**Public Issues**: DO NOT open security issues publicly  
**Response Time**: Within 72 hours  
**Responsible Disclosure**: Required, see bounty terms above

---
**Document Status**: Production Ready  
**Maintained by**: Ghost Privacy Team  
**Code**: https://github.com/Lucieran-Raven/ghost-privacy
