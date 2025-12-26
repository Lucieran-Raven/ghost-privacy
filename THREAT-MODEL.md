# Ghost Threat Model

**Explicit Protections and Acknowledged Limitations**

This document defines what Ghost protects against, what it does NOT protect against, and the reasoning behind each boundary.

---

## Design Philosophy

Ghost operates on a single principle:

> **Messages should not exist after they're no longer needed.**

This is achieved through:
1. Client-side encryption (server never sees plaintext)
2. RAM-only storage (no disk persistence)
3. Ephemeral sessions (automatic expiration)
4. Zero accounts (no identity correlation)

---

## Threat Actors

### Ghost IS designed to protect against:

| Actor | Attack Vector | Protection |
|-------|---------------|------------|
| **Passive network observer** | Traffic interception | TLS + E2E encryption |
| **Curious service provider** | Server-side logging | Zero server-side plaintext |
| **Subpoena/legal demand** | Data disclosure order | No stored messages to disclose |
| **Database breach** | Stolen session data | Only session IDs stored |
| **Session hijacking** | Stolen session link | Fingerprint binding + expiration |
| **Replay attacks** | Message duplication | Unique IVs + timestamps |

### Ghost is NOT designed to protect against:

| Actor | Attack Vector | Why Not Protected |
|-------|---------------|-------------------|
| **ISP/Network admin** | IP address logging | Use Tor—Ghost cannot hide network metadata |
| **Physical device access** | RAM forensics | Browser memory is not application-controllable |
| **Malicious browser extension** | DOM access | Sandbox violation—use a clean browser profile |
| **Compromised OS** | Keylogger, screen capture | OS-level compromise defeats all apps |
| **Malicious recipient** | Screenshot, recording | Social trust boundary—Ghost cannot stop betrayal |
| **State-level adversary** | Targeted device compromise | Use Tails OS, air-gapped systems |
| **Quantum computers** | ECDH key recovery | P-256 is not post-quantum resistant |

---

## Security Boundaries

### Boundary 1: Network Transport

**Protected:**
- Message content (E2E encrypted)
- Key exchange integrity (ECDH)
- Session metadata confidentiality (TLS)

**NOT Protected:**
- IP addresses (visible to ISP, server infrastructure)
- Connection timing/frequency (metadata analysis)
- DNS queries (without DoH/DoT)

**Mitigation:** Access Ghost via Tor Browser for network anonymity.

### Boundary 2: Server Infrastructure

**Protected:**
- Message content (never transmitted in plaintext)
- Encryption keys (never leave client)
- Message history (not stored)

**NOT Protected:**
- Session existence (session IDs are stored)
- Connection timestamps (infrastructure logs)
- Public keys (exchanged via server)

**Note:** Even with full server access, an attacker obtains only:
- Session IDs
- Expiration timestamps
- Host fingerprints (browser-derived, not personally identifiable)

### Boundary 3: Client Device

**Protected:**
- Disk persistence (no storage APIs used)
- Post-session recovery (RAM cleared on termination)
- Cross-session correlation (no persistent identifiers)

**NOT Protected:**
- Active memory inspection (debugger, RAM dump)
- Pre-session keylogging (input capture)
- Screen recording (OS-level capture)

**Mitigation:** Use a dedicated device or Tails OS for high-risk communications.

### Boundary 4: Browser Environment

**Protected:**
- Cross-origin access (same-origin policy)
- Script injection (CSP headers)
- Storage pollution (no persistence APIs)

**NOT Protected:**
- Malicious extensions (full DOM access)
- Browser vulnerabilities (0-days)
- DevTools inspection (user-initiated)

**Mitigation:** Use a clean browser profile with no extensions.

---

## Attack Scenarios

### Scenario 1: Law Enforcement Subpoena

**Request:** "Provide all messages from session GHOST-XXXX-XXXX"

**Response:** Not possible. Messages are:
1. Never transmitted to servers in plaintext
2. Never stored on servers
3. Exist only in participants' browser RAM
4. Automatically destroyed on session end

**What CAN be disclosed:**
- Session ID existence
- Session creation/expiration timestamps
- Infrastructure access logs (Netlify/Supabase)

### Scenario 2: Database Breach

**Attacker obtains:** Full database dump

**Attacker learns:**
- Session IDs (random strings)
- Host fingerprints (SHA-256 of browser properties)
- Timestamps

**Attacker CANNOT learn:**
- Message content (never stored)
- Participant identities (no accounts)
- Encryption keys (client-side only)

### Scenario 3: Man-in-the-Middle

**Attacker position:** Between client and server

**What attacker sees:**
- TLS-encrypted WebSocket traffic
- E2E encrypted message payloads (double-encrypted)

**What attacker can do:**
- Block messages (denial of service)
- Observe connection timing

**What attacker CANNOT do:**
- Read message content (no keys)
- Inject fake messages (ECDH prevents impersonation)
- Decrypt past sessions (forward secrecy)

### Scenario 4: Compromised Recipient

**Malicious partner:** Screenshots conversation

**Ghost response:** This is outside our threat model.

Ghost protects the **technical channel**, not the **social trust** between participants. If your conversation partner is an adversary, no technology can help.

---

## Cryptographic Assumptions

Ghost's security depends on:

| Assumption | Failure Impact |
|------------|----------------|
| ECDH P-256 is secure | Key agreement compromise |
| AES-256-GCM is secure | Message confidentiality loss |
| Web Crypto API is correct | Implementation bugs |
| TLS 1.3 is secure | Transport interception |
| Browser sandbox is intact | Memory isolation failure |

### Post-Quantum Considerations

ECDH P-256 is NOT quantum-resistant. A sufficiently powerful quantum computer could:
1. Recover private keys from public keys
2. Decrypt all messages encrypted with derived secrets

**Mitigation timeline:** Post-quantum key exchange (e.g., Kyber) is planned for future versions.

---

## Operational Security Recommendations

### For Standard Use
- Use Ghost on a personal device you control
- Close the session when finished
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

## What Ghost Is NOT

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

## Reporting Security Issues

If you identify a flaw in this threat model or a vulnerability in the implementation:

1. **DO NOT** open a public issue
2. Contact: [Telegram @ghostdeveloperadmin](https://t.me/ghostdeveloperadmin)
3. See [SECURITY.md](SECURITY.md) for full process

---

**Document Version:** 1.0  
**Last Updated:** 2025-12-15  
**Classification:** Public
