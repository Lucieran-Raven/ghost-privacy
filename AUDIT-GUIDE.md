# Ghost Audit Guide

**For Independent Security Researchers and Cryptographers**

This document provides a step-by-step verification path for auditing Ghost's cryptographic implementation and privacy guarantees.

---

## Audit Scope

Ghost's core security claims:
1. End-to-end encryption with forward secrecy
2. RAM-only message storage (no persistence)
3. Zero server-side message access
4. Ephemeral sessions with automatic expiration

---

## 1. Key Exchange Verification

**File:** `src/utils/encryption.ts`

### ECDH P-256 Key Agreement

```
Lines 76-112: KeyExchange class
```

**Verification Steps:**

1. Confirm `generateKeyPair()` uses ECDH with P-256 curve
2. Verify keys are generated client-side via Web Crypto API
3. Check that private keys are never exported or transmitted
4. Confirm `deriveSharedSecret()` produces AES-256-GCM keys

**Expected Behavior:**
- Each session generates a fresh ECDH key pair
- Public keys are exchanged via Supabase Realtime (encrypted channel not required—public keys are safe to expose)
- Shared secret is derived independently on both clients
- No private key material leaves the browser

**Audit Command:**
```javascript
// In browser console during active session:
// Verify key derivation produces identical secrets on both ends
// by comparing encrypted/decrypted message integrity
```

---

## 2. Symmetric Encryption Verification

**File:** `src/utils/encryption.ts`

### AES-256-GCM Message Encryption

```
Lines 4-73: EncryptionEngine class
```

**Verification Steps:**

1. Confirm `generateKey()` creates AES-256-GCM keys
2. Verify `encryptMessage()` uses a fresh 12-byte IV per message
3. Check that IVs are generated via `crypto.getRandomValues()`
4. Confirm authentication tag is included (GCM mode)

**Security Properties:**
- 256-bit key length
- 96-bit IV (12 bytes) per message
- Authenticated encryption (prevents tampering)
- IV uniqueness prevents nonce reuse attacks

**Warning:** GCM mode MUST NOT reuse IV+key combinations. Ghost generates a fresh IV per message.

---

## 3. Session ID Generation

**File:** `src/utils/encryption.ts`

### Cryptographic Session IDs

```
Lines 146-155: generateGhostId()
```

**Verification Steps:**

1. Confirm 64 bits of entropy from `crypto.getRandomValues()`
2. Verify format: `GHOST-XXXX-XXXX` (alphanumeric)
3. Check collision probability is acceptably low

**Entropy Analysis:**
- 8 bytes = 64 bits of randomness
- Mapped to 36-character alphabet (A-Z, 0-9)
- Effective entropy: ~41 bits per 8-character segment
- Collision probability at 1M sessions: negligible

---

## 4. RAM-Only Storage Verification

**File:** `src/utils/clientMessageQueue.ts`

### Memory Isolation Guarantees

**Verification Steps:**

1. Confirm `ClientMessageQueue` uses JavaScript `Map` only
2. Verify NO calls to:
   - `localStorage`
   - `sessionStorage`
   - `IndexedDB`
   - `document.cookie`
   - `Cache API`
3. Check `destroySession()` overwrites content before deletion
4. Verify `nuclearPurge()` clears all references

**Forensic Properties:**
- Messages exist in browser heap memory only
- Session termination triggers content overwrite
- Garbage collection hints are provided (not guaranteed)
- No persistence APIs are invoked

**Limitation:** Browser memory is not under application control. Forensic recovery of RAM is possible with physical device access. This is an acknowledged limitation, not a bug.

---

## 5. Server-Side Non-Storage Verification

**File:** `src/lib/sessionService.ts`

### Edge Function Architecture

**Verification Steps:**

1. Confirm client NEVER directly accesses database tables
2. Verify all DB operations go through Edge Functions
3. Check Edge Functions store ONLY:
   - Session IDs
   - Host fingerprints
   - Expiration timestamps
4. Confirm NO message content is transmitted to server

**Edge Functions to Audit:**
- `supabase/functions/create-session/index.ts`
- `supabase/functions/validate-session/index.ts`
- `supabase/functions/extend-session/index.ts`
- `supabase/functions/delete-session/index.ts`
- `supabase/functions/cleanup-sessions/index.ts`

**Database Schema:**
```sql
ghost_sessions (
  id UUID PRIMARY KEY,
  session_id TEXT UNIQUE,
  host_fingerprint TEXT,
  created_at TIMESTAMP,
  expires_at TIMESTAMP
)
```

NO `message_content`, `encrypted_data`, or similar columns exist.

---

## 6. Realtime Message Flow

**File:** `src/lib/realtimeManager.ts`

### WebSocket Message Routing

**Verification Steps:**

1. Confirm messages are encrypted BEFORE transmission
2. Verify decryption occurs AFTER reception
3. Check that Supabase Realtime sees only ciphertext
4. Confirm no plaintext is logged or stored server-side

**Data Flow:**
```
Sender:
  plaintext → AES-256-GCM encrypt → ciphertext → WebSocket → Supabase Realtime

Receiver:
  Supabase Realtime → WebSocket → ciphertext → AES-256-GCM decrypt → plaintext → RAM
```

---

## 7. Known Limitations (Not Bugs)

Ghost explicitly does NOT protect against:

| Threat | Reason |
|--------|--------|
| Network metadata (IP addresses) | Use Tor for anonymity |
| Browser memory forensics | Beyond application control |
| Malicious browser extensions | Sandbox violation |
| Device keyloggers | OS-level compromise |
| Screenshot/recording by recipient | Social trust boundary |
| Quantum computing attacks | P-256 is not post-quantum |

These are **design boundaries**, not vulnerabilities.

---

## 8. Audit Checklist

### Cryptographic Implementation
- [ ] ECDH P-256 key pairs generated correctly
- [ ] AES-256-GCM encryption with fresh IVs
- [ ] No IV reuse possible
- [ ] Authentication tags verified
- [ ] Keys derived from shared secret properly

### Memory Safety
- [ ] No localStorage/sessionStorage usage
- [ ] No IndexedDB usage
- [ ] No cookie storage of messages
- [ ] Content overwritten before deletion
- [ ] References nullified post-destruction

### Server Isolation
- [ ] No message content in database schema
- [ ] Edge Functions return metadata only
- [ ] Realtime channel sees ciphertext only
- [ ] Session cleanup removes all traces

### Browser Environment
- [ ] Web Crypto API used exclusively
- [ ] No custom crypto implementations
- [ ] No eval() or dynamic code execution
- [ ] CSP headers restrict script sources

---

## 9. Reporting Issues

If you discover a vulnerability:

1. **DO NOT** open a public GitHub issue
2. Contact: [Telegram @ghostdeveloperadmin](https://t.me/ghostdeveloperadmin)
3. Allow 72 hours for initial response
4. Coordinate disclosure timeline

See [SECURITY.md](SECURITY.md) for full reporting guidelines.

---

## 10. Verification Tools

### Browser DevTools
```javascript
// Check no storage APIs used
console.log('localStorage:', localStorage.length);
console.log('sessionStorage:', sessionStorage.length);
indexedDB.databases().then(dbs => console.log('IndexedDB:', dbs));
```

### Network Inspection
- Use browser DevTools Network tab
- Filter WebSocket frames
- Verify all message payloads are base64 ciphertext

### Source Code Audit
- Full source available at: https://github.com/[your-repo]/ghost
- Build from source to verify deployed code matches

---

**Document Version:** 1.0  
**Last Updated:** 2025-12-15  
**Maintainer:** Ghost Security Team
