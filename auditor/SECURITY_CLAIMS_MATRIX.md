# Security Claims Matrix

This matrix documents *externally visible* security/privacy claims and maps them to:

- **Actual technical guarantee** (what the code is designed to do)
- **Caveats / limitations** (what is not guaranteed)
- **Evidence / references** (files/tests an auditor can inspect)

> Scope note: This project is a privacy-focused application and makes **best-effort** anti-forensic/ephemeral claims. OS, browser, and platform layers may create artifacts outside application control.

| Claim (external wording) | Actual technical guarantee | Caveats / limitations | Evidence / references |
|---|---|---|---|
| End-to-end encryption | Messages are encrypted/decrypted client-side using Web Crypto primitives (AES-GCM) with session keys derived from ECDH P-256. | First-contact integrity depends on key verification; compromised endpoints defeat E2EE. | `src/utils/algorithms/encryption/ephemeral.ts`, `src/utils/encryption.ts`, `src/components/Ghost/ChatInterface.tsx` |
| Server does not need plaintext | Backend is designed to relay ciphertext; plaintext is not required for server operation. | Infrastructure can still log metadata (IP/timing); server compromise can still affect availability. | `src/lib/realtimeManager.ts`, `supabase/functions/*`, `SECURITY.md` |
| Memory-first / RAM-only by design | Application avoids intentional persistence of plaintext messages/keys using disk-backed browser storage primitives. | Browsers/OS may page memory, crash-dump, or retain traces until GC; screenshots/recording are always possible. | `src/utils/clientMessageQueue.ts`, `src/utils/sessionKeyManager.ts`, `src/test/forensicArtifacts.test.ts`, `SECURITY.md` |
| Session cleanup / nuclear purge | On explicit session end, in-memory queues and keys are destroyed and best-effort zeroization is performed. | Best-effort: JS engines may copy/relocate strings/buffers; no guarantee of complete artifact removal. | `src/components/Ghost/ChatInterface.tsx` (`destroyLocalSessionData`, `handleEndSession`, `handleNuclearPurge`), `src/utils/algorithms/memory/zeroization.ts` |
| Replay protection | Incoming realtime frames are checked for nonce replays and malformed frames are rejected. | Replay protection is bounded by retention window and memory constraints; does not protect against fully compromised peers. | `src/utils/replayProtection.ts`, `src/utils/algorithms/integrity/replay.ts`, `src/lib/realtimeManager.ts`, `src/lib/realtimeManager.test.ts` |
| RNG is cryptographically strong | Security-critical randomness uses `crypto.getRandomValues` and fails closed if unavailable. | Best-effort randomness exists for decoy/UX only and must not be used for cryptography. | `src/utils/secureRng.ts` |
| Clearnet IP is not hidden | App does not provide network anonymity by itself; Tor Browser is recommended for IP anonymity. | Tor usage is an operational/user choice; hosting providers may still observe connection metadata. | `README.md`, `SECURITY.md`, `src/components/Ghost/ClearnetWarning.tsx` |
| No accounts / minimal identifiers | No username/password/email/phone number accounts are required for session usage. | Network metadata and device identifiers may still exist at platform level; users can still self-identify via message content. | `src/components/Ghost/SessionCreator.tsx`, `supabase/functions/create-session/*`, `SECURITY.md` |

## How to verify

- Run:
  - `npm test`
  - `npm run integrity`
- Review:
  - `auditor/SECURITY_CONTROLS.md`
  - `SECURITY.md`

## Change control

Any change that affects the semantics of a claim above should update:

- This matrix
- `README.md` and `SECURITY.md`
- Relevant tests (especially `src/test/forensicArtifacts.test.ts` and layer side-channel tests)
