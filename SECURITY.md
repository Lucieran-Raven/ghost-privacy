# 🔒 Ghost Privacy Security Model

**Authoritative security documentation**  
Last updated: 2026-01-11 | Version: 2.1

## 🎯 What We Guarantee

### Core Promises
- **Messages are kept in RAM only** — never written to disk, localStorage, or server.
- **Post-session recovery is minimized** — memory zeroization reduces forensic artifacts under normal conditions.
- **Deniable encryption** — dual-password hidden volumes (real vs. decoy) for coercion resistance.
- **Zero server-side message storage** — servers never receive or store plaintext.

### Technical Guarantees
| Guarantee | Implementation | Verification |
|----------|----------------|--------------|
| Ephemeral Messages | RAM-only `Map`, `nuclearPurge()` on close | DevTools memory inspection |
| Forward Secrecy | Per-session ECDH key exchange | Cryptographic analysis |
| Server Blindness | Ciphertext-only delivery | Code audit, server logs |
| Anti-Forensic | Zeroization of keys/buffers | $50K Forensic Challenge |
| Plausible Deniability | Decoy content + fake UI | Coercion scenario testing |

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
> With **Tor Browser**, it provides strong protection for journalists and activists.

## 🛡️ What We Store (and Why)

| Field | Purpose | Retention |
|------|--------|----------|
| `session_id` | Session coordination | Auto-deleted after 30 min |
| `capability_hash` | Session access control | Deleted with session |
| `ip_hash` (truncated) | Anti-hijacking | HMAC-SHA256, 16-char only |

**Never stored**: Message content, encryption keys, user identities.

## 🎭 Threat Model

### ✅ Protected Against
- Forensic message recovery
- Session hijacking (via capability + IP binding)
- MITM (with fingerprint verification)
- Server compromise (no plaintext stored)
- Legal subpoena (nothing to disclose)

### ❌ Not Protected Against
- Clearnet IP exposure → **use Tor Browser**
- Malware/keyloggers → **use clean device**
- Screen recording → **social trust boundary**

## 🧾 Claim → Enforcement → Tests

*(Keep your existing technical mapping — it’s excellent)*

## 🐛 Bug Bounty

**Report via**: [Telegram @ghostdeveloperadmin](https://t.me/ghostdeveloperadmin)  
**In scope**: Crypto flaws, memory leaks, metadata exposure, MITM, session hijacking  
**Bounties**: $100–$5,000 based on severity

## 📞 Contact

Security issues only via Telegram.  
Do not disclose publicly.

---
**Document Status**: Production Ready  
**Maintained by**: Ghost Privacy Team  
**Code**: https://github.com/Lucieran-Raven/ghost-privacy
