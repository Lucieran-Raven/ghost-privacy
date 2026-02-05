# Ghost Privacy

**Private by design. Ephemeral by default.**  
Available on **Web (PWA)**, **Windows/macOS/Linux (Tauri Desktop)**, and **Android (APK)** — same core, same guarantees.

🔗 **Live App**: https://ghostprivacy.netlify.app/  
📄 **Source Code**: https://github.com/Lucieran-Raven/ghost-privacy  

> [!IMPORTANT]  
> **Network Anonymity**: Ghost does **not hide your IP address** by default. For full network anonymity, access via **Tor Browser**.  
> **Safety Notice**: Ghost is **not designed for active conflict zones** or targeted/state-level adversaries. Read the full threat model in [`SECURITY.md`](SECURITY.md).

---

## What Ghost Is

Ghost is a **browser-native, privacy-focused messaging platform** designed to keep conversation state **in memory** and to avoid *intentional* plaintext persistence. Built for lawyers, doctors, journalists, activists, and anyone who believes some words should not outlive the session.

### Core Guarantees
- **End-to-end encryption** — AES-256-GCM + ECDH P-256 (Web Crypto API)
- **Memory-first design** — Avoids disk-backed browser storage by design; best-effort cleanup/zeroization on session end
- **Zero accounts** — No phone numbers, no emails, no identity correlation
- **Automatic expiration** — Sessions expire; recovery is not supported by the application
- **Open source** — Full codebase available for audit

### What Ghost Does NOT Do
| Limitation | Explanation |
|-----------|-------------|
| **IP addresses visible** | Use Tor Browser for network anonymity |
| **Browser memory not guaranteed** | RAM forensics possible with physical access |
| **No protection against malware** | Keyloggers, screen capture defeat all apps |
| **Recipient can betray you** | Screenshots, recordings are always possible |
| **Not post-quantum secure** | ECDH P-256 will break under quantum computers |

→ **Read the full threat model**: [`SECURITY.md`](SECURITY.md)

---


## 🔐 How Ghost Works 

Here’s what happens when you send a message:

1. **On Your Device**  
   - You type → message encrypted with **AES-256-GCM**  
   - Key derived from **ECDH P-256** (via Web Crypto API)  
   - IV generated → unique per message  
   - Data is handled in memory; the app avoids intentional plaintext persistence  

2. **To Supabase**  
   - Only **ciphertext + metadata** sent (no plaintext, no keys)  
   - Metadata: `session_id`, `capability_token`, `truncated_ip_hash`  
   - **Zero message storage** — relayed then forgotten  

3. **On Recipient’s Device**  
   - Message decrypted using same key  
   - Displayed → vanishes when session ends  
   - No built-in message history; external capture (screenshots/recording) is always possible  

4. **When You Close**  
   - `nuclearPurge()` triggers → zeroize keys, clear queues, kill workers  
   - Session ends → best-effort cleanup/zeroization runs (OS/browser behavior may still leave artifacts outside app control)

> 🧊 **That’s it. No magic. Just math that vanishes.**

                          ▼
                Supabase Edge Functions
                (Ciphertext Relay Only)



- **Encryption**: AES-256-GCM + ECDH P-256 via Web Crypto API
- **Key Derivation**: PBKDF2-SHA256, **600,000 iterations** (OWASP 2023)
- **Session Binding**: Capability tokens + truncated IP hashes (no raw IPs stored)
- **Infrastructure**: Supabase (ciphertext relay; plaintext is not required for server operation)

---

## For High-Risk Users

Journalists, activists, and whistleblowers should:
1. **Access via Tor Browser** — Hides your IP address
2. **Use a dedicated device** — Not your personal phone/laptop
3. **Verify key fingerprints** — Out-of-band confirmation prevents MITM
4. **Assume compromise is possible** — No tool is perfect

> 🧅 **Tor setup guide**: https://ghostprivacy.netlify.app/onion

---

## Documentation

- [`SECURITY.md`](SECURITY.md) — Authoritative security model & bug bounty
- [`ARCHITECTURE.md`](docs/ARCHITECTURE.md) — System design
- [`FORENSIC_CHALLENGE.md`](docs/FORENSIC_CHALLENGE.md) — $50K recovery challenge
- [`CONTRIBUTING.md`](CONTRIBUTING.md) — How to contribute securely
- [`INSTALL_GUIDE.md`](docs/INSTALL_GUIDE.md) — Setup instructions

---

## License & Support

- **License**: GNU AGPL v3.0 ([`LICENSE`](LICENSE))
- **Security Issues**: Report privately via Telegram [@ghostdeveloperadmin](https://t.me/ghostdeveloperadmin)
- **Status**: Production-ready, forensically hardened, open for audit

---

**© 2026 Ghost Privacy. All rights reserved.**  
End-to-end encrypted. No message storage. Built for those who need conversations that never existed.

## Technical Architecture
