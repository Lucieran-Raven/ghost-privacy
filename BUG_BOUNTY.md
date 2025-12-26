# Ghost Bug Bounty Program

## 🚧 Status: COMING SOON (Q1 2026)

Ghost is actively raising funds via community donations to launch a formal bug bounty program. Until then, we rely on the ethical security community to help us stay safe.

## 🔍 Report Vulnerabilities

**Channel**: [Telegram @ghostdeveloperadmin](https://t.me/ghostdeveloperadmin)  
**Response Time**: Within 72 hours

### ✅ In Scope
- Cryptographic implementation flaws (AES-GCM, ECDH)
- Ephemeral bypasses (messages persisting in disk, cache, or memory)
- Metadata leaks (IP addresses, session IDs, timing)
- MITM in key exchange or fingerprint verification
- PWA/session termination logic flaws

### ❌ Out of Scope
- Theoretical issues without proof of concept
- Social engineering
- Spam or DoS attacks
- Issues in third-party dependencies (e.g., React, Tailwind)

## 💰 Future Bounty Tiers (Upon Launch)

| Severity | Description | Reward |
|----------|-------------|--------|
| **Critical** | Remote code execution, key recovery, message decryption | $1,000 – $5,000 |
| **High** | Authentication bypass, MITM, session hijacking | $500 – $1,000 |
| **Medium** | Information leakage, UI spoofing, metadata exposure | $100 – $500 |

> 💡 This program will be **funded entirely by community donations**.  
> Support Ghost: [https://ghostprivacy.netlify.app/contribute](https://ghostprivacy.netlify.app/contribute)

## 🤝 Responsible Disclosure

1. **Do not** disclose publicly before coordination
2. **Do not** exploit vulnerabilities beyond proof of concept
3. **Do not** access/modify data beyond what’s needed to verify

We honor **ethical researchers** who help protect Ghost’s users.

---

Thank you for defending the ephemeral.
