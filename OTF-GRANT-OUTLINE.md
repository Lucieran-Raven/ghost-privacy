# Ghost - Open Technology Fund Grant Outline

**Applicant:** LucieRaven (Ghost Project)  
**Funding Request:** $100,000 USD  
**Duration:** 12 months  

---

## Problem Statement

Journalists, activists, lawyers, and human rights defenders worldwide need secure communication channels that:

1. **Leave no trace** — Messages should not exist after the conversation ends
2. **Require no accounts** — Identity correlation enables targeting
3. **Work in browsers** — Native apps are blocked in restrictive environments
4. **Cannot be compelled** — Service providers should have nothing to disclose

Current solutions fail at least one requirement:
- Signal/WhatsApp: Require phone numbers, store message history
- Telegram: Server-side storage, account-based
- Wickr/Session: Native apps, complex setup
- Self-destructing messages: Still stored temporarily, server sees plaintext

**Gap:** No browser-based, zero-knowledge, truly ephemeral messaging platform exists for high-risk users.

---

## Solution: Ghost

Ghost is a browser-based private messaging platform where:

- **Messages exist ONLY in browser RAM** — No server storage, no disk writes
- **End-to-end encryption** — Server never sees plaintext (AES-256-GCM, ECDH P-256)
- **Zero accounts** — Share a session link, no registration
- **Automatic destruction** — Sessions expire, RAM is cleared

### Technical Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        CLIENT A                              │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐     │
│  │ Key Gen     │───▶│ Encrypt     │───▶│ RAM Store   │     │
│  │ (ECDH)      │    │ (AES-GCM)   │    │ (No Disk)   │     │
│  └─────────────┘    └─────────────┘    └─────────────┘     │
└─────────────────────────────────────────────────────────────┘
              │                                   ▲
              │ Public Keys (safe)                │ Ciphertext Only
              ▼                                   │
┌─────────────────────────────────────────────────────────────┐
│                    SUPABASE REALTIME                         │
│           (Sees: session IDs, ciphertext, timestamps)        │
│           (Never sees: plaintext, private keys)              │
└─────────────────────────────────────────────────────────────┘
              │                                   ▲
              │ Public Keys (safe)                │ Ciphertext Only
              ▼                                   │
┌─────────────────────────────────────────────────────────────┐
│                        CLIENT B                              │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐     │
│  │ Key Derive  │───▶│ Decrypt     │───▶│ RAM Store   │     │
│  │ (ECDH)      │    │ (AES-GCM)   │    │ (No Disk)   │     │
│  └─────────────┘    └─────────────┘    └─────────────┘     │
└─────────────────────────────────────────────────────────────┘
```

---

## Why Browser-Based Matters

1. **Accessibility** — Works anywhere with a browser, no app store approval needed
2. **Censorship resistance** — Can be hosted on multiple domains, accessed via Tor
3. **Deployment speed** — Updates deploy instantly, no user action required
4. **Auditability** — Source visible in browser DevTools
5. **Disposability** — Close tab, open new browser—fresh start

### Tor Integration

Ghost is accessible as a Tor Hidden Service, providing:
- IP address anonymity for users
- Censorship circumvention
- Protection against network-level surveillance

---

## Traction

- **Live deployment:** https://ghostprivacy.netlify.app/
- **Open source:** Full codebase on GitHub
- **Student-founded:** Team from APU, Sunway, Taylor's, UNITEN (Malaysia)
- **Self-funded:** Built with zero external capital
- **Community interest:** Organic adoption from privacy-conscious users

---

### Milestones

**Month 1-3:**
- Complete independent security audit
- Publish audit report publicly
- Launch bug bounty program

**Month 4-6:**
- Implement audit recommendations
- Deploy redundant Tor infrastructure
- Translate documentation (Arabic, Farsi, Mandarin, Russian)

**Month 7-12:**
- Research post-quantum key exchange integration
- Expand user documentation
- Pursue additional funding for long-term sustainability

---

## Why OTF?

Ghost aligns with OTF's mission to support:

- **Internet freedom technologies**
- **Tools for journalists and activists**
- **Open-source security software**
- **Censorship circumvention**

Ghost is NOT a commercial product. It's a public good designed to protect those who need ephemeral, secure communication.

---

## Team

**LucieRaven** — Project Lead, Security Architecture  
- Background in privacy engineering, open-source development
- Contact: lucieranraven@gmail.com

**Core Contributors:**
- Students from Asia Pacific University, Sunway, Taylor's, UNITEN
- Volunteers from privacy/security community

---

## Sustainability Plan

**Short-term (Year 1):** OTF grant for audit, infrastructure, bug bounty  
**Medium-term (Years 2-3):** Apply for additional grants (EFF, Mozilla, Access Now)  
**Long-term:** Establish as nonprofit privacy infrastructure with community governance

Ghost will NEVER:
- Monetize user data
- Introduce premium features
- Accept funding with strings attached

---

## Contact

**Project:** Ghost  
**Website:** https://ghostprivacy.netlify.app/  
**Security Contact:** Telegram @ghostdeveloperadmin  
**Email:** lucieranraven@gmail.com  

---

**Document Version:** 1.0  
**Date:** 2025-12-15
