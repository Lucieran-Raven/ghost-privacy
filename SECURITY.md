# Security Policy

Ghost is built on a simple promise:  
> **“Conversations don’t just disappear — they never existed in the first place.”**

This isn’t marketing. It’s a mathematical commitment.  
We take security seriously — and we welcome help from the ethical security community.

## 🔍 Supported Versions

Only the **latest public release** (hosted at [https://ghostprivacy.netlify.app/](https://ghostprivacy.netlify.app/)) is in scope.  
Self-hosted or modified versions are **not supported**.

## 📬 Reporting a Vulnerability

**Do not open public GitHub Issues for security bugs.**  
Instead, contact us **privately**:

- **Channel**: [Telegram @ghostdeveloperadmin](https://t.me/ghostdeveloperadmin)  
- **PGP Key**: Not yet published (coming in Q1 2026)  
- **Expected Response Time**: Within **72 hours**

### What to Include
To help us assess quickly, please provide:
- A clear description of the issue  
- Steps to reproduce (with screenshots if helpful)  
- Affected component (e.g., `encryption.ts`, PWA, Supabase RLS)  
- Why it violates Ghost’s “never existed” promise

## 🤝 Our Commitment to You

If you report a **valid, previously unknown vulnerability**:
- We will **acknowledge your report within 3 days**  
- We will **keep you informed** during triage and patching  
- We will **credit you** (with your permission) in release notes  
- Upon launch (Q1 2026), you may be eligible for our **Bug Bounty Program**  

## 🚫 Scope Exclusions

The following are **not considered vulnerabilities**:
- Theoretical issues without practical impact  
- User error (e.g., screenshotting, screen recording)  
- Browser-level attacks (e.g., malicious extensions)  
- Social engineering  
- Issues in third-party services (e.g., Netlify, Supabase infrastructure)

## 📜 Legal Safe Harbor

We consider **good-faith security research** to be:
- Authorized testing of publicly accessible Ghost instances  
- Responsible disclosure via the channels above  

We **will not** initiate legal action against researchers who:
- Make a **good-faith effort** to avoid privacy violations  
- **Do not** demand payment or threaten disclosure  
- **Do not** exploit issues beyond proof-of-concept  

## 🛡️ Current Limitations (Be Aware)

Ghost is **not magic**. We openly document what we **cannot protect**:
- **Network metadata** (IPs visible to relay — use Tor for full anonymity)  
- **Device compromise** (keyloggers, malware)  
- **Browser memory traces** (until garbage collection runs)  
- **Recipient-side recording** (screenshots, another device)  

→ See full details: [Limitations Page](https://ghostprivacy.netlify.app/limitations)

---

Thank you for helping protect the ephemeral.
