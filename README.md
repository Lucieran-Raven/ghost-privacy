# Ghost

**Private by design. Ephemeral by default.**

Ghost is a browser-based, zero-knowledge messaging platform where conversations exist only in RAM and vanish when you're done.

> **Safe for high-risk use ONLY when accessed via Tor Browser.**

🌐 **Live App:** https://ghostprivacy.netlify.app/  
🧅 **Tor Access:** [Coming Soon]  
📞 **Security Contact:** [Telegram @ghostdeveloperadmin](https://t.me/ghostdeveloperadmin)

---

## What Ghost Does

- **End-to-end encryption** — AES-256-GCM + ECDH P-256, client-side only
- **RAM-only storage** — Messages never touch disk, localStorage, or IndexedDB
- **Zero accounts** — No phone numbers, no emails, no identity correlation
- **Automatic expiration** — Sessions self-destruct, no recovery possible
- **Open source** — Full codebase available for audit

---

## What Ghost Does NOT Do

Ghost is not magic. Be aware of these limitations:

| Limitation | Explanation |
|------------|-------------|
| **IP addresses visible** | Use Tor Browser for network anonymity |
| **Browser memory not guaranteed** | RAM forensics possible with physical access |
| **No protection against malware** | Keyloggers, screen capture defeat all apps |
| **Recipient can betray you** | Screenshots, recordings are always possible |
| **Not post-quantum secure** | ECDH P-256 will break under quantum computers |

**Read the full threat model:** [THREAT-MODEL.md](THREAT-MODEL.md)

---

## For High-Risk Users

Journalists, activists, and whistleblowers should:

1. **Access Ghost via Tor Browser** — Hides your IP address
2. **Use a dedicated device** — Not your personal phone/laptop
3. **Verify key fingerprints** — Out-of-band confirmation prevents MITM
4. **Assume compromise is possible** — No tool is perfect

**Tor setup guide:** https://ghostprivacy.netlify.app/onion

---


## Architecture Overview

| Component | Location | What it Handles | What it Never Sees |
|-----------|----------|-----------------|-------------------|
| **ECDH P-256** | Client | Ephemeral key exchange | Plaintext messages |
| **AES-256-GCM** | Client | Message encryption | Private keys |
| **Client Storage** | RAM only | Temporary session data | Persistent data |
| **Supabase** | Server | Encrypted ciphertext | Plaintext, keys, decrypted data |



**Crypto audit paths:**
- `src/utils/encryption.ts` — Key exchange and symmetric encryption
- `src/utils/clientMessageQueue.ts` — RAM-only message storage
- `src/lib/sessionService.ts` — Edge function communication

See [AUDIT-GUIDE.md](AUDIT-GUIDE.md) for detailed verification steps.

---

## 🚀 Development Approach: Human-Led, AI-Assisted

Ghost was built using a **modern, AI-assisted development workflow** that demonstrates how student teams can achieve enterprise-grade results with limited resources.

### 🤖 AI as Development Accelerator
We leveraged **advanced AI coding assistants** (Claude, Qwen, GPT) as **force multipliers** to:
- **Accelerate implementation** of complex cryptographic functions
- **Ensure code quality** with consistent patterns and error handling
- **Maintain comprehensive documentation** alongside all code
- **Explore multiple architectural approaches** efficiently

### 👨‍💻 Human Leadership & Direction
**Critical human roles included:**
- **Architecture Design**: Core system design and security decisions
- **Code Review & Validation**: Manual review of all AI-generated code
- **Security Oversight**: Human verification of all cryptographic implementations
- **Integration Strategy**: Planning how components work together

### ⚡ The Workflow

Human Architect → Defines requirements & security specs
↓
AI Assistant → Generates implementation options
↓
Human Developer → Reviews, tests, refines code
↓
Security Review → Manual cryptographic validation
↓
Integration → Human-led component assembly


### 🌍 Why This Matters for Global South Innovation
This approach proves that:
- **Resource-constrained teams** can build world-class software
- **AI democratizes development** access beyond wealthy tech hubs
- **Student-led projects** can achieve production-ready quality
- **The future of development** is human-AI collaboration

**Transparency Note**: All AI-generated code underwent rigorous human review, especially for security-critical components like encryption and memory management.

---

## 🎓 Built by Malaysian University Students

Ghost is developed by a **grassroots team of Malaysian university students** passionate about privacy technology. Contributors include computer science and engineering students from:

- **Asia Pacific University (APU)** - Frontend architecture & cryptographic implementation
- **Sunway University** - PWA research & UX optimization  
- **Taylor's University** - Security protocol analysis & testing
- **UNITEN** - System architecture & project coordination

### Why This Matters
- **Global South Perspective**: We build tools for surveillance challenges we understand firsthand
- **Student-Led Innovation**: Demonstrates that world-class privacy tech can come from university students
- **Cross-University Collaboration**: Shows how remote student teams can achieve production-ready results
- **Future Talent Pipeline**: Creates a model for more student-led security projects in Southeast Asia

*Note: This represents the educational backgrounds of individual student contributors, not institutional partnerships.*

---

## 🔬 Applied Research Components

Beyond secure messaging, Ghost incorporates **novel security research instrumentation** that contributes to the broader digital security community.

### Deception-Based Security Research
Ghost includes a **client-side honeypot system** designed to:
- **Study forensic analysis techniques** used by attackers
- **Measure deception effectiveness** through engagement metrics
- **Develop non-alarming psychological traps** that waste attacker resources
- **Generate real-world data** on counter-forensic methods

### Research Capabilities
- **Behavior Tracking**: Monitor how attackers interact with decoy systems
- **Escalation Analysis**: Study progression through threat levels
- **Memory Forensics Research**: Test browser memory analysis techniques
- **Timeline Obfuscation**: Research methods to break forensic correlation

### Research Outputs
Findings from Ghost's research systems contribute to:
- Academic papers on client-side deception
- Improved security training materials
- Enhanced threat models for browser-based tools
- Best practices for ethical honeypot design

**All research is conducted transparently with clear simulation labeling and ethical guidelines.**

---

## 💼 Sustainability Model

Ghost follows an **open-core sustainability model** to ensure long-term viability without compromising its core mission.

### 🔓 Ghost Core (Open Source)
- **License**: GNU AGPL v3.0
- **Status**: Free public good
- **Features**: Complete encryption stack, RAM-only storage, basic UI
- **Access**: Anyone can use, modify, or distribute

### 🛡️ Ghost Guardian (Enterprise)
- **License**: Commercial
- **Status**: For organizations requiring support
- **Features**: Admin dashboards, compliance tooling, managed deployment
- **Purpose**: Generates revenue to fund core development

### Revenue Flow

Enterprise Revenue → Funds → Core Development → Free Public Good


### Commitment to Open Source
- Core privacy technology remains **permanently free and open-source**
- Enterprise features are **add-ons, not core functionality**
- Revenue funds **security audits, research, and maintenance**
- **No user data is ever monetized**

This model ensures Ghost can survive and improve while staying true to its mission of accessible privacy for all.

---

## For Researchers & Students

Ghost is an educational resource for studying:

- Web Crypto API implementation (AES-256-GCM, ECDH P-256)
- Ephemeral memory design patterns
- Privacy-first architecture
- Browser security boundaries
- Human-AI collaborative development models
- Deception-based security research methodologies

**Academic use is encouraged.** Fork, study, critique. Just rename your project.

---

## Security Reporting

**DO NOT open public GitHub issues for security bugs.**

Contact privately:
- **Telegram:** [@ghostdeveloperadmin](https://t.me/ghostdeveloperadmin)
- **Response time:** Within 72 hours

See [SECURITY.md](SECURITY.md) for full disclosure process.

Bug bounty program: Coming Q1 2026

---

## Documentation

| Document | Purpose |
|----------|---------|
| [SECURITY.md](SECURITY.md) | Vulnerability reporting process |
| [AUDIT-GUIDE.md](AUDIT-GUIDE.md) | Step-by-step crypto verification |
| [THREAT-MODEL.md](THREAT-MODEL.md) | What we protect and don't protect |
| [CONTRIBUTING.md](CONTRIBUTING.md) | How to contribute |
| [LICENSE](LICENSE) | GNU AGPL v3.0 |
| [COMMERCIAL_USE_POLICY.md](COMMERCIAL_USE_POLICY.md) | Trademark & commercial use terms |
| [GOVERNANCE.md](GOVERNANCE.md) | Project governance structure |
| [TRADEMARK.md](TRADEMARK.md) | Name and logo policy |

---

## License

Ghost is licensed under the **GNU Affero General Public License v3.0 (AGPL-3.0)**.

- **Permitted**: Any use, including commercial use, with source code sharing requirements
- **Required**: Derivatives must remain open-source under AGPL-3.0
- **Attribution**: Must credit original project

See [LICENSE](LICENSE) for full terms and [COMMERCIAL_USE_POLICY.md](COMMERCIAL_USE_POLICY.md) for trademark information.

---

## Support the Project

Ghost is a public good, not a product. If you believe in privacy:

- ⭐ Star this repository
- 🔍 Audit our code
- 🐛 Report vulnerabilities responsibly
- 📢 Share with those who need it

---

**© 2025 Lucieran Raven. All rights reserved.**

End-to-end encrypted. No message storage. Built for those who need conversations that never existed.



## Technical Architecture
