import { Shield, CheckCircle, AlertTriangle, ExternalLink, Mail, Bug, DollarSign, Mic } from 'lucide-react';
import { Link } from 'react-router-dom';
import Navbar from '@/components/Ghost/Navbar';
import Footer from '@/components/Ghost/Footer';

const Limitations = () => {
  return (
    <div className="min-h-screen bg-background">
      <Navbar />
      
      <main className="pt-24 pb-12">
        <div className="container mx-auto px-4">
          {/* Header */}
          <div className="max-w-4xl mx-auto text-center mb-16">
            <div className="inline-flex items-center gap-2 px-4 py-2 rounded-full glass border border-yellow-500/30 mb-6">
              <AlertTriangle className="h-4 w-4 text-yellow-500" />
              <span className="text-sm font-medium text-muted-foreground">Transparency Report</span>
            </div>
            <h1 className="font-outfit font-bold text-4xl md:text-5xl mb-4">
              <span className="gradient-text">What Ghost Can & Cannot Protect</span>
            </h1>
            <p className="text-xl text-muted-foreground">
              We believe honesty is part of security. Ghost minimizes risk—but isn't magic.
            </p>
          </div>

          {/* Protection Grid */}
          <div className="max-w-5xl mx-auto grid md:grid-cols-2 gap-6 mb-16">
            {/* What We Protect */}
            <div className="p-8 rounded-2xl glass border border-accent/30">
              <div className="flex items-center gap-3 mb-6">
                <div className="p-3 rounded-xl bg-accent/10">
                  <CheckCircle className="h-6 w-6 text-accent" />
                </div>
                <h2 className="font-outfit font-bold text-2xl text-foreground">What Ghost Protects</h2>
              </div>
              <ul className="space-y-4">
                {[
                  { title: 'Message Content', desc: 'AES-256-GCM encryption, end-to-end' },
                  { title: 'Message Persistence', desc: 'RAM-only storage, vanishes on close' },
                  { title: 'Identity Privacy', desc: 'No accounts, no phone numbers, no emails' },
                  { title: 'Injection Attacks', desc: 'Input validation and sanitization' },
                  { title: 'Key Security', desc: 'ECDH P-256 key exchange, no key transmission' },
                ].map((item) => (
                  <li key={item.title} className="flex items-start gap-3">
                    <CheckCircle className="h-5 w-5 text-accent flex-shrink-0 mt-0.5" />
                    <div>
                      <span className="font-medium text-foreground">{item.title}</span>
                      <p className="text-sm text-muted-foreground">{item.desc}</p>
                    </div>
                  </li>
                ))}
              </ul>
            </div>

            {/* What We Cannot Protect */}
            <div className="p-8 rounded-2xl glass border border-destructive/30">
              <div className="flex items-center gap-3 mb-6">
                <div className="p-3 rounded-xl bg-destructive/10">
                  <AlertTriangle className="h-6 w-6 text-destructive" />
                </div>
                <h2 className="font-outfit font-bold text-2xl text-foreground">What Ghost Cannot Protect</h2>
              </div>
              <ul className="space-y-4">
                {[
                  { title: 'Network Metadata', desc: 'IP addresses, timing, session duration visible to relay' },
                  { title: 'Device Compromise', desc: 'Keyloggers, malware, compromised OS' },
                  { title: 'Screenshots', desc: 'Screen recording or photo capture by recipient' },
                  { title: 'Browser Vulnerabilities', desc: 'Malicious extensions or browser exploits' },
                  { title: 'Memory Traces', desc: 'Browser may retain data until garbage collection' },
                  { title: 'Infrastructure', desc: 'We rely on third-party cloud providers' },
                ].map((item) => (
                  <li key={item.title} className="flex items-start gap-3">
                    <AlertTriangle className="h-5 w-5 text-destructive flex-shrink-0 mt-0.5" />
                    <div>
                      <span className="font-medium text-foreground">{item.title}</span>
                      <p className="text-sm text-muted-foreground">{item.desc}</p>
                    </div>
                  </li>
                ))}
              </ul>
            </div>
          </div>

          {/* MITM Warning */}
          <div className="max-w-4xl mx-auto mb-16">
            <div className="p-8 rounded-2xl glass border border-yellow-500/30">
              <div className="flex items-start gap-4">
                <div className="p-3 rounded-xl bg-yellow-500/10">
                  <Shield className="h-6 w-6 text-yellow-500" />
                </div>
                <div>
                  <h3 className="font-outfit font-bold text-xl text-foreground mb-3">
                    Man-in-the-Middle Attack Prevention
                  </h3>
                  <p className="text-muted-foreground mb-4">
                    Without manual key verification, an active network attacker could impersonate your contact. 
                    Ghost provides key fingerprints that you should verify through a separate channel 
                    (phone call, in-person meeting) before sharing sensitive information.
                  </p>
                  <p className="text-sm text-yellow-500 font-medium">
                    Always verify the security codes shown before your first message.
                  </p>
                </div>
              </div>
            </div>
          </div>

          {/* Metadata Disclosure */}
          <div className="max-w-4xl mx-auto mb-16">
            <div className="p-8 rounded-2xl glass border border-border/50">
              <h3 className="font-outfit font-bold text-xl text-foreground mb-4">
                📊 Metadata We Cannot Avoid
              </h3>
              <div className="grid md:grid-cols-2 gap-4 mb-6">
                {[
                  'IP addresses (visible to cloud infrastructure)',
                  'Connection timestamps',
                  'Session duration',
                  'Message count (but not content)',
                  'Browser/user agent',
                  'WebSocket connection patterns'
                ].map((item) => (
                  <div key={item} className="flex items-center gap-2 text-sm text-muted-foreground">
                    <div className="w-1.5 h-1.5 rounded-full bg-muted-foreground" />
                    {item}
                  </div>
                ))}
              </div>
              <p className="text-sm text-muted-foreground">
                We never log this data intentionally, but it exists at the network level. 
                For maximum privacy, use Ghost with a VPN or Tor.
              </p>
            </div>
          </div>

          {/* Bug Bounty Program */}
          <div className="max-w-4xl mx-auto mb-16">
            <div className="p-8 rounded-2xl glass border border-primary/30">
              <div className="flex items-center gap-3 mb-6">
                <div className="p-3 rounded-xl bg-primary/10">
                  <Bug className="h-6 w-6 text-primary" />
                </div>
                <h2 className="font-outfit font-bold text-2xl text-foreground">Security Research & Bug Bounty</h2>
              </div>
              <p className="text-muted-foreground mb-6">
                We welcome responsible disclosure. If you discover a security vulnerability, 
                please report it to our security team.
              </p>

              <div className="overflow-x-auto mb-6">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-border">
                      <th className="text-left py-3 px-4 font-semibold text-foreground">Severity</th>
                      <th className="text-left py-3 px-4 font-semibold text-foreground">Example</th>
                      <th className="text-left py-3 px-4 font-semibold text-foreground">Bounty</th>
                    </tr>
                  </thead>
                  <tbody>
                    <tr className="border-b border-border/50">
                      <td className="py-3 px-4 text-destructive font-medium">Critical</td>
                      <td className="py-3 px-4 text-muted-foreground">Key recovery, message decryption</td>
                      <td className="py-3 px-4 text-accent font-medium">$1,000 - $5,000</td>
                    </tr>
                    <tr className="border-b border-border/50">
                      <td className="py-3 px-4 text-orange-500 font-medium">High</td>
                      <td className="py-3 px-4 text-muted-foreground">Authentication bypass, MITM</td>
                      <td className="py-3 px-4 text-accent font-medium">$500 - $1,000</td>
                    </tr>
                    <tr>
                      <td className="py-3 px-4 text-yellow-500 font-medium">Medium</td>
                      <td className="py-3 px-4 text-muted-foreground">Information leakage, UI spoofing</td>
                      <td className="py-3 px-4 text-accent font-medium">$100 - $500</td>
                    </tr>
                  </tbody>
                </table>
              </div>

              <div className="flex flex-wrap gap-4">
                <a
                  href="https://t.me/ghostdeveloperadmin"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="inline-flex items-center gap-2 px-4 py-2 bg-primary/10 border border-primary/30 text-primary rounded-lg hover:bg-primary/20 transition-colors text-sm"
                >
                  <Mail className="h-4 w-4" />
                  Report via Telegram (@ghostdeveloperadmin)
                  <ExternalLink className="h-3 w-3" />
                </a>
              </div>
              <p className="text-xs text-muted-foreground mt-3">
                Formal bug bounty program launching in 2026, funded by community contributions. Until then, report issues via Telegram (@ghostdeveloperadmin).
              </p>
            </div>
          </div>

          {/* Honesty Statement */}
          <div className="max-w-3xl mx-auto text-center">
            <div className="p-8 rounded-2xl glass border border-border/50">
              <h2 className="font-outfit font-bold text-2xl text-foreground mb-4">
                Why This Matters
              </h2>
              <p className="text-muted-foreground leading-relaxed mb-4">
                While big tech treats privacy as a PR problem, we treat it as a computational one. 
                While they collect metadata "for your safety," we engineered a system to minimize what metadata can exist.
              </p>
              <p className="text-muted-foreground leading-relaxed">
                Ghost proves that privacy isn't about trusting corporations—it's about trusting mathematics. 
                And mathematics doesn't have shareholders, profit motives, or government pressure points.
              </p>
            </div>
          </div>

          {/* Voice Message Limitations */}
          <div className="max-w-5xl mx-auto mb-16">
            <div className="p-8 rounded-2xl glass border border-primary/30">
              <div className="flex items-center gap-3 mb-6">
                <div className="p-3 rounded-xl bg-primary/10">
                  <Mic className="h-6 w-6 text-primary" />
                </div>
                <h2 className="font-outfit font-bold text-2xl text-foreground">
                  🎤 Voice Message Security
                </h2>
              </div>

              <div className="grid md:grid-cols-3 gap-6">
                {/* Cannot Protect */}
                <div className="p-4 rounded-xl bg-destructive/5 border border-destructive/20">
                  <h3 className="font-semibold text-destructive mb-3 flex items-center gap-2">
                    <AlertTriangle className="h-4 w-4" />
                    Cannot Protect
                  </h3>
                  <ul className="space-y-2 text-sm text-muted-foreground">
                    <li className="flex items-start gap-2">
                      <span className="text-destructive">•</span>
                      <span><strong>Device Recording:</strong> Recipient can record with another device</span>
                    </li>
                    <li className="flex items-start gap-2">
                      <span className="text-destructive">•</span>
                      <span><strong>Browser Caching:</strong> Audio may exist in memory temporarily</span>
                    </li>
                    <li className="flex items-start gap-2">
                      <span className="text-destructive">•</span>
                      <span><strong>Metadata:</strong> Duration, size, timing visible</span>
                    </li>
                    <li className="flex items-start gap-2">
                      <span className="text-destructive">•</span>
                      <span><strong>Side Channels:</strong> Short = "yes", long = detailed answer</span>
                    </li>
                  </ul>
                </div>

                {/* Can Protect */}
                <div className="p-4 rounded-xl bg-accent/5 border border-accent/20">
                  <h3 className="font-semibold text-accent mb-3 flex items-center gap-2">
                    <CheckCircle className="h-4 w-4" />
                    Does Protect
                  </h3>
                  <ul className="space-y-2 text-sm text-muted-foreground">
                    <li className="flex items-start gap-2">
                      <span className="text-accent">•</span>
                      <span><strong>Content:</strong> Encrypted end-to-end (AES-256-GCM)</span>
                    </li>
                    <li className="flex items-start gap-2">
                      <span className="text-accent">•</span>
                      <span><strong>Server Storage:</strong> We never receive audio</span>
                    </li>
                    <li className="flex items-start gap-2">
                      <span className="text-accent">•</span>
                      <span><strong>Replay Attacks:</strong> Messages play only once</span>
                    </li>
                    <li className="flex items-start gap-2">
                      <span className="text-accent">•</span>
                      <span><strong>Network:</strong> Encrypted in transit</span>
                    </li>
                  </ul>
                </div>

                {/* Important Notes */}
                <div className="p-4 rounded-xl bg-yellow-500/5 border border-yellow-500/20">
                  <h3 className="font-semibold text-yellow-500 mb-3 flex items-center gap-2">
                    <AlertTriangle className="h-4 w-4" />
                    Important Notes
                  </h3>
                  <ul className="space-y-2 text-sm text-muted-foreground">
                    <li className="flex items-start gap-2">
                      <span className="text-yellow-500">•</span>
                      <span>Voice is <strong>harder</strong> to secure than text</span>
                    </li>
                    <li className="flex items-start gap-2">
                      <span className="text-yellow-500">•</span>
                      <span>JavaScript can't guarantee memory deletion</span>
                    </li>
                    <li className="flex items-start gap-2">
                      <span className="text-yellow-500">•</span>
                      <span>Verify fingerprints before sensitive voice</span>
                    </li>
                    <li className="flex items-start gap-2">
                      <span className="text-yellow-500">•</span>
                      <span>For high-risk: use text or don't speak</span>
                    </li>
                  </ul>
                </div>
              </div>

              {/* Use Cases */}
              <div className="mt-6 grid md:grid-cols-2 gap-4">
                <div className="p-4 rounded-lg bg-accent/5">
                  <h4 className="font-medium text-foreground mb-2">🎯 Good For:</h4>
                  <ul className="text-sm text-muted-foreground space-y-1">
                    <li>• Quick voice notes between trusted partners</li>
                    <li>• Non-critical personal conversations</li>
                    <li>• When convenience {">"} absolute security</li>
                  </ul>
                </div>
                <div className="p-4 rounded-lg bg-destructive/5">
                  <h4 className="font-medium text-foreground mb-2">🚨 Not For:</h4>
                  <ul className="text-sm text-muted-foreground space-y-1">
                    <li>• Journalists in active conflict zones</li>
                    <li>• Sharing passwords or encryption keys</li>
                    <li>• Situations requiring absolute secrecy</li>
                  </ul>
                </div>
              </div>
            </div>
          </div>

          {/* CTA */}
          <div className="max-w-xl mx-auto mt-12 text-center">
            <Link
              to="/security"
              className="inline-flex items-center gap-2 px-6 py-3 bg-primary text-primary-foreground font-semibold rounded-xl hover:opacity-90 transition-opacity"
            >
              <Shield className="h-5 w-5" />
              View Full Security Architecture
              <ExternalLink className="h-4 w-4" />
            </Link>
          </div>
        </div>
      </main>

      <Footer />
    </div>
  );
};

export default Limitations;
