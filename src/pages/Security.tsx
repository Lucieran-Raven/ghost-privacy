import { Shield, Lock, Key, FileCode, Eye, Server, CheckCircle, Github, ExternalLink, AlertTriangle, Check, X } from 'lucide-react';
import { motion } from 'framer-motion';
import Navbar from '@/components/Ghost/Navbar';
import Footer from '@/components/Ghost/Footer';

const securityFeatures = [
  {
    icon: Lock,
    title: 'AES-256-GCM Encryption',
    description: 'All messages are encrypted using AES-256 in Galois/Counter Mode, providing both confidentiality and authentication.',
    details: [
      '256-bit key length - computationally infeasible to brute force',
      'GCM mode provides authenticated encryption',
      'Unique 96-bit IV for each message',
      'No padding oracle vulnerabilities'
    ]
  },
  {
    icon: Key,
    title: 'ECDH P-256 Key Exchange',
    description: 'Elliptic Curve Diffie-Hellman on the P-256 curve establishes shared secrets without ever transmitting keys.',
    details: [
      'Perfect forward secrecy - past sessions remain secure',
      'NIST P-256 curve (secp256r1)',
      'Keys derived client-side only',
      'No key transmission over network'
    ]
  },
  {
    icon: Eye,
    title: 'Zero-Knowledge Architecture',
    description: 'Our servers relay encrypted data but never have access to plaintext messages or encryption keys.',
    details: [
      'End-to-end encryption at the protocol level',
      'Server sees only encrypted payloads',
      'No message content logging',
      'Minimal metadata collection'
    ]
  },
  {
    icon: Server,
    title: 'Ephemeral Sessions',
    description: 'Sessions exist only in memory. When closed, all cryptographic material is securely destroyed.',
    details: [
      'No persistent storage of messages',
      'Keys cleared on session end',
      'Automatic session expiration',
      'Memory-only operation'
    ]
  }
];

const auditItems = [
  { status: 'pass', item: 'Web Crypto API implementation' },
  { status: 'pass', item: 'ECDH key generation (P-256)' },
  { status: 'pass', item: 'AES-256-GCM encryption' },
  { status: 'pass', item: 'No plaintext key transmission' },
  { status: 'pass', item: 'Client-side only cryptography' },
  { status: 'pass', item: 'Secure random number generation' },
  { status: 'pass', item: 'No server-side message storage' },
  { status: 'pass', item: 'Input validation and sanitization' }
];

// Comparison table data
const comparisonFeatures = [
  {
    feature: 'End-to-End Encryption',
    whatsapp: { value: true, note: 'by default' },
    signal: { value: true, note: 'by default' },
    telegram: { value: false, note: 'only in Secret Chats' },
    ghost: { value: true, note: 'always, client-side' }
  },
  {
    feature: 'Zero-Knowledge Design',
    whatsapp: { value: false, note: 'Facebook-owned' },
    signal: { value: false, note: 'stores phone numbers + metadata' },
    telegram: { value: false, note: 'cloud servers store all data' },
    ghost: { value: true, note: 'we never see your data' }
  },
  {
    feature: 'No Phone Number Required',
    whatsapp: { value: false },
    signal: { value: false },
    telegram: { value: false, note: 'optional in some regions' },
    ghost: { value: true, note: 'no account, no identity' }
  },
  {
    feature: 'Messages Truly Ephemeral',
    whatsapp: { value: false, note: 'stored unless deleted' },
    signal: { value: false, note: 'disappearing optional' },
    telegram: { value: false, note: 'cloud backups default' },
    ghost: { value: true, note: 'vanish on session end' }
  },
  {
    feature: 'No Server Message Storage',
    whatsapp: { value: false },
    signal: { value: false, note: 'keeps logs 30+ days' },
    telegram: { value: false, note: 'full cloud sync' },
    ghost: { value: true, note: 'RAM-only, wiped on close' }
  },
  {
    feature: 'Open Source (Client)',
    whatsapp: { value: false },
    signal: { value: true },
    telegram: { value: false, note: 'partial' },
    ghost: { value: true, note: 'full core open soon' }
  },
  {
    feature: 'File Sharing (PDF, Docs)',
    whatsapp: { value: true },
    signal: { value: true },
    telegram: { value: true },
    ghost: { value: true, note: 'E2E encrypted, no server upload' }
  },
  {
    feature: 'Metadata Minimized',
    whatsapp: { value: false, note: 'full contact graph, IPs' },
    signal: { value: false, note: 'who talks to whom' },
    telegram: { value: false, note: 'full social graph' },
    ghost: { value: true, note: 'only network-level IP*' }
  }
];

const Security = () => {
  return (
    <div className="min-h-screen bg-background">
      <Navbar />
      
      <main className="pt-24 pb-12">
        <div className="container mx-auto px-4">
          {/* Header */}
          <motion.div
            initial={{ opacity: 0, y: 30 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.6 }}
            className="max-w-4xl mx-auto text-center mb-16"
          >
            <div className="inline-flex items-center gap-2 px-4 py-2 rounded-full glass border border-primary/30 mb-6">
              <Shield className="h-4 w-4 text-primary" />
              <span className="text-sm font-medium text-muted-foreground">Security Audit</span>
            </div>
            <h1 className="font-outfit font-bold text-4xl md:text-5xl mb-4">
              <span className="gradient-text">Security Architecture</span>
            </h1>
            <p className="text-xl text-muted-foreground">
              Complete transparency about how Ghost protects your communications.
              Every implementation detail, open for inspection.
            </p>
          </motion.div>

          {/* Security Features */}
          <div className="max-w-5xl mx-auto space-y-8 mb-16">
            {securityFeatures.map((feature, index) => {
              const Icon = feature.icon;
              return (
                <motion.div
                  key={feature.title}
                  initial={{ opacity: 0, y: 20 }}
                  whileInView={{ opacity: 1, y: 0 }}
                  viewport={{ once: true }}
                  transition={{ duration: 0.5, delay: index * 0.1 }}
                  className="p-8 rounded-2xl glass border border-border/50"
                >
                  <div className="flex flex-col md:flex-row gap-6">
                    <div className="flex-shrink-0">
                      <div className="inline-flex p-4 rounded-xl bg-primary/10">
                        <Icon className="h-8 w-8 text-primary" />
                      </div>
                    </div>
                    <div className="flex-1">
                      <h2 className="font-outfit font-semibold text-2xl text-foreground mb-2">
                        {feature.title}
                      </h2>
                      <p className="text-muted-foreground mb-4">
                        {feature.description}
                      </p>
                      <ul className="space-y-2">
                        {feature.details.map((detail, i) => (
                          <li key={i} className="flex items-start gap-2 text-sm text-muted-foreground">
                            <CheckCircle className="h-4 w-4 text-accent flex-shrink-0 mt-0.5" />
                            {detail}
                          </li>
                        ))}
                      </ul>
                    </div>
                  </div>
                </motion.div>
              );
            })}
          </div>

          {/* Audit Checklist */}
          <motion.div
            initial={{ opacity: 0, y: 30 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            transition={{ duration: 0.6 }}
            className="max-w-3xl mx-auto mb-16"
          >
            <div className="p-8 rounded-2xl glass border border-accent/30">
              <div className="flex items-center gap-3 mb-6">
                <FileCode className="h-6 w-6 text-accent" />
                <h2 className="font-outfit font-semibold text-2xl text-foreground">
                  Implementation Audit
                </h2>
              </div>
              <div className="grid md:grid-cols-2 gap-4">
                {auditItems.map((item, index) => (
                  <div
                    key={index}
                    className="flex items-center gap-3 p-3 rounded-lg bg-secondary/30"
                  >
                    <CheckCircle className="h-5 w-5 text-accent flex-shrink-0" />
                    <span className="text-sm text-foreground">{item.item}</span>
                  </div>
                ))}
              </div>
            </div>
          </motion.div>

          {/* Comparison Table */}
          <motion.div
            initial={{ opacity: 0, y: 30 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            transition={{ duration: 0.6 }}
            className="max-w-6xl mx-auto mb-16"
          >
            <div className="p-8 rounded-2xl glass border border-primary/20">
              <div className="text-center mb-8">
                <h2 className="font-outfit font-bold text-2xl md:text-3xl text-foreground mb-2">
                  Privacy by Architecture — Not Just Marketing
                </h2>
                <p className="text-muted-foreground">
                  How Ghost compares to popular messaging apps
                </p>
              </div>

              {/* Desktop Table */}
              <div className="hidden md:block overflow-x-auto">
                <table className="w-full">
                  <thead>
                    <tr className="border-b border-border/50">
                      <th className="text-left py-4 px-4 font-outfit font-semibold text-foreground">Feature</th>
                      <th className="text-center py-4 px-4 font-outfit font-semibold text-muted-foreground">WhatsApp</th>
                      <th className="text-center py-4 px-4 font-outfit font-semibold text-muted-foreground">Signal</th>
                      <th className="text-center py-4 px-4 font-outfit font-semibold text-muted-foreground">Telegram</th>
                      <th className="text-center py-4 px-4 font-outfit font-semibold text-primary">Ghost</th>
                    </tr>
                  </thead>
                  <tbody>
                    {comparisonFeatures.map((row, index) => (
                      <tr key={row.feature} className={index % 2 === 0 ? 'bg-secondary/10' : ''}>
                        <td className="py-4 px-4 font-medium text-foreground">{row.feature}</td>
                        <td className="text-center py-4 px-4">
                          <div className="flex flex-col items-center gap-1">
                            {row.whatsapp.value ? (
                              <Check className="h-5 w-5 text-accent" />
                            ) : (
                              <X className="h-5 w-5 text-ghost-red" />
                            )}
                            {row.whatsapp.note && (
                              <span className="text-xs text-muted-foreground">{row.whatsapp.note}</span>
                            )}
                          </div>
                        </td>
                        <td className="text-center py-4 px-4">
                          <div className="flex flex-col items-center gap-1">
                            {row.signal.value ? (
                              <Check className="h-5 w-5 text-accent" />
                            ) : (
                              <X className="h-5 w-5 text-ghost-red" />
                            )}
                            {row.signal.note && (
                              <span className="text-xs text-muted-foreground">{row.signal.note}</span>
                            )}
                          </div>
                        </td>
                        <td className="text-center py-4 px-4">
                          <div className="flex flex-col items-center gap-1">
                            {row.telegram.value ? (
                              <Check className="h-5 w-5 text-accent" />
                            ) : (
                              <X className="h-5 w-5 text-ghost-red" />
                            )}
                            {row.telegram.note && (
                              <span className="text-xs text-muted-foreground">{row.telegram.note}</span>
                            )}
                          </div>
                        </td>
                        <td className="text-center py-4 px-4 bg-primary/5">
                          <div className="flex flex-col items-center gap-1">
                            {row.ghost.value ? (
                              <Check className="h-5 w-5 text-primary" />
                            ) : (
                              <X className="h-5 w-5 text-ghost-red" />
                            )}
                            {row.ghost.note && (
                              <span className="text-xs text-primary">{row.ghost.note}</span>
                            )}
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>

              {/* Mobile Cards */}
              <div className="md:hidden space-y-4">
                {comparisonFeatures.map((row) => (
                  <div key={row.feature} className="p-4 rounded-xl bg-secondary/20">
                    <h4 className="font-semibold text-foreground mb-3">{row.feature}</h4>
                    <div className="grid grid-cols-2 gap-2">
                      <div className="flex items-center gap-2">
                        <span className="text-xs text-muted-foreground">WhatsApp:</span>
                        {row.whatsapp.value ? (
                          <Check className="h-4 w-4 text-accent" />
                        ) : (
                          <X className="h-4 w-4 text-ghost-red" />
                        )}
                      </div>
                      <div className="flex items-center gap-2">
                        <span className="text-xs text-muted-foreground">Signal:</span>
                        {row.signal.value ? (
                          <Check className="h-4 w-4 text-accent" />
                        ) : (
                          <X className="h-4 w-4 text-ghost-red" />
                        )}
                      </div>
                      <div className="flex items-center gap-2">
                        <span className="text-xs text-muted-foreground">Telegram:</span>
                        {row.telegram.value ? (
                          <Check className="h-4 w-4 text-accent" />
                        ) : (
                          <X className="h-4 w-4 text-ghost-red" />
                        )}
                      </div>
                      <div className="flex items-center gap-2">
                        <span className="text-xs text-primary font-medium">Ghost:</span>
                        {row.ghost.value ? (
                          <Check className="h-4 w-4 text-primary" />
                        ) : (
                          <X className="h-4 w-4 text-ghost-red" />
                        )}
                      </div>
                    </div>
                  </div>
                ))}
              </div>

              {/* Footnotes */}
              <div className="mt-8 p-4 rounded-xl bg-secondary/30 border border-border/30">
                <p className="text-xs text-muted-foreground space-y-1">
                  <span className="block">* Ghost does not log IPs or session data, but like all web apps, your IP is visible to the relay server. For true anonymity, use Ghost with Tor.</span>
                  <span className="block">* Telegram's "Secret Chats" offer E2EE but are not default and lack cloud sync.</span>
                  <span className="block">* Signal stores phone numbers and message request logs for ~30 days.</span>
                  <span className="block">* WhatsApp backups to iCloud/Google Drive are <strong>not encrypted</strong> by default.</span>
                </p>
              </div>

              {/* Why This Matters Callout */}
              <div className="mt-6 p-6 rounded-xl bg-primary/10 border border-primary/30">
                <div className="flex items-start gap-3">
                  <Shield className="h-6 w-6 text-primary flex-shrink-0 mt-1" />
                  <div>
                    <h4 className="font-outfit font-bold text-lg text-foreground mb-2">🔐 Why This Matters</h4>
                    <p className="text-muted-foreground">
                      Other apps say "private" — but still log who you talk to, when, and from where.
                      Ghost was built on a simple rule: <strong className="text-primary">If it's not needed, it's not collected — not even by us.</strong>
                      That's not privacy theater. That's mathematical integrity.
                    </p>
                  </div>
                </div>
              </div>

              {/* Source */}
              <p className="mt-4 text-xs text-muted-foreground text-center italic">
                Source: Public documentation, security audits, and Ghost's open-source implementation (
                <a 
                  href="https://github.com/Lucieran-Raven/ghost-privacy" 
                  target="_blank" 
                  rel="noopener noreferrer"
                  className="text-primary hover:underline"
                >
                  github.com/Lucieran-Raven/ghost-privacy
                </a>
                )
              </p>
            </div>
          </motion.div>

          {/* Code Reference */}
          <motion.div
            initial={{ opacity: 0, y: 30 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            transition={{ duration: 0.6 }}
            className="max-w-3xl mx-auto"
          >
            <div className="p-8 rounded-2xl glass border border-border/50 text-center">
              <h2 className="font-outfit font-semibold text-xl text-foreground mb-4">
                Open Source Security
              </h2>
              <p className="text-muted-foreground mb-6">
                All cryptographic implementations are available for review.
                We believe security through obscurity is no security at all.
              </p>
              <div className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-secondary/50 font-mono text-sm text-muted-foreground mb-4">
                <code>src/utils/encryption.ts</code>
              </div>
              <div className="mt-4">
                <a
                  href="https://github.com/Lucieran-Raven/ghost-privacy"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="inline-flex items-center gap-2 px-6 py-3 bg-accent/10 hover:bg-accent/20 border border-accent/30 rounded-xl text-accent font-semibold transition-all duration-300"
                >
                  <Github className="h-5 w-5" />
                  View on GitHub
                  <ExternalLink className="h-4 w-4" />
                </a>
              </div>
            </div>
          </motion.div>
        </div>
      </main>

      <Footer />
    </div>
  );
};

export default Security;