import { FileText, Shield, Eye, Scale, Heart, Lock } from 'lucide-react';
import { motion } from 'framer-motion';
import Navbar from '@/components/Ghost/Navbar';
import Footer from '@/components/Ghost/Footer';

const articles = [
  {
    number: '01',
    icon: Lock,
    title: "WE DON'T STORE YOUR DATA",
    content: "We are designed so message plaintext is encrypted on your device before transmission, and server components process ciphertext rather than plaintext. Session data is handled as ephemeral in-app state on a best-effort basis.",
    color: 'primary'
  },
  {
    number: '02',
    icon: Eye,
    title: "WE DON'T TRACK YOU",
    content: "By default we do not run advertising trackers and we minimize identifiers. Limited security telemetry and infrastructure metadata can still exist depending on runtime, hosting, and network layers.",
    color: 'accent'
  },
  {
    number: '03',
    icon: Shield,
    title: "WE CAN'T HELP AUTHORITIES SPY ON YOU",
    content: "If legally compelled, we can provide only data we actually possess. Ghost is engineered to keep message plaintext and private keys on client devices, but legal exposure can still include accountless metadata outside encrypted payloads.",
    color: 'ghost-red'
  },
  {
    number: '04',
    icon: Scale,
    title: "USE RESPONSIBLY OR NOT AT ALL",
    content: "We built Ghost for journalists, activists, doctors, lawyers, and people who need privacy. We will ban anyone using it for harassment, terrorism, or illegal activities.",
    color: 'ghost-purple'
  },
  {
    number: '05',
    icon: Heart,
    title: "NO WARRANTIES, ONLY PROMISES",
    content: "We commit to public auditability, transparent security updates, and rapid remediation. We cannot promise zero defects or instantaneous fixes, but we can document controls and respond quickly to verified issues.",
    color: 'ghost-gold'
  },
];

const Terms = () => {
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
            className="max-w-4xl mx-auto text-center mb-20"
          >
            <div className="inline-flex items-center gap-2 px-5 py-2.5 rounded-full glass border border-primary/30 mb-8">
              <FileText className="h-5 w-5 text-primary" />
              <span className="text-sm font-bold tracking-wider text-primary uppercase">The Ghost Manifesto</span>
            </div>
            <h1 className="font-outfit font-black text-5xl md:text-6xl lg:text-7xl mb-6">
              <span className="text-foreground">NOT </span>
              <span className="gradient-text">TERMS.</span>
              <br />
              <span className="text-foreground">PROMISES.</span>
            </h1>
            <p className="text-xl text-muted-foreground max-w-2xl mx-auto">
              We believe legal documents should be readable by humans.
              Here's what we stand for, in plain language.
            </p>
          </motion.div>

          {/* Articles */}
          <div className="max-w-4xl mx-auto space-y-8 mb-20">
            {articles.map((article, index) => {
              const Icon = article.icon;
              return (
                <motion.div
                  key={article.number}
                  initial={{ opacity: 0, x: index % 2 === 0 ? -30 : 30 }}
                  whileInView={{ opacity: 1, x: 0 }}
                  viewport={{ once: true }}
                  transition={{ duration: 0.6 }}
                  className="relative"
                >
                  <div className={`p-8 md:p-10 rounded-2xl glass border transition-all duration-300 hover-lift ${
                    article.color === 'primary' ? 'border-primary/20 hover:border-primary/40' :
                    article.color === 'accent' ? 'border-accent/20 hover:border-accent/40' :
                    article.color === 'ghost-red' ? 'border-ghost-red/20 hover:border-ghost-red/40' :
                    article.color === 'ghost-purple' ? 'border-ghost-purple/20 hover:border-ghost-purple/40' :
                    'border-ghost-gold/20 hover:border-ghost-gold/40'
                  }`}>
                    <div className="flex items-start gap-6">
                      {/* Article Number */}
                      <div className={`text-6xl md:text-7xl font-outfit font-black opacity-20 ${
                        article.color === 'primary' ? 'text-primary' :
                        article.color === 'accent' ? 'text-accent' :
                        article.color === 'ghost-red' ? 'text-ghost-red' :
                        article.color === 'ghost-purple' ? 'text-ghost-purple' :
                        'text-ghost-gold'
                      }`}>
                        {article.number}
                      </div>

                      <div className="flex-1">
                        {/* Icon & Title */}
                        <div className="flex items-center gap-3 mb-4">
                          <div className={`p-2 rounded-lg ${
                            article.color === 'primary' ? 'bg-primary/10' :
                            article.color === 'accent' ? 'bg-accent/10' :
                            article.color === 'ghost-red' ? 'bg-ghost-red/10' :
                            article.color === 'ghost-purple' ? 'bg-ghost-purple/10' :
                            'bg-ghost-gold/10'
                          }`}>
                            <Icon className={`h-5 w-5 ${
                              article.color === 'primary' ? 'text-primary' :
                              article.color === 'accent' ? 'text-accent' :
                              article.color === 'ghost-red' ? 'text-ghost-red' :
                              article.color === 'ghost-purple' ? 'text-ghost-purple' :
                              'text-ghost-gold'
                            }`} />
                          </div>
                          <h2 className="font-outfit font-bold text-xl md:text-2xl text-foreground">
                            {article.title}
                          </h2>
                        </div>

                        {/* Content */}
                        <p className="text-muted-foreground leading-relaxed text-lg">
                          {article.content}
                        </p>
                      </div>
                    </div>
                  </div>
                </motion.div>
              );
            })}
          </div>

          {/* Legal Notice */}
          <motion.div
            initial={{ opacity: 0, y: 30 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            transition={{ duration: 0.6 }}
            className="max-w-3xl mx-auto"
          >
            <div className="p-8 rounded-2xl glass border border-border/30 text-center">
              <h3 className="font-outfit font-bold text-lg mb-4 text-foreground">
                Legal Fine Print
              </h3>
              <p className="text-sm text-muted-foreground leading-relaxed mb-4">
                The above manifesto represents our ethical commitments. For legally binding terms and conditions,
                please review our complete Terms of Service and Privacy Policy documents. By using Ghost,
                you acknowledge these commitments and agree to use the platform responsibly.
              </p>
              <p className="text-xs text-muted-foreground">
                Last updated: December 2024 · Jurisdiction: Malaysia · Contact: lucieranraven@gmail.com
              </p>
            </div>
          </motion.div>
        </div>
      </main>

      <Footer />
    </div>
  );
};

export default Terms;
