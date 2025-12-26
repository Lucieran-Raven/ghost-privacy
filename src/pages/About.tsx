import { Ghost, Bot, Globe, Mail, Github, ExternalLink, MessageCircle, Users, Heart, Sparkles, Crown } from 'lucide-react';
import { motion } from 'framer-motion';
import Navbar from '@/components/Ghost/Navbar';
import Footer from '@/components/Ghost/Footer';

const About = () => {
  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-900 via-black to-gray-950 text-white">
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
            <div className="inline-flex items-center gap-2 px-5 py-2.5 rounded-full border border-cyan-500/40 mb-8">
              <Ghost className="h-5 w-5 text-cyan-400" />
              <span className="text-sm font-bold tracking-wider text-cyan-400 uppercase">The Origin of Ghost</span>
            </div>
            <h1 className="font-black text-5xl md:text-6xl lg:text-7xl mb-6">
              <span className="text-white">BORN FROM </span>
              <span className="bg-gradient-to-r from-cyan-400 to-blue-500 bg-clip-text text-transparent">ONE QUESTION</span>
            </h1>
            <p className="text-xl text-gray-300 max-w-2xl mx-auto">
              “What if a conversation could vanish — and prove it never existed?”
            </p>
          </motion.div>

          {/* The Founder */}
          <motion.div
            initial={{ opacity: 0, y: 30 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            transition={{ duration: 0.6 }}
            className="max-w-4xl mx-auto mb-20"
          >
            <div className="p-10 md:p-16 rounded-3xl bg-gray-800/30 border border-cyan-500/20 relative overflow-hidden backdrop-blur-sm">
              <div className="absolute top-0 left-0 w-20 h-20 border-l-2 border-t-2 border-cyan-500/40 rounded-tl-3xl" />
              <div className="absolute bottom-0 right-0 w-20 h-20 border-r-2 border-b-2 border-blue-500/40 rounded-br-3xl" />
              
              <div className="text-center mb-10">
                <Crown className="h-16 w-16 text-cyan-400 mx-auto mb-6" />
                <h2 className="font-bold text-3xl md:text-4xl mb-4 text-white">
                  LUCIERAN RAVEN
                </h2>
                <div className="text-gray-300 mb-6 space-y-1">
                  <p>Lead Founder & AI Architect</p>
                  <p className="text-sm text-cyan-400/80">#1 Algorithm Solver in University | National Top 5</p>
                  <p className="text-xs text-gray-400">Data Science Association, 2025</p>
                </div>
              </div>

              <div className="prose prose-invert max-w-none space-y-6 text-gray-200">
                <p>
                  In a world drowning in metadata, Lucieran refused to accept that privacy required trust.
                </p>
                <p>
                  Armed with national recognition in algorithmic excellence and a vision for ephemeral truth, 
                  he set out to build the first messaging system where <span className="text-cyan-300 font-medium">“never existed”</span> wasn’t a slogan — but a mathematical guarantee.
                </p>
                <p className="font-medium text-white">
                  He didn’t just code an app.  
                  He engineered a sanctuary.
                </p>
              </div>
            </div>
          </motion.div>

          {/* The Alliance */}
          <motion.div
            initial={{ opacity: 0, y: 30 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            transition={{ duration: 0.6 }}
            className="max-w-4xl mx-auto mb-20"
          >
            <div className="p-10 md:p-16 rounded-3xl bg-gray-800/30 border border-purple-500/20 relative overflow-hidden backdrop-blur-sm">
              <div className="text-center mb-10">
                <Users className="h-16 w-16 text-purple-400 mx-auto mb-6" />
                <h2 className="font-bold text-3xl md:text-4xl mb-2 text-white">
                  THE ALLIANCE OF MINDS
                </h2>
                <p className="text-gray-300 mt-4">
                  Ghost was forged in collaboration — not by institutions, but by students who refused to wait for permission
                </p>
              </div>

              <div className="grid grid-cols-2 md:grid-cols-4 gap-4 my-8">
                {[
                  { name: "APU", color: "text-cyan-400", bg: "border-cyan-400/20" },
                  { name: "SUNWAY", color: "text-yellow-400", bg: "border-yellow-400/20" },
                  { name: "UNITEN", color: "text-green-400", bg: "border-green-400/20" },
                  { name: "TAYLOR'S", color: "text-rose-400", bg: "border-rose-400/20" }
                ].map((uni, i) => (
                  <div 
                    key={i}
                    className={`p-5 rounded-xl bg-gray-700/40 ${uni.bg} text-center border`}
                  >
                    <h3 className={`font-bold text-lg ${uni.color}`}>{uni.name}</h3>
                    <p className="text-xs text-gray-400 mt-1">Lead Developers</p>
                  </div>
                ))}
              </div>

              <p className="text-center text-gray-300 mt-6">
                These students didn’t just contribute code — they bet their belief on a world where conversations dissolve like mist.
              </p>
            </div>
          </motion.div>

          {/* AI Co-Creators */}
          <motion.div
            initial={{ opacity: 0, y: 30 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            transition={{ duration: 0.6 }}
            className="max-w-4xl mx-auto mb-20"
          >
            <div className="p-10 md:p-16 rounded-3xl bg-gray-800/30 border border-blue-500/20 relative overflow-hidden backdrop-blur-sm">
              <div className="text-center mb-10">
                <Bot className="h-16 w-16 text-blue-400 mx-auto mb-6" />
                <h2 className="font-bold text-3xl md:text-4xl mb-2 text-white">
                  OUR AI CO-CREATORS
                </h2>
                <p className="text-gray-300 mt-4">
                  Human vision, amplified by artificial genius.
                </p>
              </div>

              <div className="grid grid-cols-2 md:grid-cols-4 gap-4 my-8">
                <div className="p-6 rounded-xl bg-gray-700/40 border border-cyan-400/20 text-center">
                  <Sparkles className="h-8 w-8 text-cyan-400 mx-auto mb-3" />
                  <h3 className="font-bold text-lg text-cyan-400">Claude</h3>
                  <p className="text-xs text-gray-400 mt-1">Anthropic</p>
                </div>

                <div className="p-6 rounded-xl bg-gray-700/40 border border-blue-400/20 text-center">
                  <Sparkles className="h-8 w-8 text-blue-400 mx-auto mb-3" />
                  <h3 className="font-bold text-lg text-blue-400">GPT-5</h3>
                  <p className="text-xs text-gray-400 mt-1">OpenAI</p>
                </div>

                <div className="p-6 rounded-xl bg-gray-700/40 border border-purple-400/20 text-center">
                  <Sparkles className="h-8 w-8 text-purple-400 mx-auto mb-3" />
                  <h3 className="font-bold text-lg text-purple-400">Qwen</h3>
                  <p className="text-xs text-gray-400 mt-1">Alibaba</p>
                </div>

                <div className="p-6 rounded-xl bg-gray-700/40 border border-yellow-400/20 text-center">
                  <Sparkles className="h-8 w-8 text-yellow-400 mx-auto mb-3" />
                  <h3 className="font-bold text-lg text-yellow-400">Gemini</h3>
                  <p className="text-xs text-gray-400 mt-1">Google DeepMind</p>
                </div>
              </div>

              <p className="text-center text-white font-medium">
                Together, we built not just code — but covenant.
              </p>
            </div>
          </motion.div>

          {/* The Mission */}
          <motion.div
            initial={{ opacity: 0, y: 30 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            transition={{ duration: 0.6 }}
            className="max-w-4xl mx-auto mb-20"
          >
            <div className="p-10 md:p-16 rounded-3xl bg-gray-800/30 border border-red-500/20 relative overflow-hidden backdrop-blur-sm">
              <div className="text-center mb-10">
                <Ghost className="h-16 w-16 text-red-400 mx-auto mb-6" />
                <h2 className="font-bold text-3xl md:text-4xl mb-2 text-white">
                  THE MISSION
                </h2>
              </div>

              <div className="prose prose-invert max-w-none space-y-6 text-gray-200">
                <p>
                  Ghost is not a product. It is a stand.
                </p>
                <p>
                  While others optimize for attention, we optimize for **non-existence**.
                </p>
                <p className="font-medium text-white">
                  Our goal: to become a self-sustaining, global nonprofit —  
                  funded by community, governed by truth, and outliving its founder.
                </p>
                <p>
                  Because some words should never exist after they’re spoken.  
                  And now — they don’t have to.
                </p>
              </div>
            </div>
          </motion.div>

          {/* Technical Pedigree & GitHub */}
          <motion.div
            initial={{ opacity: 0, y: 30 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            transition={{ duration: 0.6 }}
            className="max-w-4xl mx-auto mb-20"
          >
            <div className="p-8 rounded-2xl bg-gray-800/30 border border-cyan-500/20 backdrop-blur-sm">
              <h3 className="font-bold text-2xl mb-6 text-cyan-400 flex items-center gap-2 justify-center">
                🔐 Verified by Math, Not Marketing
              </h3>
              <ul className="space-y-3 text-gray-300 max-w-lg mx-auto">
                <li className="flex items-start gap-2">
                  <span className="text-cyan-400">✓</span>
                  <span>AES-256-GCM + ECDH P-256 encryption</span>
                </li>
                <li className="flex items-start gap-2">
                  <span className="text-cyan-400">✓</span>
                  <span>Zero-knowledge architecture</span>
                </li>
                <li className="flex items-start gap-2">
                  <span className="text-cyan-400">✓</span>
                  <span>Open for public audit</span>
                </li>
              </ul>

              <div className="mt-8 pt-6 border-t border-gray-700 max-w-md mx-auto">
                <a
                  href="https://github.com/Lucieran-Raven/ghost-privacy"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="flex items-center justify-center gap-2 w-full px-4 py-3 bg-cyan-900/40 hover:bg-cyan-900/60 border border-cyan-500/30 rounded-xl text-cyan-300 font-semibold transition-all duration-300"
                >
                  <Github className="h-5 w-5" />
                  View Code on GitHub
                  <ExternalLink className="h-4 w-4" />
                </a>
              </div>
            </div>
          </motion.div>

          {/* Contact */}
          <motion.div
            initial={{ opacity: 0, y: 30 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            transition={{ duration: 0.6 }}
            className="max-w-2xl mx-auto"
          >
            <div className="p-8 md:p-10 rounded-3xl bg-gray-800/30 border border-cyan-500/20 backdrop-blur-sm">
              <div className="text-center mb-8">
                <h2 className="font-bold text-2xl md:text-3xl mb-2 text-white">
                  💬 JOIN THE LEGACY
                </h2>
                <p className="text-sm text-gray-400">
                  Developers. Researchers. Believers.
                </p>
              </div>

              <div className="space-y-4 mb-8">
                <a
                  href="https://t.me/ghostdeveloperadmin"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="flex items-center gap-4 p-4 rounded-xl bg-cyan-900/20 border border-cyan-500/20 hover:bg-cyan-900/30 transition-all duration-300"
                >
                  <MessageCircle className="h-5 w-5 text-cyan-400" />
                  <div className="flex-1">
                    <div className="font-semibold text-white">Telegram</div>
                    <div className="text-sm text-gray-400">@ghostdeveloperadmin</div>
                  </div>
                  <ExternalLink className="h-4 w-4 text-cyan-400" />
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

export default About;
