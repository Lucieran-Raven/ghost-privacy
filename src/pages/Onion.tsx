import { motion } from "framer-motion";
import { Shield, AlertTriangle, ExternalLink, Eye, EyeOff, Globe, Lock } from "lucide-react";
import Navbar from "@/components/Ghost/Navbar";
import Footer from "@/components/Ghost/Footer";
import { Button } from "@/components/ui/button";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";

const Onion = () => {
  // Placeholder .onion address - to be replaced with actual hidden service
  const onionAddress = "ghostxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx.onion";
  const isPlaceholder = onionAddress.includes("xxxxxxxx");

  return (
    <div className="min-h-screen bg-background text-foreground">
      <Navbar />
      
      <main className="container mx-auto px-4 py-12 max-w-4xl">
        {/* Hero Section */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6 }}
          className="text-center mb-12"
        >
          <div className="inline-flex items-center justify-center w-20 h-20 rounded-full bg-primary/10 mb-6">
            <Shield className="w-10 h-10 text-primary" />
          </div>
          
          <h1 className="text-4xl md:text-5xl font-bold mb-4">
            Ghost for High-Risk Users
          </h1>
          <p className="text-xl text-muted-foreground max-w-2xl mx-auto">
            Access via Tor to reduce network metadata exposure
          </p>
        </motion.div>

        {/* Critical Warning */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6, delay: 0.1 }}
          className="mb-8"
        >
          <Alert variant="destructive" className="border-destructive/50 bg-destructive/10">
            <AlertTriangle className="h-5 w-5" />
            <AlertTitle className="text-lg font-semibold">Clearnet Exposes Your Identity</AlertTitle>
            <AlertDescription className="mt-2 text-base">
              Accessing Ghost via regular browsers (Chrome, Firefox, Safari) exposes your IP address to:
              <ul className="list-disc list-inside mt-2 space-y-1">
                <li>Your Internet Service Provider (ISP)</li>
                <li>Network administrators</li>
                <li>Ghost's infrastructure providers (Netlify, Supabase)</li>
              </ul>
              <p className="mt-3 font-medium">
                For higher-risk situations: <strong>Use Tor Browser</strong> and read the limitations.
              </p>
              <p className="mt-3 text-sm">
                Tor reduces IP exposure, but it is not a guarantee against targeted adversaries or device compromise.
              </p>
            </AlertDescription>
          </Alert>
        </motion.div>

        {/* Comparison Cards */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6, delay: 0.2 }}
          className="grid md:grid-cols-2 gap-6 mb-12"
        >
          {/* Clearnet Card */}
          <div className="relative p-6 rounded-xl border border-border bg-card">
            <div className="absolute top-4 right-4">
              <Eye className="w-5 h-5 text-destructive" />
            </div>
            <div className="flex items-center gap-3 mb-4">
              <Globe className="w-8 h-8 text-muted-foreground" />
              <div>
                <h3 className="font-semibold text-lg">Clearnet Access</h3>
                <p className="text-sm text-muted-foreground">ghostprivacy.netlify.app</p>
              </div>
            </div>
            <ul className="space-y-2 text-sm">
              <li className="flex items-center gap-2">
                <span className="text-primary">✓</span>
                <span>End-to-end encrypted messages</span>
              </li>
              <li className="flex items-center gap-2">
                <span className="text-primary">✓</span>
                <span>RAM-only storage</span>
              </li>
              <li className="flex items-center gap-2">
                <span className="text-destructive">✗</span>
                <span>IP address visible to observers</span>
              </li>
              <li className="flex items-center gap-2">
                <span className="text-destructive">✗</span>
                <span>Connection timing visible</span>
              </li>
            </ul>
            <p className="mt-4 text-xs text-muted-foreground">
              Suitable for: General privacy, avoiding data brokers
            </p>
          </div>

          {/* Tor Card */}
          <div className="relative p-6 rounded-xl border-2 border-primary bg-primary/5">
            <div className="absolute top-4 right-4">
              <EyeOff className="w-5 h-5 text-primary" />
            </div>
            <div className="absolute -top-3 left-4 px-2 py-0.5 bg-primary text-primary-foreground text-xs font-medium rounded">
              RECOMMENDED
            </div>
            <div className="flex items-center gap-3 mb-4">
              <Lock className="w-8 h-8 text-primary" />
              <div>
                <h3 className="font-semibold text-lg">Tor Hidden Service</h3>
                <p className="text-sm text-muted-foreground">.onion address</p>
              </div>
            </div>
            <ul className="space-y-2 text-sm">
              <li className="flex items-center gap-2">
                <span className="text-primary">✓</span>
                <span>End-to-end encrypted messages</span>
              </li>
              <li className="flex items-center gap-2">
                <span className="text-primary">✓</span>
                <span>RAM-only storage</span>
              </li>
              <li className="flex items-center gap-2">
                <span className="text-primary">✓</span>
                <span>IP address hidden (3 relays)</span>
              </li>
              <li className="flex items-center gap-2">
                <span className="text-primary">✓</span>
                <span>Traffic pattern obfuscation</span>
              </li>
            </ul>
            <p className="mt-4 text-xs text-muted-foreground">
              Suitable for: Higher-risk users who understand limitations (not a guarantee against targeted adversaries)
            </p>
          </div>
        </motion.div>

        {/* Onion Address Section */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6, delay: 0.3 }}
          className="text-center mb-12"
        >
          <h2 className="text-2xl font-bold mb-6">Access Ghost via Tor</h2>
          
          {isPlaceholder ? (
            <div className="p-6 rounded-xl border border-border bg-card">
              <p className="text-muted-foreground mb-4">
                Tor Hidden Service coming soon. The .onion address will be published here once operational.
              </p>
              <p className="text-sm text-muted-foreground">
                Follow our GitHub for updates.
              </p>
            </div>
          ) : (
            <div className="p-6 rounded-xl border-2 border-primary bg-primary/5">
              <p className="text-sm text-muted-foreground mb-3">Tor Hidden Service Address:</p>
              <code className="block p-4 bg-background rounded-lg text-sm font-mono break-all mb-4">
                {onionAddress}
              </code>
              <Button asChild size="lg" className="gap-2">
                <a href={`http://${onionAddress}`} target="_blank" rel="noopener noreferrer">
                  <Lock className="w-4 h-4" />
                  Open in Tor Browser
                  <ExternalLink className="w-4 h-4" />
                </a>
              </Button>
              <p className="mt-4 text-xs text-muted-foreground">
                This link only works in Tor Browser
              </p>
            </div>
          )}
        </motion.div>

        {/* Setup Instructions */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6, delay: 0.4 }}
          className="mb-12"
        >
          <h2 className="text-2xl font-bold mb-6 text-center">3-Step Tor Setup</h2>
          
          <div className="grid md:grid-cols-3 gap-6">
            <div className="p-6 rounded-xl border border-border bg-card text-center">
              <div className="w-12 h-12 rounded-full bg-primary/10 flex items-center justify-center mx-auto mb-4">
                <span className="text-2xl font-bold text-primary">1</span>
              </div>
              <h3 className="font-semibold mb-2">Download Tor Browser</h3>
              <p className="text-sm text-muted-foreground mb-4">
                Get the official Tor Browser from torproject.org
              </p>
              <Button variant="outline" size="sm" asChild>
                <a href="https://www.torproject.org/download/" target="_blank" rel="noopener noreferrer">
                  Download
                  <ExternalLink className="w-3 h-3 ml-1" />
                </a>
              </Button>
            </div>

            <div className="p-6 rounded-xl border border-border bg-card text-center">
              <div className="w-12 h-12 rounded-full bg-primary/10 flex items-center justify-center mx-auto mb-4">
                <span className="text-2xl font-bold text-primary">2</span>
              </div>
              <h3 className="font-semibold mb-2">Connect to Tor Network</h3>
              <p className="text-sm text-muted-foreground">
                Launch Tor Browser and click "Connect". Wait for the connection to establish (may take 30-60 seconds).
              </p>
            </div>

            <div className="p-6 rounded-xl border border-border bg-card text-center">
              <div className="w-12 h-12 rounded-full bg-primary/10 flex items-center justify-center mx-auto mb-4">
                <span className="text-2xl font-bold text-primary">3</span>
              </div>
              <h3 className="font-semibold mb-2">Access Ghost</h3>
              <p className="text-sm text-muted-foreground">
                {isPlaceholder 
                  ? "Paste the .onion address into Tor Browser (available soon)"
                  : "Paste the .onion address into Tor Browser's address bar"}
              </p>
            </div>
          </div>
        </motion.div>

        {/* Security Notes */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6, delay: 0.5 }}
          className="mb-12"
        >
          <h2 className="text-2xl font-bold mb-6 text-center">Security Considerations</h2>
          
          <div className="p-6 rounded-xl border border-border bg-card">
            <h3 className="font-semibold mb-3 text-primary">What Tor Protects</h3>
            <ul className="space-y-2 text-sm mb-6">
              <li className="flex items-start gap-2">
                <span className="text-primary mt-0.5">•</span>
                <span><strong>IP address:</strong> Your real IP is hidden behind 3 relay nodes</span>
              </li>
              <li className="flex items-start gap-2">
                <span className="text-primary mt-0.5">•</span>
                <span><strong>Location:</strong> Geographic location cannot be determined from traffic</span>
              </li>
              <li className="flex items-start gap-2">
                <span className="text-primary mt-0.5">•</span>
                <span><strong>Traffic analysis:</strong> Patterns are obfuscated across the network</span>
              </li>
            </ul>

            <h3 className="font-semibold mb-3 text-destructive">What Tor Does NOT Protect</h3>
            <ul className="space-y-2 text-sm">
              <li className="flex items-start gap-2">
                <span className="text-destructive mt-0.5">•</span>
                <span><strong>Browser fingerprinting:</strong> Use default Tor Browser settings, don't resize window</span>
              </li>
              <li className="flex items-start gap-2">
                <span className="text-destructive mt-0.5">•</span>
                <span><strong>JavaScript attacks:</strong> Consider using "Safest" security level for maximum protection</span>
              </li>
              <li className="flex items-start gap-2">
                <span className="text-destructive mt-0.5">•</span>
                <span><strong>User behavior:</strong> Don't log into personal accounts while using Ghost over Tor</span>
              </li>
              <li className="flex items-start gap-2">
                <span className="text-destructive mt-0.5">•</span>
                <span><strong>Endpoint compromise:</strong> If your device is compromised, Tor cannot help</span>
              </li>
            </ul>
          </div>
        </motion.div>

        {/* Final Warning */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6, delay: 0.6 }}
        >
          <Alert className="border-primary/50 bg-primary/5">
            <Shield className="h-5 w-5 text-primary" />
            <AlertTitle className="font-semibold">Ghost Is Not Magic</AlertTitle>
            <AlertDescription className="mt-2">
              <p>
                Ghost provides strong technical protections, but no tool guarantees absolute security. 
                For life-or-death situations, combine Ghost + Tor with:
              </p>
              <ul className="list-disc list-inside mt-2 space-y-1 text-sm">
                <li>A dedicated device (not your personal phone/laptop)</li>
                <li>Tails OS for maximum anonymity</li>
                <li>Out-of-band key verification with your contact</li>
                <li>Awareness that your contact could be compromised</li>
              </ul>
              <p className="mt-3">
                <a href="/limitations" className="text-primary hover:underline">
                  Read our full limitations disclosure →
                </a>
              </p>
            </AlertDescription>
          </Alert>
        </motion.div>
      </main>

      <Footer />
    </div>
  );
};

export default Onion;
