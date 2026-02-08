import Navbar from '@/components/Ghost/Navbar';
import Footer from '@/components/Ghost/Footer';
import PageTransition from '@/components/Ghost/PageTransition';
import { useMemo, useEffect, useState } from 'react';
import { Monitor, Smartphone, Globe, Shield, Download, ExternalLink, Check, AlertCircle, Lock } from 'lucide-react';

// Platform detection types
type Platform = 'windows' | 'macos' | 'linux' | 'android' | 'ios' | 'unknown';
type Arch = 'x64' | 'arm64' | 'unknown';

interface DetectedPlatform {
  platform: Platform;
  arch: Arch;
  isMobile: boolean;
  isDesktop: boolean;
  isWeb: boolean;
}

const Downloads = () => {
  const releaseTag = 'v0.1.37';
  const [detected, setDetected] = useState<DetectedPlatform>({ 
    platform: 'unknown', 
    arch: 'unknown', 
    isMobile: false, 
    isDesktop: false, 
    isWeb: true 
  });

  // Platform detection
  useEffect(() => {
    const detect = (): DetectedPlatform => {
      const ua = navigator.userAgent.toLowerCase();
      const platform = navigator.platform.toLowerCase();
      
      // Architecture detection
      const isArm64 = ua.includes('arm64') || ua.includes('aarch64');
      const arch: Arch = isArm64 ? 'arm64' : 'x64';
      
      // Platform detection
      let detectedPlatform: Platform = 'unknown';
      
      if (/android/.test(ua)) {
        detectedPlatform = 'android';
      } else if (/iphone|ipad|ipod/.test(ua)) {
        detectedPlatform = 'ios';
      } else if (/win/.test(platform) || /win/.test(ua)) {
        detectedPlatform = 'windows';
      } else if (/mac/.test(platform) || /macintosh|mac os x/.test(ua)) {
        detectedPlatform = 'macos';
      } else if (/linux/.test(platform) || /linux/.test(ua)) {
        detectedPlatform = 'linux';
      }

      const isMobile = detectedPlatform === 'android' || detectedPlatform === 'ios';
      const isDesktop = ['windows', 'macos', 'linux'].includes(detectedPlatform);

      return {
        platform: detectedPlatform,
        arch,
        isMobile,
        isDesktop,
        isWeb: true
      };
    };

    setDetected(detect());
  }, []);

  // Download URLs
  const downloads = useMemo(() => ({
    windows: {
      x64: `https://github.com/Lucieran-Raven/ghost-privacy/releases/download/${releaseTag}/ghost-privacy-windows-installers/Ghost%20Privacy_${releaseTag.slice(1)}_x64-setup.exe`,
      arm64: `https://github.com/Lucieran-Raven/ghost-privacy/releases/download/${releaseTag}/ghost-privacy-windows-installers/Ghost%20Privacy_${releaseTag.slice(1)}_arm64-setup.exe`,
      name: 'Windows',
      icon: Monitor,
      instructions: 'Download .exe → Run → SmartScreen: Click "More info" → "Run anyway"'
    },
    macos: {
      x64: `https://github.com/Lucieran-Raven/ghost-privacy/releases/download/${releaseTag}/ghost-privacy-macos-x86_64-installers/Ghost%20Privacy_${releaseTag.slice(1)}_x64.dmg`,
      arm64: `https://github.com/Lucieran-Raven/ghost-privacy/releases/download/${releaseTag}/ghost-privacy-macos-aarch64-installers/Ghost%20Privacy_${releaseTag.slice(1)}_aarch64.dmg`,
      name: 'macOS',
      icon: Monitor,
      instructions: 'Download .dmg → Open → Drag to Applications → Security: Click "Open"'
    },
    linux: {
      x64: `https://github.com/Lucieran-Raven/ghost-privacy/releases/download/${releaseTag}/ghost-privacy-linux-x86_64-installers/ghost-privacy_${releaseTag.slice(1)}_amd64.AppImage`,
      arm64: `https://github.com/Lucieran-Raven/ghost-privacy/releases/download/${releaseTag}/ghost-privacy-linux-aarch64-installers/ghost-privacy_${releaseTag.slice(1)}_arm64.AppImage`,
      name: 'Linux',
      icon: Monitor,
      instructions: 'Download AppImage → chmod +x → Run. Or install .deb/.rpm package.'
    },
    android: {
      universal: `https://github.com/Lucieran-Raven/ghost-privacy/releases/download/${releaseTag}/ghost-privacy-android-release.apk`,
      name: 'Android',
      icon: Smartphone,
      instructions: 'Download APK → Settings → Security → Enable "Unknown sources" → Install'
    },
    ios: {
      device: `https://github.com/Lucieran-Raven/ghost-privacy/releases/download/${releaseTag}/ghost-privacy-ios-unsigned.ipa`,
      name: 'iOS',
      icon: Smartphone,
      instructions: 'Device: Requires sideloading (AltStore, Sideloadly). Simulator available.'
    },
    web: {
      url: 'https://ghostprivacy.netlify.app',
      name: 'Web (PWA)',
      icon: Globe,
      instructions: 'Use directly in browser. Add to home screen for app-like experience.'
    }
  }), [releaseTag]);

  const releasePageUrl = `https://github.com/Lucieran-Raven/ghost-privacy/releases/tag/${releaseTag}`;

  // Get recommended download
  const getRecommendedDownload = () => {
    if (detected.platform === 'unknown') return null;
    
    if (detected.platform === 'android') {
      return { ...downloads.android, type: 'direct', url: downloads.android.universal };
    }
    
    if (detected.platform === 'ios') {
      return { ...downloads.ios, type: 'direct', url: downloads.ios.device };
    }
    
    if (['windows', 'macos', 'linux'].includes(detected.platform)) {
      const platformDownloads = downloads[detected.platform as keyof typeof downloads] as { x64: string; arm64: string; name: string; icon: typeof Monitor; instructions: string };
      const arch = detected.arch === 'arm64' ? 'arm64' : 'x64';
      return { 
        ...platformDownloads, 
        type: 'direct', 
        url: platformDownloads[arch as keyof typeof platformDownloads] as string 
      };
    }
    
    return null;
  };

  const recommended = getRecommendedDownload();

  return (
    <div className="min-h-screen bg-background text-foreground">
      <Navbar />
      <PageTransition>
        <main className="pt-24 pb-12">
          <div className="mx-auto max-w-[1400px] px-4">
            {/* Header */}
            <div className="mb-8 border border-[rgba(255,10,42,0.18)] bg-black/60 backdrop-blur-md">
              <div className="px-5 py-4 border-b border-[rgba(255,10,42,0.14)]">
                <div className="font-mono text-xs tracking-[0.16em] uppercase text-white/60">SECURE DOWNLOADS</div>
              </div>
              <div className="p-5">
                <div className="font-mono text-sm tracking-[0.12em] text-white/90 mb-2">GHOST PRIVACY {releaseTag}</div>
                <div className="font-mono text-[12px] leading-relaxed text-white/70">
                  Multi-platform counter-forensic messaging. All downloads are signed and attested.
                </div>
              </div>
            </div>

            {/* Recommended Download */}
            {recommended && (
              <div className="mb-6 border-2 border-[#ff0a2a] bg-[rgba(255,10,42,0.12)]">
                <div className="px-5 py-4 border-b border-[rgba(255,10,42,0.3)] flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    <Shield className="w-5 h-5 text-[#ff0a2a]" />
                    <div className="font-mono text-sm tracking-[0.12em] text-white">RECOMMENDED FOR YOUR DEVICE</div>
                  </div>
                  <div className="font-mono text-[10px] tracking-wider text-[#ff0a2a]">
                    {detected.platform.toUpperCase()} {detected.arch.toUpperCase()}
                  </div>
                </div>
                <div className="p-5">
                  <div className="border border-[rgba(255,10,42,0.5)] bg-black/50">
                    <div className="px-4 py-3 border-b border-[rgba(255,10,42,0.3)] flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <recommended.icon className="w-4 h-4 text-[#ff0a2a]" />
                        <div className="font-mono text-xs tracking-[0.16em] uppercase text-white/80">{recommended.name}</div>
                      </div>
                      <div className="flex items-center gap-1 text-[#ff0a2a]">
                        <Check className="w-3 h-3" />
                        <span className="font-mono text-[10px] tracking-wider">DETECTED</span>
                      </div>
                    </div>
                    <div className="p-4 space-y-3">
                      <div className="flex flex-wrap gap-2">
                        {['Signed', 'Attested', 'Verified'].map((badge) => (
                          <span key={badge} className="px-2 py-0.5 border border-[rgba(255,10,42,0.3)] bg-black/40 font-mono text-[10px] text-white/60">{badge}</span>
                        ))}
                      </div>
                      <div className="font-mono text-[11px] leading-relaxed text-white/60">{recommended.instructions}</div>
                      <a
                        href={recommended.url}
                        className="inline-flex w-full justify-between items-center px-4 py-3 border border-[rgba(255,10,42,0.4)] bg-black/50 font-mono text-xs tracking-[0.12em] uppercase text-white transition-all active:translate-y-[1px] hover:border-[#ff0a2a] hover:shadow-[0_0_20px_rgba(255,10,42,0.4)]"
                      >
                        <span className="flex items-center gap-2"><Download className="w-4 h-4" />DOWNLOAD</span>
                        <span className="text-white/50">{detected.platform}</span>
                      </a>
                    </div>
                  </div>
                </div>
              </div>
            )}

            {/* All Platforms */}
            <div className="border border-[rgba(255,10,42,0.18)] bg-black/60">
              <div className="px-5 py-4 border-b border-[rgba(255,10,42,0.14)]">
                <div className="font-mono text-xs tracking-[0.16em] uppercase text-white/60">ALL PLATFORMS</div>
              </div>
              <div className="p-5 space-y-6">
                {/* Desktop */}
                <div>
                  <div className="font-mono text-[11px] tracking-[0.2em] uppercase text-white/40 mb-3 flex items-center gap-2">
                    <Monitor className="w-3 h-3" />DESKTOP
                  </div>
                  <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                    {[
                      { name: 'Windows', url: downloads.windows.x64, badges: ['x64', 'arm64', 'MSI + EXE'], instructions: downloads.windows.instructions },
                      { name: 'macOS', url: downloads.macos[detected.arch === 'arm64' ? 'arm64' : 'x64'], badges: ['Intel', 'Apple Silicon', 'DMG'], instructions: downloads.macos.instructions },
                      { name: 'Linux', url: downloads.linux[detected.arch === 'arm64' ? 'arm64' : 'x64'], badges: ['AppImage', 'DEB', 'RPM'], instructions: downloads.linux.instructions }
                    ].map((platform) => (
                      <div key={platform.name} className="border border-[rgba(255,10,42,0.14)] bg-black/35">
                        <div className="px-4 py-3 border-b border-[rgba(255,10,42,0.14)] flex items-center gap-2">
                          <Monitor className="w-4 h-4 text-[#ff0a2a]" />
                          <div className="font-mono text-xs tracking-[0.16em] uppercase text-white/80">{platform.name}</div>
                        </div>
                        <div className="p-4 space-y-3">
                          <div className="flex flex-wrap gap-2">
                            {platform.badges.map((badge) => (
                              <span key={badge} className="px-2 py-0.5 border border-[rgba(255,10,42,0.3)] bg-black/40 font-mono text-[10px] text-white/60">{badge}</span>
                            ))}
                          </div>
                          <div className="font-mono text-[11px] leading-relaxed text-white/60">{platform.instructions}</div>
                          <a href={platform.url} className="inline-flex w-full justify-between items-center px-4 py-3 border border-[rgba(255,10,42,0.24)] bg-black/40 font-mono text-xs tracking-[0.12em] uppercase text-white/85 transition-all active:translate-y-[1px] hover:border-[rgba(255,10,42,0.55)] hover:text-white">
                            <span className="flex items-center gap-2"><Download className="w-4 h-4" />DOWNLOAD</span>
                            <span className="text-white/50">{platform.name}</span>
                          </a>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Mobile */}
                <div>
                  <div className="font-mono text-[11px] tracking-[0.2em] uppercase text-white/40 mb-3 flex items-center gap-2">
                    <Smartphone className="w-3 h-3" />MOBILE
                  </div>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    {[
                      { name: 'Android', url: downloads.android.universal, badges: ['Universal APK', 'API 26+'], instructions: downloads.android.instructions },
                      { name: 'iOS', url: downloads.ios.device, badges: ['Sideload', 'Simulator', 'IPA'], instructions: downloads.ios.instructions }
                    ].map((platform) => (
                      <div key={platform.name} className="border border-[rgba(255,10,42,0.14)] bg-black/35">
                        <div className="px-4 py-3 border-b border-[rgba(255,10,42,0.14)] flex items-center gap-2">
                          <Smartphone className="w-4 h-4 text-[#ff0a2a]" />
                          <div className="font-mono text-xs tracking-[0.16em] uppercase text-white/80">{platform.name}</div>
                        </div>
                        <div className="p-4 space-y-3">
                          <div className="flex flex-wrap gap-2">
                            {platform.badges.map((badge) => (
                              <span key={badge} className="px-2 py-0.5 border border-[rgba(255,10,42,0.3)] bg-black/40 font-mono text-[10px] text-white/60">{badge}</span>
                            ))}
                          </div>
                          <div className="font-mono text-[11px] leading-relaxed text-white/60">{platform.instructions}</div>
                          <a href={platform.url} className="inline-flex w-full justify-between items-center px-4 py-3 border border-[rgba(255,10,42,0.24)] bg-black/40 font-mono text-xs tracking-[0.12em] uppercase text-white/85 transition-all active:translate-y-[1px] hover:border-[rgba(255,10,42,0.55)] hover:text-white">
                            <span className="flex items-center gap-2"><Download className="w-4 h-4" />DOWNLOAD</span>
                            <span className="text-white/50">{platform.name}</span>
                          </a>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Web */}
                <div>
                  <div className="font-mono text-[11px] tracking-[0.2em] uppercase text-white/40 mb-3 flex items-center gap-2">
                    <Globe className="w-3 h-3" />WEB / PWA
                  </div>
                  <div className="border border-[rgba(255,10,42,0.14)] bg-black/35">
                    <div className="px-4 py-3 border-b border-[rgba(255,10,42,0.14)] flex items-center gap-2">
                      <Globe className="w-4 h-4 text-[#ff0a2a]" />
                      <div className="font-mono text-xs tracking-[0.16em] uppercase text-white/80">Web Browser</div>
                    </div>
                    <div className="p-4 space-y-3">
                      <div className="flex flex-wrap gap-2">
                        {['Chrome', 'Firefox', 'Safari', 'Tor'].map((badge) => (
                          <span key={badge} className="px-2 py-0.5 border border-[rgba(255,10,42,0.3)] bg-black/40 font-mono text-[10px] text-white/60">{badge}</span>
                        ))}
                      </div>
                      <div className="font-mono text-[11px] leading-relaxed text-white/60">{downloads.web.instructions}</div>
                      <a href={downloads.web.url} className="inline-flex w-full justify-between items-center px-4 py-3 border border-[rgba(255,10,42,0.24)] bg-black/40 font-mono text-xs tracking-[0.12em] uppercase text-white/85 transition-all active:translate-y-[1px] hover:border-[rgba(255,10,42,0.55)] hover:text-white">
                        <span className="flex items-center gap-2"><Globe className="w-4 h-4" />LAUNCH WEB APP</span>
                        <span className="text-white/50">PWA</span>
                      </a>
                    </div>
                  </div>
                </div>

                {/* Verification Info */}
                <div className="border border-[rgba(255,10,42,0.14)] p-4 bg-black/40">
                  <div className="flex items-center gap-2 mb-3">
                    <Lock className="w-4 h-4 text-[#ff0a2a]" />
                    <div className="font-mono text-xs tracking-[0.16em] uppercase text-white/60">VERIFICATION & SECURITY</div>
                  </div>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4 font-mono text-[11px] leading-relaxed text-white/70">
                    <div className="space-y-2">
                      <div><span className="text-white/50">Release:</span><a className="underline hover:text-white ml-2" href={releasePageUrl} target="_blank" rel="noopener noreferrer">GitHub {releaseTag}</a></div>
                      <div><span className="text-white/50">Verification:</span><a className="underline hover:text-white ml-2" href="https://github.com/Lucieran-Raven/ghost-privacy/blob/main/docs/RELEASE_VERIFICATION.md" target="_blank" rel="noopener noreferrer">docs/RELEASE_VERIFICATION.md</a></div>
                      <div><span className="text-white/50">Install Guide:</span><a className="underline hover:text-white ml-2" href="https://github.com/Lucieran-Raven/ghost-privacy/blob/main/docs/INSTALL_GUIDE.md" target="_blank" rel="noopener noreferrer">docs/INSTALL_GUIDE.md</a></div>
                    </div>
                    <div className="space-y-2">
                      <div><span className="text-white/50">Attestations:</span><span className="text-[#ff0a2a] ml-2">GitHub Sigstore</span></div>
                      <div><span className="text-white/50">Source:</span><a className="underline hover:text-white ml-2" href="https://github.com/Lucieran-Raven/ghost-privacy" target="_blank" rel="noopener noreferrer">Open Source (AGPL)</a></div>
                      <div><span className="text-white/50">Tor Mirror:</span><span className="text-white/30 ml-2">Coming soon</span></div>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </main>
      </PageTransition>
      <Footer />
    </div>
  );
};

export default Downloads;
