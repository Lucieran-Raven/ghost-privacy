import { useState, useRef } from 'react';
import { Ghost, Copy, Check, ArrowRight, Loader2, Shield, Lock, AlertCircle } from 'lucide-react';
import { toast } from 'sonner';
import { generateGhostId, isValidGhostId } from '@/utils/encryption';
import { SecurityManager } from '@/utils/security';
import { SessionService } from '@/lib/sessionService';
import { HoneypotService } from '@/lib/honeypotService';
import { parseAccessCode } from '@/utils/algorithms/session/accessCode';
import { getResearchFeaturesState, setResearchFeaturesEnabled } from '@/utils/researchFeatures';
import { cn } from '@/lib/utils';
import ParticleField from './ParticleField';
import { Switch } from '@/components/ui/switch';
import { Label } from '@/components/ui/label';

interface SessionCreatorProps {
  onSessionStart: (sessionId: string, capabilityToken: string, isHost: boolean, timerMode: string) => void;
  onHoneypotDetected?: (sessionId: string, trapType: string) => void;
}

const SessionCreator = ({ onSessionStart, onHoneypotDetected }: SessionCreatorProps) => {
  const [mode, setMode] = useState<'create' | 'join'>('create');
  const [ghostId, setGhostId] = useState('');
  const [joinId, setJoinId] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [isCopied, setIsCopied] = useState(false);
  const [isWaiting, setIsWaiting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [researchEnabled, setResearchEnabled] = useState(getResearchFeaturesState().enabled);
  
  // Guard against double-execution
  const isCreatingRef = useRef(false);

  const handleCreateSession = async () => {
    // Prevent double execution
    if (isCreatingRef.current || isLoading) return;
    isCreatingRef.current = true;
    
    setIsLoading(true);
    setError(null);
    
    try {
      const newId = generateGhostId();
      const result = await SessionService.reserveSession(newId);
      
      if (!result.success) {
        // Distinguish error types for user
        if (result.errorType === 'NETWORK_ERROR') {
          setError('Network unreachable. Check your connection.');
        } else if (result.errorType === 'RATE_LIMITED') {
          setError('Too many attempts. Please wait a moment.');
        } else {
          setError(result.error || 'Failed to create session');
        }
        return;
      }

      if (!result.capabilityToken) {
        setError('Failed to establish session capability');
        return;
      }

      SecurityManager.setCapabilityToken(newId, result.capabilityToken);
      setGhostId(`${newId}.${result.capabilityToken}`);
      setIsWaiting(true);
      toast.success('Secure channel established');
    } catch {
      setError('Failed to create session. Please retry.');
    } finally {
      setIsLoading(false);
      isCreatingRef.current = false;
    }
  };

  const handleCopyId = async () => {
    await navigator.clipboard.writeText(ghostId);

    setTimeout(() => {
      try {
        void navigator.clipboard.writeText('');
      } catch {
      }
    }, 30000);
    setIsCopied(true);
    toast.success('Access code copied');
    setTimeout(() => setIsCopied(false), 2000);
  };

  const handleStartSession = () => {
    if (ghostId) {
      const parts = ghostId.split('.');
      const sessionId = parts[0] || '';
      const capabilityToken = parts[1] || '';
      onSessionStart(sessionId, capabilityToken, true, 'on-leave');
    }
  };

  const handleJoinSession = async () => {
    if (isLoading) return;
    
    const trimmedId = joinId.trim();
    const rawSessionId = (trimmedId.split('.', 1)[0] || '').trim().toUpperCase();
    
    // Allow both standard format and honeypot formats
    const isStandardFormat = isValidGhostId(rawSessionId);
    const isHoneypotFormat = researchEnabled && HoneypotService.hasHoneypotPrefix(rawSessionId);
    
    if (!isStandardFormat && !isHoneypotFormat) {
      setError('Invalid access code format');
      return;
    }

    const parsed = isStandardFormat ? parseAccessCode(trimmedId) : null;
    if (isStandardFormat && !parsed) {
      setError('Invalid access code (missing capability token)');
      return;
    }

    setIsLoading(true);
    setError(null);
    
    try {
      if (isStandardFormat) {
        SecurityManager.setCapabilityToken(parsed!.sessionId, parsed!.capabilityToken);
        const ok = await SessionService.validateSession(parsed!.sessionId, parsed!.capabilityToken, 'guest');
        if (!ok) {
          setError('Invalid or expired access code');
          SecurityManager.clearCapabilityToken(parsed!.sessionId);
          return;
        }
        onSessionStart(parsed!.sessionId, parsed!.capabilityToken, false, 'on-join');
      } else {
        // Handle honeypot format
        if (!researchEnabled) {
          setError('Invalid access code format');
          return;
        }
        const fingerprint = await SecurityManager.generateFingerprint();
        onHoneypotDetected?.(rawSessionId, fingerprint);
      }
    } catch {
      setError('Failed to join session. Please retry.');
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="min-h-screen min-h-[100dvh] pt-20 pb-8 md:pt-24 md:pb-12 flex items-center justify-center px-4 safe-area-inset-top relative overflow-hidden">
      {/* Cinematic particle background */}
      <ParticleField />
      <div className="w-full max-w-xl mx-auto relative z-10">
        {/* Cinematic Header */}
        <div className="text-center mb-6 md:mb-8">
          <div className="inline-flex items-center gap-2 px-3 py-1.5 rounded-full bg-primary/10 border border-primary/30 text-primary text-xs font-mono uppercase tracking-wider mb-4">
            <Lock className="h-3 w-3" />
            Zero-Knowledge Protocol
          </div>
          <h1 className="font-outfit font-bold text-2xl md:text-3xl lg:text-4xl text-foreground mb-2">
            Initiate Secure Channel
          </h1>
          <p className="text-muted-foreground text-sm md:text-base max-w-md mx-auto">
            End-to-end encrypted. RAM-only. No logs. No trace.
          </p>
        </div>

        {/* Mode Toggle */}
        <div className="flex p-1 rounded-xl bg-secondary/50 backdrop-blur-sm mb-6 md:mb-8 border border-border/30">
          <button
            onClick={() => { setMode('create'); setIsWaiting(false); setGhostId(''); }}
            className={cn(
              "flex-1 py-3 px-4 rounded-lg font-outfit font-semibold transition-all duration-200 touch-target",
              mode === 'create' ? "bg-primary text-primary-foreground shadow-glow-sm" : "text-muted-foreground hover:text-foreground active:text-foreground"
            )}
          >
            Create Channel
          </button>
          <button
            onClick={() => { setMode('join'); setIsWaiting(false); setGhostId(''); }}
            className={cn(
              "flex-1 py-3 px-4 rounded-lg font-outfit font-semibold transition-all duration-200 touch-target",
              mode === 'join' ? "bg-primary text-primary-foreground shadow-glow-sm" : "text-muted-foreground hover:text-foreground active:text-foreground"
            )}
          >
            Join Channel
          </button>
        </div>

        {/* Main Card */}
        <div className="p-5 md:p-8 rounded-2xl glass border border-border/50 session-creator-mobile backdrop-blur-md">
          <div className="mb-5 md:mb-6 flex items-center justify-between p-3 rounded-lg bg-secondary/30 border border-border">
            <div className="flex items-center gap-3">
              <Switch
                checked={researchEnabled}
                onCheckedChange={(enabled) => {
                  setResearchFeaturesEnabled(enabled);
                  setResearchEnabled(enabled);
                }}
              />
              <Label className="text-foreground cursor-pointer">
                Enable research defenses
              </Label>
            </div>
          </div>
          {mode === 'create' ? (
            <>
              {!isWaiting ? (
                <>
                  {/* Cinematic intro text */}
                  <div className="text-center mb-6">
                    <Shield className="h-12 w-12 text-primary mx-auto mb-4 opacity-80" />
                    <p className="text-muted-foreground text-sm">
                      Generate a unique access code to share with your contact.
                      Messages exist only in memory — vanish when you leave.
                    </p>
                  </div>

                  {/* Error display */}
                  {error && (
                    <div className="mb-4 p-3 rounded-lg bg-destructive/10 border border-destructive/30 flex items-center gap-2 text-sm text-destructive">
                      <AlertCircle className="h-4 w-4 flex-shrink-0" />
                      <span>{error}</span>
                    </div>
                  )}
                  
                  {/* Create Button */}
                  <button
                    onClick={handleCreateSession}
                    disabled={isLoading}
                    className="w-full flex items-center justify-center gap-3 py-4 bg-primary text-primary-foreground font-outfit font-bold text-base md:text-lg rounded-xl transition-all duration-300 hover:shadow-glow-md active:scale-[0.98] disabled:opacity-50 min-h-[52px] touch-target"
                  >
                    {isLoading ? (
                      <Loader2 className="h-5 w-5 animate-spin" />
                    ) : error ? (
                      <>
                        <Ghost className="h-5 w-5" />
                        Retry
                      </>
                    ) : (
                      <>
                        <Ghost className="h-5 w-5" />
                        Initialize Secure Channel
                      </>
                    )}
                  </button>
                </>
              ) : (
                <>
                  {/* Ghost ID Display */}
                  <div className="text-center mb-6 md:mb-8">
                    <div className="inline-flex items-center gap-2 px-3 py-1.5 rounded-full bg-accent/20 text-accent text-sm font-medium mb-4 animate-pulse">
                      <div className="w-2 h-2 bg-accent rounded-full" />
                      CHANNEL ACTIVE
                    </div>
                    <p className="text-muted-foreground mb-4 md:mb-6 text-sm md:text-base">
                      Transmit this access code via secure channel only
                    </p>
                    
                    {/* ID Box - Cinematic glowing border */}
                    <div className="relative p-4 md:p-6 rounded-xl bg-background/80 border-2 border-primary/50 mb-4 md:mb-6 shadow-[0_0_30px_rgba(var(--primary-rgb),0.3)] backdrop-blur-sm">
                      <div className="font-mono text-xl md:text-2xl lg:text-3xl font-bold text-primary tracking-[0.2em] ghost-id-display pr-10">
                        {ghostId.split('.')[0]}
                      </div>
                      <button
                        onClick={handleCopyId}
                        className="absolute top-3 right-3 md:top-4 md:right-4 p-2 rounded-lg hover:bg-primary/10 active:bg-primary/20 transition-colors touch-target"
                      >
                        {isCopied ? (
                          <Check className="h-5 w-5 text-accent" />
                        ) : (
                          <Copy className="h-5 w-5 text-muted-foreground" />
                        )}
                      </button>
                    </div>

                    {/* Waiting indicator */}
                    <div className="flex items-center justify-center gap-2 text-muted-foreground mb-6 md:mb-8 text-sm">
                      <div className="flex gap-1">
                        <span className="w-1.5 h-1.5 bg-primary rounded-full animate-bounce [animation-delay:0ms]" />
                        <span className="w-1.5 h-1.5 bg-primary rounded-full animate-bounce [animation-delay:150ms]" />
                        <span className="w-1.5 h-1.5 bg-primary rounded-full animate-bounce [animation-delay:300ms]" />
                      </div>
                      <span>Awaiting connection...</span>
                    </div>
                  </div>

                  {/* Start Button */}
                  <button
                    onClick={handleStartSession}
                    className="w-full flex items-center justify-center gap-3 py-4 bg-primary text-primary-foreground font-outfit font-bold text-base md:text-lg rounded-xl transition-all duration-300 hover:shadow-glow-md active:scale-[0.98] min-h-[52px] touch-target"
                  >
                    Enter Secure Channel
                    <ArrowRight className="h-5 w-5" />
                  </button>
                </>
              )}
            </>
          ) : (
            <>
              {/* Join Session */}
              <div className="text-center mb-6 md:mb-8">
                <Ghost className="h-10 w-10 md:h-12 md:w-12 text-primary mx-auto mb-4" />
                <h2 className="font-outfit font-bold text-xl md:text-2xl text-foreground mb-2">
                  Connect to Secure Channel
                </h2>
                <p className="text-muted-foreground text-sm md:text-base">
                  Enter the access code transmitted by your contact
                </p>
              </div>

              {/* Error display */}
              {error && (
                <div className="mb-4 p-3 rounded-lg bg-destructive/10 border border-destructive/30 flex items-center gap-2 text-sm text-destructive">
                  <AlertCircle className="h-4 w-4 flex-shrink-0" />
                  <span>{error}</span>
                </div>
              )}

              {/* Input with glowing focus */}
              <div className="mb-4 md:mb-6">
                <input
                  type="text"
                  value={joinId}
                  onChange={(e) => { setJoinId(e.target.value); setError(null); }}
                  placeholder="GHOST-XXXX-XXXX.<access-token>"
                  className="w-full p-4 rounded-xl bg-background/80 border-2 border-border/50 focus:border-primary focus:outline-none focus:shadow-[0_0_20px_rgba(var(--primary-rgb),0.3)] font-mono text-base md:text-lg text-center tracking-[0.15em] placeholder:text-muted-foreground/50 transition-all"
                />
              </div>

              {/* Join Button */}
              <button
                onClick={handleJoinSession}
                disabled={isLoading || !joinId.trim()}
                className="w-full flex items-center justify-center gap-3 py-4 bg-primary text-primary-foreground font-outfit font-bold text-base md:text-lg rounded-xl transition-all duration-300 hover:shadow-glow-md active:scale-[0.98] disabled:opacity-50 min-h-[52px] touch-target"
              >
                {isLoading ? (
                  <Loader2 className="h-5 w-5 animate-spin" />
                ) : (
                  <>
                    <Shield className="h-5 w-5" />
                    Establish Connection
                  </>
                )}
              </button>
            </>
          )}
        </div>

        {/* Security Note - Cinematic */}
        <div className="text-center mt-4 md:mt-6 px-2 space-y-2">
          <p className="text-xs text-muted-foreground/60 font-mono uppercase tracking-wider">
            Zero-knowledge • RAM-only • Ephemeral by design
          </p>
          <p className="text-[10px] text-muted-foreground/40">
            Messages exist only in memory. No server logs. No persistence. No trace.
          </p>
        </div>
      </div>
    </div>
  );
};

export default SessionCreator;
