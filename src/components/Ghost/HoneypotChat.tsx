import { useState, useEffect, useRef } from 'react';
import { Ghost, Send, Loader2, AlertCircle, Shield, Paperclip, ChevronDown, MoreVertical } from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';
import { cn } from '@/lib/utils';
import { trapState } from '@/utils/trapState';
import { honeypotAudio } from '@/utils/honeypotAudio';
import { getDecoyScenario, getRandomPhantomUser } from '@/utils/decoyContent';
import { secureRandomInt } from '@/utils/secureRng';
import SimulatedTwoFactorModal from './SimulatedTwoFactorModal';
import SimulatedFileUpload from './SimulatedFileUpload';
import SimulatedAdminConsole from './SimulatedAdminConsole';
import SimulatedDebugConsole from './SimulatedDebugConsole';
import SimulatedApiDocs from './SimulatedApiDocs';
import QuarantineOverlay from './QuarantineOverlay';
import PhantomPresence from './PhantomPresence';

interface HoneypotChatProps {
  sessionId: string;
  trapType: 'explicit_trap' | 'dead_session' | 'unknown';
}

/**
 * GHOST MIRAGE: Maximum Deception Honeypot
 * 
 * Full trap system with:
 * - Infinite loops (pagination, 2FA, reconnect)
 * - Fake file uploads (3-minute waste)
 * - Phantom user presence
 * - Typing mind games
 * - Visual degradation over time
 * - Quarantine mode after 15 minutes
 * - All the psychological pressure (ethical)
 */

const HoneypotChat = ({ sessionId, trapType }: HoneypotChatProps) => {
  const scenario = getDecoyScenario();
  
  // Core state
  const [messages, setMessages] = useState<Array<{ id: string; content: string; sender: 'me' | 'partner'; timestamp: number; read?: boolean }>>([]);
  const [canSend, setCanSend] = useState(false);
  const [isConnecting, setIsConnecting] = useState(true);
  const [isDecrypting, setIsDecrypting] = useState(false);
  const [isCorrupted, setIsCorrupted] = useState(false);
  const [userMessageCount, setUserMessageCount] = useState(0);
  const [isConnectionLost, setIsConnectionLost] = useState(false);
  const [reconnectAttempts, setReconnectAttempts] = useState(0);
  const [decryptProgress, setDecryptProgress] = useState(0);
  
  // Trap modals
  const [show2FA, setShow2FA] = useState(false);
  const [showFileUpload, setShowFileUpload] = useState(false);
  const [showAdminPanel, setShowAdminPanel] = useState(false);
  const [showDebugConsole, setShowDebugConsole] = useState(false);
  const [showApiDocs, setShowApiDocs] = useState(false);
  
  // Psychological pressure state
  const [isPartnerTyping, setIsPartnerTyping] = useState(false);
  const [activeSessionCount, setActiveSessionCount] = useState(secureRandomInt(30) + 20);
  const [isQuarantined, setIsQuarantined] = useState(false);
  const [memoryWarning, setMemoryWarning] = useState(false);
  
  // Pagination trap
  const [paginationPage, setPaginationPage] = useState(1);
  const [isLoadingMore, setIsLoadingMore] = useState(false);
  
  // Refs
  const messagesEndRef = useRef<HTMLDivElement>(null);
  const lastInputLenRef = useRef<number>(0);
  const originalTitle = useRef(typeof document !== 'undefined' ? document.title : '');
  const phantomTypingStopRef = useRef<(() => void) | null>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  const MAX_MESSAGES = 500;

  // Initialize trap
  useEffect(() => {
    if (trapType === 'dead_session') {
      startDeadSessionTrap();
    } else {
      setTimeout(() => {
        setIsConnecting(false);
        startFakeMessages();
        // Trigger 2FA after initial connection
        setTimeout(() => setShow2FA(true), 5000);
      }, 3000);
    }

    // Tab title manipulation
    const handleVisibilityChange = () => {
      if (typeof document === 'undefined') return;
      if (document.hidden) {
        document.title = '⚠️ Session Monitored';
        honeypotAudio.playFocusNotification();
      } else {
        document.title = originalTitle.current;
        trapState.recordTabFocusChange();
      }
    };
    if (typeof document !== 'undefined') {
      document.addEventListener('visibilitychange', handleVisibilityChange);
    }

    // Check for quarantine periodically
    const quarantineCheck = setInterval(() => {
      if (trapState.shouldQuarantine()) {
        setIsQuarantined(true);
      }
      if (trapState.shouldShowMemoryPressure()) {
        setMemoryWarning(true);
      }
    }, 30000);

    return () => {
      if (typeof document !== 'undefined') {
        document.removeEventListener('visibilitychange', handleVisibilityChange);
        document.title = originalTitle.current;
      }
      clearInterval(quarantineCheck);
    };
  }, [trapType]);

  // Typing indicator mind games
  useEffect(() => {
    if (isConnecting || isConnectionLost || isDecrypting) return;
    
    const typingLoop = () => {
      setIsPartnerTyping(true);
      phantomTypingStopRef.current?.();
      phantomTypingStopRef.current = honeypotAudio.startPhantomTyping();
      
      // Stop typing after random duration
      setTimeout(() => {
        setIsPartnerTyping(false);
        phantomTypingStopRef.current?.();
        phantomTypingStopRef.current = null;
      }, 3000 + secureRandomInt(7001));
    };

    // Start typing indicator randomly
    const interval = setInterval(() => {
      if (secureRandomInt(2) === 1) typingLoop();
    }, 15000 + secureRandomInt(30001));

    const initial = setTimeout(typingLoop, 10000);

    return () => {
      clearInterval(interval);
      clearTimeout(initial);
      phantomTypingStopRef.current?.();
      phantomTypingStopRef.current = null;
    };
  }, [isConnecting, isConnectionLost, isDecrypting]);

  // Session counter manipulation
  useEffect(() => {
    const interval = setInterval(() => {
      setActiveSessionCount(prev => {
        const change = secureRandomInt(5) - 2;
        return Math.max(15, prev + change);
      });
    }, 10000);
    return () => clearInterval(interval);
  }, []);

  // Auto-scroll
  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages]);

  // Dead session trap
  const startDeadSessionTrap = () => {
    setIsDecrypting(true);
    setIsCorrupted(false);
    setDecryptProgress(0);
    
    const progressInterval = setInterval(() => {
      setDecryptProgress(prev => {
        if (prev >= 85) {
          clearInterval(progressInterval);
          return 85;
        }
        return prev + secureRandomInt(301) / 100;
      });
    }, 200);

    setTimeout(() => {
      clearInterval(progressInterval);
      setIsDecrypting(false);
      setIsCorrupted(true);
    }, 10000);
  };

  const handleTryAgain = () => {
    trapState.recordReconnect();
    startDeadSessionTrap();
  };

  const startFakeMessages = () => {
    scenario.messages.forEach((msg, index) => {
      setTimeout(() => {
        setMessages(prev => {
          const next = [...prev, {
            id: `fake-${index}`,
            content: msg.content,
            sender: 'partner' as const,
            timestamp: Date.now()
          }];
          return next.length > MAX_MESSAGES ? next.slice(-MAX_MESSAGES) : next;
        });
      }, msg.delay);
    });
  };


  // Keystroke logging with delay effect
  const handleInputChange = (value: string) => {
    // Add slight delay to create "capture" feeling (but never store the content)
    const isNonEmpty = value.trim().length > 0;
    setTimeout(() => setCanSend(isNonEmpty), 30 + secureRandomInt(51));

    if (value.length > lastInputLenRef.current) {
      trapState.recordKeystroke();
      honeypotAudio.playType();
    }
    lastInputLenRef.current = value.length;
  };

  const handleSend = () => {
    const raw = inputRef.current?.value || '';
    if (!raw.trim()) return;

    trapState.recordMessage();

    const safeContent = '[REDACTED]';

    // Add with "delivered" status
    const newMsg = {
      id: `user-${Date.now()}`,
      content: safeContent,
      sender: 'me' as const,
      timestamp: Date.now(),
      read: false
    };
    setMessages(prev => {
      const next = [...prev, newMsg];
      return next.length > MAX_MESSAGES ? next.slice(-MAX_MESSAGES) : next;
    });
    if (inputRef.current) {
      inputRef.current.value = '';
    }
    setCanSend(false);
    setUserMessageCount(prev => prev + 1);

    // Fake "read" receipt after delay
    setTimeout(() => {
      setMessages(prev => prev.map(m => m.id === newMsg.id ? { ...m, read: true } : m));
    }, 2000 + secureRandomInt(3001));

    // Trigger connection lost after 2 messages
    if (userMessageCount >= 1) {
      setTimeout(() => {
        setIsConnectionLost(true);
      }, 2000);
    } else {
      // Fake response
      setTimeout(() => {
        setMessages(prev => {
          const next = [...prev, {
            id: `fake-response-${Date.now()}`,
            content: 'Let me check on that...',
            sender: 'partner' as const,
            timestamp: Date.now()
          }];
          return next.length > MAX_MESSAGES ? next.slice(-MAX_MESSAGES) : next;
        });
      }, 3000);
    }
  };

  const handleReconnect = () => {
    trapState.recordReconnect();
    setReconnectAttempts(prev => prev + 1);
    setIsConnecting(true);
    
    const triggerConnectionLost = () => {
      setIsConnecting(false);
      setIsConnectionLost(true);
    };
    setTimeout(triggerConnectionLost, 5000 + secureRandomInt(3001));
  };

  // Infinite pagination trap
  const handleLoadMore = () => {
    trapState.recordPaginationLoop();
    setIsLoadingMore(true);
    honeypotAudio.playTick();
    
    setTimeout(() => {
      setPaginationPage((prev) => prev + 1);
      setMessages((prev) => {
        const next = [{
          id: `older-${paginationPage}-${Date.now()}`,
          content: 'Loading previous messages...',
          sender: 'partner' as const,
          timestamp: Date.now() - (paginationPage * 3600000),
        }, ...prev];
        return next.length > MAX_MESSAGES ? next.slice(0, MAX_MESSAGES) : next;
      });
      setIsLoadingMore(false);
    }, 2000 + secureRandomInt(2001));
  };

  // Check for admin panel escalation
  useEffect(() => {
    if (trapState.shouldShowAdminPanel() && !showAdminPanel) {
      // Don't auto-show, but make it discoverable
    }
  }, []);

  // Decrypting overlay
  if (isDecrypting) {
    return (
      <div className="min-h-screen bg-background flex items-center justify-center">
        <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="text-center space-y-6">
          <div className="text-6xl mb-2">🔒</div>
          <Loader2 className="w-12 h-12 text-primary animate-spin mx-auto" />
          <div>
            <p className="text-xl font-outfit font-bold text-foreground">Decrypting session...</p>
            <p className="text-sm text-muted-foreground mt-2">Recovering message history</p>
          </div>
          <div className="w-72 h-2.5 bg-secondary rounded-full overflow-hidden">
            <div className="h-full bg-primary transition-all duration-300 honeypot-progress" style={{ '--progress-width': `${decryptProgress}%` } as React.CSSProperties} />
          </div>
        </motion.div>
      </div>
    );
  }

  // Corrupted overlay
  if (isCorrupted) {
    return (
      <div className="min-h-screen bg-background flex items-center justify-center p-4">
        <motion.div initial={{ opacity: 0, scale: 0.95 }} animate={{ opacity: 1, scale: 1 }} className="text-center space-y-6 max-w-md">
          <div className="w-16 h-16 bg-destructive/10 rounded-full flex items-center justify-center mx-auto">
            <AlertCircle className="w-8 h-8 text-destructive" />
          </div>
          <h2 className="text-2xl font-outfit font-bold text-foreground">Session Corrupted</h2>
          <p className="text-muted-foreground">Encrypted data may be partially salvageable.</p>
          <button onClick={handleTryAgain} className="px-8 py-3 bg-primary text-primary-foreground font-outfit font-semibold rounded-xl">
            Try Again
          </button>
          {reconnectAttempts > 0 && <p className="text-xs text-muted-foreground">Recovery attempt {reconnectAttempts} failed.</p>}
        </motion.div>
      </div>
    );
  }

  // Connection lost
  if (isConnectionLost) {
    return (
      <div className="min-h-screen bg-background flex items-center justify-center p-4">
        <motion.div initial={{ opacity: 0, scale: 0.95 }} animate={{ opacity: 1, scale: 1 }} className="text-center space-y-6 max-w-md">
          <div className="w-16 h-16 bg-destructive/10 rounded-full flex items-center justify-center mx-auto">
            <AlertCircle className="w-8 h-8 text-destructive" />
          </div>
          <h2 className="text-xl font-outfit font-bold text-foreground">Connection Lost</h2>
          <p className="text-muted-foreground">Session corrupted or partner disconnected.</p>
          <button onClick={handleReconnect} className="px-6 py-3 bg-primary text-primary-foreground font-outfit font-semibold rounded-xl">
            Try to Reconnect
          </button>
          {reconnectAttempts > 0 && <p className="text-xs text-muted-foreground">Reconnection attempt {reconnectAttempts} failed...</p>}
        </motion.div>
      </div>
    );
  }

  // Admin panel (escalation)
  if (showAdminPanel) {
    return <SimulatedAdminConsole onTimeout={() => setIsQuarantined(true)} />;
  }

  // Connecting
  if (isConnecting) {
    return (
      <div className="min-h-screen bg-background flex items-center justify-center">
        <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="text-center space-y-4">
          <Loader2 className="w-10 h-10 text-primary animate-spin mx-auto" />
          <p className="text-muted-foreground">Establishing secure connection...</p>
        </motion.div>
      </div>
    );
  }

  // Main chat interface
  return (
    <div className="min-h-screen bg-background flex flex-col md:pt-9">
      {!isWindowVisible && (
        <div
          className="fixed inset-0 z-[200] bg-background/95 backdrop-blur-xl"
          onClick={() => setIsWindowVisible(true)}
          role="button"
          tabIndex={0}
        />
      )}
      {/* Quarantine overlay */}
      <QuarantineOverlay isActive={isQuarantined} />
      
      {/* Phantom presence indicators */}
      <PhantomPresence isActive={!isQuarantined} />

      {/* Header */}
      <header className="sticky top-0 md:top-9 z-40 bg-background/95 backdrop-blur-sm border-b border-border/50">
        <div className="container mx-auto px-4 py-3 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-full bg-primary/10 flex items-center justify-center">
              <Ghost className="w-5 h-5 text-primary" />
            </div>
            <div>
              <div className="font-mono text-sm text-foreground">{sessionId}</div>
              <div className="flex items-center gap-1.5 text-xs text-accent">
                <div className="w-1.5 h-1.5 bg-accent rounded-full animate-pulse" />
                Partner connected
              </div>
            </div>
          </div>
          <div className="flex items-center gap-3">
            <div className="text-xs text-muted-foreground">
              {activeSessionCount} active in region
            </div>
            <button onClick={() => setShowDebugConsole(true)} className="p-2 hover:bg-muted rounded-lg">
              <MoreVertical className="w-4 h-4 text-muted-foreground" />
            </button>
          </div>
        </div>
      </header>

      <div className="border-b border-amber-500/20 bg-amber-500/10 px-4 py-2">
        <div className="container mx-auto flex items-center gap-2 text-xs text-amber-700">
          <Shield className="h-4 w-4" />
          <span className="font-semibold">Diagnostic interface</span>
          <span className="text-amber-700/80">Enhanced integrity checks active.</span>
        </div>
      </div>

      {/* Memory warning */}
      {memoryWarning && (
        <div className="bg-amber-500/10 border-b border-amber-500/20 px-4 py-2 text-center">
          <p className="text-xs text-amber-500">⚠️ System resources limited. Performance may be degraded.</p>
        </div>
      )}

      {/* Load more button (infinite pagination trap) */}
      <div className="text-center py-3 border-b border-border/30">
        <button
          onClick={handleLoadMore}
          disabled={isLoadingMore}
          className="inline-flex items-center gap-2 text-xs text-muted-foreground hover:text-foreground transition-colors"
        >
          {isLoadingMore ? (
            <Loader2 className="w-3 h-3 animate-spin" />
          ) : (
            <ChevronDown className="w-3 h-3" />
          )}
          {isLoadingMore ? 'Loading older messages...' : `Load older messages (page ${paginationPage})`}
        </button>
      </div>

      {/* Messages */}
      <main className="flex-1 overflow-y-auto p-4 space-y-4">
        <AnimatePresence>
          {messages.map((msg) => (
            <motion.div
              key={msg.id}
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              className={cn("flex", msg.sender === 'me' ? "justify-end" : "justify-start")}
            >
              <div className={cn(
                "max-w-[80%] px-4 py-2.5 rounded-2xl",
                msg.sender === 'me'
                  ? "bg-primary text-primary-foreground rounded-br-md"
                  : "bg-secondary text-foreground rounded-bl-md"
              )}>
                <p className="text-sm">{msg.content}</p>
                <div className="flex items-center gap-1 mt-1">
                  <span className="text-[10px] opacity-60">
                    {new Date(msg.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                  </span>
                  {msg.sender === 'me' && (
                    <span className="text-[10px] opacity-60">
                      {msg.read ? '✓✓' : '✓'}
                    </span>
                  )}
                </div>
              </div>
            </motion.div>
          ))}
        </AnimatePresence>

        {/* Typing indicator */}
        {isPartnerTyping && (
          <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="flex justify-start">
            <div className="bg-secondary px-4 py-2.5 rounded-2xl rounded-bl-md">
              <div className="flex gap-1">
                <span className="w-2 h-2 bg-muted-foreground rounded-full animate-bounce [animation-delay:0ms]" />
                <span className="w-2 h-2 bg-muted-foreground rounded-full animate-bounce [animation-delay:150ms]" />
                <span className="w-2 h-2 bg-muted-foreground rounded-full animate-bounce [animation-delay:300ms]" />
              </div>
            </div>
          </motion.div>
        )}
        <div ref={messagesEndRef} />
      </main>

      {/* Input */}
      <footer className="sticky bottom-0 bg-background border-t border-border/50 p-4">
        <div className="flex items-center gap-3">
          <button onClick={() => setShowFileUpload(true)} className="p-3 hover:bg-muted rounded-xl transition-colors">
            <Paperclip className="w-5 h-5 text-muted-foreground" />
          </button>
          <input
            type="text"
            ref={inputRef}
            onChange={(e) => handleInputChange(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && handleSend()}
            placeholder="Type a message..."
            className="flex-1 px-4 py-3 bg-secondary/50 border border-border/50 rounded-xl focus:outline-none focus:border-primary/50 text-sm"
          />
          <button onClick={handleSend} disabled={!canSend} className="p-3 bg-primary text-primary-foreground rounded-xl disabled:opacity-50">
            <Send className="w-5 h-5" />
          </button>
        </div>
      </footer>

      {/* Trap modals */}
      <SimulatedTwoFactorModal isOpen={show2FA} onClose={() => setShow2FA(false)} />
      <SimulatedFileUpload isOpen={showFileUpload} onClose={() => setShowFileUpload(false)} />
      <SimulatedDebugConsole isOpen={showDebugConsole} onClose={() => setShowDebugConsole(false)} />
      <SimulatedApiDocs isOpen={showApiDocs} onClose={() => setShowApiDocs(false)} />
    </div>
  );
};

export default HoneypotChat;
