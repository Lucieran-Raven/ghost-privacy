import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { toast } from 'sonner';
import Navbar from '@/components/Ghost/Navbar';
import SessionCreator from '@/components/Ghost/SessionCreator';
import ChatInterface from '@/components/Ghost/ChatInterface';
import HoneypotChat from '@/components/Ghost/HoneypotChat';
import ClearnetWarning from '@/components/Ghost/ClearnetWarning';
import DecoyCalculator from '@/components/Ghost/DecoyCalculator';
import { usePlausibleDeniability } from '@/hooks/usePlausibleDeniability';

interface SessionState {
  sessionId: string;
  capabilityToken: string;
  isHost: boolean;
  timerMode: string;
}

interface HoneypotState {
  sessionId: string;
  trapType: 'explicit_trap' | 'dead_session' | 'unknown';
}

const Session = () => {
  const navigate = useNavigate();
  const [session, setSession] = useState<SessionState | null>(null);
  const [honeypot, setHoneypot] = useState<HoneypotState | null>(null);

  // Ghost v3.0: Plausible Deniability
  const { isDecoyActive, deactivateDecoy } = usePlausibleDeniability();

  // SECURITY: Warn user but NEVER auto-terminate on navigation
  useEffect(() => {
    if (!session) return;

    const handleBeforeUnload = (e: BeforeUnloadEvent) => {
      e.preventDefault();
      e.returnValue = 'Leave Ghost session? Messages will be preserved until you click "End Session".';
      return e.returnValue;
    };

    window.addEventListener('beforeunload', handleBeforeUnload);
    
    return () => {
      window.removeEventListener('beforeunload', handleBeforeUnload);
    };
  }, [session]);

  const handleSessionStart = (sessionId: string, capabilityToken: string, isHost: boolean, timerMode: string) => {
    setSession({ sessionId, capabilityToken, isHost, timerMode });
  };

  const handleHoneypotDetected = (sessionId: string, trapType: string) => {
    setHoneypot({ 
      sessionId, 
      trapType: trapType as 'explicit_trap' | 'dead_session' | 'unknown' 
    });
  };

  const handleEndSession = (showToast = true) => {
    setSession(null);
    // Only show toast when manually ending, not when navigating
    if (showToast) {
      toast.success('Session terminated. All data destroyed.');
    }
    navigate('/');
  };

  // Ghost v3.0: Show decoy calculator when panic mode activated
  if (isDecoyActive) {
    return <DecoyCalculator onExit={deactivateDecoy} />;
  }

  // Show honeypot interface if triggered
  if (honeypot) {
    return (
      <HoneypotChat
        sessionId={honeypot.sessionId}
        trapType={honeypot.trapType}
      />
    );
  }

  if (session) {
    return (
      <ChatInterface
        sessionId={session.sessionId}
        capabilityToken={session.capabilityToken}
        isHost={session.isHost}
        timerMode={session.timerMode}
        onEndSession={(showToast = true) => handleEndSession(showToast)}
      />
    );
  }

  return (
    <div className="min-h-screen bg-background">
      <Navbar />
      <div className="pt-20 md:pt-24">
        <div className="container mx-auto px-4">
          <ClearnetWarning className="max-w-2xl mx-auto mb-6" />
        </div>
        <SessionCreator 
          onSessionStart={handleSessionStart} 
          onHoneypotDetected={handleHoneypotDetected}
        />
      </div>
    </div>
  );
};

export default Session;

