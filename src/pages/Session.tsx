import { useState, useEffect, Suspense, lazy } from 'react';
import { useNavigate } from 'react-router-dom';
import { toast } from 'sonner';
import Navbar from '@/components/Ghost/Navbar';
import SessionCreator from '@/components/Ghost/SessionCreator';
import ClearnetWarning from '@/components/Ghost/ClearnetWarning';
import { usePlausibleDeniability } from '@/hooks/usePlausibleDeniability';

const ChatInterface = lazy(() => import('@/components/Ghost/ChatInterface'));
const HoneypotChat = lazy(() => import('@/components/Ghost/HoneypotChat'));
const DecoyCalculator = lazy(() => import('@/components/Ghost/DecoyCalculator'));

interface SessionState {
  sessionId: string;
  token: string;
  channelToken: string;
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
      e.returnValue = 'Leave Ghost session? RAM-only session data will be destroyed.';
      return e.returnValue;
    };

    window.addEventListener('beforeunload', handleBeforeUnload);
    
    return () => {
      window.removeEventListener('beforeunload', handleBeforeUnload);
    };
  }, [session]);

  const handleSessionStart = (sessionId: string, token: string, channelToken: string, isHost: boolean, timerMode: string) => {
    setSession({ sessionId, token, channelToken, isHost, timerMode });
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

  const baseView = honeypot ? (
    <Suspense fallback={<div />}>
      <HoneypotChat
        sessionId={honeypot.sessionId}
        trapType={honeypot.trapType}
      />
    </Suspense>
  ) : session ? (
    <Suspense fallback={<div />}>
      <ChatInterface
        sessionId={session.sessionId}
        token={session.token}
        channelToken={session.channelToken}
        isHost={session.isHost}
        timerMode={session.timerMode}
        onEndSession={(showToast = true) => handleEndSession(showToast)}
      />
    </Suspense>
  ) : (
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

  return (
    <>
      {baseView}
      {isDecoyActive && (
        <Suspense fallback={<div />}>
          <DecoyCalculator onExit={deactivateDecoy} />
        </Suspense>
      )}
    </>
  );
};

export default Session;

