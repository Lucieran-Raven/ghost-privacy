import { useState, useRef, useEffect, useCallback } from 'react';
import { Mic, Square, Send, X, AlertTriangle } from 'lucide-react';
import { SecureVoiceRecorder } from '@/utils/voiceEncryption';
import { cn } from '@/lib/utils';
import PermissionModal from './PermissionModal';

interface VoiceRecorderProps {
  sessionKey: CryptoKey | null;
  onVoiceMessage: (blob: Blob, duration: number) => void;
  disabled: boolean;
  voiceVerified: boolean;
  onRequestVerification: () => void;
}

const VoiceRecorder = ({
  sessionKey,
  onVoiceMessage,
  disabled,
  voiceVerified,
  onRequestVerification
}: VoiceRecorderProps) => {
  const [isRecording, setIsRecording] = useState(false);
  const [recordingTime, setRecordingTime] = useState(0);
  const [showWarning, setShowWarning] = useState(false);
  const [showPermissionModal, setShowPermissionModal] = useState(false);
  const [recordedBlob, setRecordedBlob] = useState<Blob | null>(null);
  const [recordedDuration, setRecordedDuration] = useState(0);
  const recorderRef = useRef<SecureVoiceRecorder | null>(null);
  const timerRef = useRef<NodeJS.Timeout | null>(null);
  const holdTimerRef = useRef<NodeJS.Timeout | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const isHoldingRef = useRef(false);
  const recordingStartTimeRef = useRef<number>(0);

  const MAX_RECORDING_TIME = 60;
  const MIN_RECORDING_TIME = 0.5; // Minimum 0.5 seconds to send

  useEffect(() => {
    return () => {
      if (timerRef.current) clearInterval(timerRef.current);
      if (holdTimerRef.current) clearTimeout(holdTimerRef.current);
      recorderRef.current?.cancelRecording();
    };
  }, []);

  useEffect(() => {
    if (recordingTime >= MAX_RECORDING_TIME && isRecording) {
      handleStopRecording(true);
    }
  }, [recordingTime, isRecording]);

  const startRecording = useCallback(async () => {
    if (!voiceVerified) {
      setShowWarning(true);
      return;
    }

    if (!sessionKey) {
      return;
    }

    try {
      // CRITICAL: Always request fresh microphone stream
      // This fixes the issue where first-time permission grant doesn't work
      const testStream = await navigator.mediaDevices.getUserMedia({ 
        audio: {
          echoCancellation: true,
          noiseSuppression: true,
          autoGainControl: true
        }
      });
      
      // Stop the test stream immediately - we just needed to trigger permission
      testStream.getTracks().forEach(track => track.stop());
      
      // Now create the secure recorder which will get its own stream
      recorderRef.current = new SecureVoiceRecorder(sessionKey);
      await recorderRef.current.startRecording();
      setIsRecording(true);
      setRecordingTime(0);
      setRecordedBlob(null);
      recordingStartTimeRef.current = Date.now();

      timerRef.current = setInterval(() => {
        setRecordingTime(prev => prev + 1);
      }, 1000);
    } catch (error) {
      // Show permission modal for denied access
      if (error instanceof DOMException) {
        if (error.name === 'NotAllowedError' || error.name === 'NotFoundError') {
          setShowPermissionModal(true);
        }
      }
      
      setIsRecording(false);
    }
  }, [voiceVerified, sessionKey]);

  const handleStopRecording = useCallback(async (autoSend: boolean = false) => {
    if (!recorderRef.current || !isRecording) return;

    try {
      if (timerRef.current) {
        clearInterval(timerRef.current);
        timerRef.current = null;
      }

      const { blob, duration } = await recorderRef.current.stopRecording();
      const actualDuration = (Date.now() - recordingStartTimeRef.current) / 1000;
      
      setIsRecording(false);

      // If recording is too short, discard it
      if (actualDuration < MIN_RECORDING_TIME) {
        return;
      }

      if (autoSend) {
        // Auto-send on release
        onVoiceMessage(blob, duration);
      } else {
        // Show preview
        setRecordedBlob(blob);
        setRecordedDuration(duration);
      }
    } catch {
      setIsRecording(false);
    }
  }, [isRecording, onVoiceMessage]);

  const handleCancelRecording = useCallback(() => {
    if (timerRef.current) {
      clearInterval(timerRef.current);
      timerRef.current = null;
    }
    recorderRef.current?.cancelRecording();
    setIsRecording(false);
    setRecordingTime(0);
    setRecordedBlob(null);
    isHoldingRef.current = false;
  }, []);

  const handleSendRecording = useCallback(() => {
    if (recordedBlob) {
      onVoiceMessage(recordedBlob, recordedDuration);
      setRecordedBlob(null);
      setRecordedDuration(0);
    }
  }, [recordedBlob, recordedDuration, onVoiceMessage]);

  const handleDiscardRecording = useCallback(() => {
    setRecordedBlob(null);
    setRecordedDuration(0);
  }, []);

  // Simple click handler - start/stop recording on tap
  const handleClick = useCallback(async (e: React.MouseEvent | React.TouchEvent) => {
    e.preventDefault();
    e.stopPropagation();
    
    if (isRecording) {
      // Stop and send recording
      handleStopRecording(true);
    } else {
      // Start recording
      await startRecording();
    }
  }, [isRecording, voiceVerified, startRecording, handleStopRecording]);

  const handleVerificationRequest = () => {
    setShowWarning(false);
    onRequestVerification();
  };

  const formatTime = (seconds: number) => {
    const mins = Math.floor(seconds / 60);
    const secs = seconds % 60;
    return `${mins}:${secs.toString().padStart(2, '0')}`;
  };

  // Warning modal for unverified voice
  if (showWarning) {
    return (
      <>
        <button
          disabled={disabled}
          className={cn(
            "voice-mic-button",
            "bg-yellow-500/10 text-yellow-500 border border-yellow-500/30"
          )}
          aria-label="Voice not verified"
        >
          <Mic className="h-5 w-5" />
        </button>
        <div className="fixed inset-0 bg-background/95 backdrop-blur-sm z-[100] flex items-center justify-center p-4">
          <div className="max-w-md w-full p-6 rounded-2xl glass border border-destructive/50">
            <div className="flex items-center gap-3 mb-4">
              <div className="p-2 rounded-lg bg-destructive/20">
                <AlertTriangle className="h-6 w-6 text-destructive" />
              </div>
              <h3 className="font-outfit font-bold text-lg text-foreground">
                Voice Verification Required
              </h3>
            </div>
            
            <div className="space-y-3 mb-6 text-sm text-muted-foreground">
              <p>
                <strong className="text-foreground">Without verification, an attacker could:</strong>
              </p>
              <ul className="list-disc list-inside space-y-1 ml-2">
                <li>Intercept and listen to your voice messages</li>
                <li>Replace your voice with fake audio</li>
                <li>Record messages you think vanished</li>
              </ul>
            </div>

            <div className="flex gap-3">
              <button
                onClick={handleVerificationRequest}
                className="flex-1 min-h-[48px] px-4 py-3 bg-primary text-primary-foreground rounded-lg font-medium active:scale-95 transition-transform"
              >
                Verify Now
              </button>
              <button
                onClick={() => setShowWarning(false)}
                className="min-h-[48px] px-4 py-3 bg-muted text-muted-foreground rounded-lg font-medium active:scale-95 transition-colors"
              >
                Cancel
              </button>
            </div>
          </div>
        </div>
      </>
    );
  }

  return (
    <>
      {/* Permission Modal */}
      <PermissionModal
        type="microphone"
        isOpen={showPermissionModal}
        onClose={() => setShowPermissionModal(false)}
        onRetry={() => {
          setShowPermissionModal(false);
          startRecording();
        }}
        onFallback={() => {
          setShowPermissionModal(false);
          fileInputRef.current?.click();
        }}
      />

      {/* Hidden file input for fallback */}
      <input
        ref={fileInputRef}
        type="file"
        accept="audio/*"
        onChange={(e) => {
          const file = e.target.files?.[0];
          e.target.value = '';
          if (file && voiceVerified) {
            onVoiceMessage(file, 0);
          }
        }}
        className="hidden"
      />

      {/* Main Mic Button */}
      <button
        onClick={handleClick}
        onTouchEnd={(e) => {
          e.preventDefault();
          handleClick(e);
        }}
        disabled={disabled}
        className={cn(
          "voice-mic-button select-none cursor-pointer",
          disabled
            ? "bg-muted/30 text-muted-foreground cursor-not-allowed"
            : isRecording
              ? "bg-destructive text-destructive-foreground animate-pulse"
              : voiceVerified
                ? "bg-accent/10 text-accent border border-accent/30 hover:bg-accent/20 active:bg-accent/30"
                : "bg-yellow-500/10 text-yellow-500 border border-yellow-500/30 hover:bg-yellow-500/20"
        )}
        style={{ touchAction: 'manipulation' }}
        aria-label={isRecording ? "Tap to stop recording" : !voiceVerified ? "Verify to enable voice" : "Tap to record"}
      >
        {isRecording ? <Square className="h-5 w-5" /> : <Mic className="h-5 w-5" />}
      </button>

      {/* Recording Overlay */}
      {isRecording && (
        <div className="voice-recording-overlay">
          <div className="voice-recording-indicator">
            <div className="flex items-center gap-3">
              <div className="w-3 h-3 rounded-full bg-destructive animate-pulse" />
              <span className="text-destructive font-medium text-sm">REC</span>
              <span className="font-mono text-sm text-foreground">
                {formatTime(recordingTime)} / {formatTime(MAX_RECORDING_TIME)}
              </span>
            </div>
            <button
              onClick={handleCancelRecording}
              className="p-2 rounded-full bg-muted/50 active:scale-95 transition-transform"
              aria-label="Cancel recording"
            >
              <X className="h-4 w-4 text-muted-foreground" />
            </button>
          </div>
          <p className="text-xs text-muted-foreground mt-2">Release to send • Tap ✕ to cancel</p>
        </div>
      )}

      {/* Preview Overlay */}
      {recordedBlob && !isRecording && (
        <div className="voice-preview-overlay">
          <div className="voice-preview-content">
            <div className="flex items-center gap-3">
              <span className="font-mono text-sm text-foreground">
                {formatTime(Math.round(recordedDuration))}
              </span>
              <span className="text-xs text-muted-foreground">Voice message ready</span>
            </div>
            <div className="flex items-center gap-2">
              <button
                onClick={handleDiscardRecording}
                className="p-3 rounded-full bg-destructive/20 active:scale-95 transition-transform"
                aria-label="Discard"
              >
                <X className="h-5 w-5 text-destructive" />
              </button>
              <button
                onClick={handleSendRecording}
                className="p-3 rounded-full bg-accent active:scale-95 transition-transform shadow-lg shadow-accent/30"
                aria-label="Send"
              >
                <Send className="h-5 w-5 text-accent-foreground" />
              </button>
            </div>
          </div>
        </div>
      )}
    </>
  );
};

export default VoiceRecorder;