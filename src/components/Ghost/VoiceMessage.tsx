import { useState, useRef, useEffect } from 'react';
import { Play, Square, Volume2, AlertTriangle, CheckCircle } from 'lucide-react';
import { SecureVoicePlayer } from '@/utils/voiceEncryption';
import { cn } from '@/lib/utils';

interface VoiceMessageProps {
  messageId: string;
  audioBlob: Blob;
  duration: number;
  sender: 'me' | 'partner';
  timestamp: number;
  onPlayed: (messageId: string) => void;
}

const VoiceMessage = ({
  messageId,
  audioBlob,
  duration,
  sender,
  timestamp,
  onPlayed
}: VoiceMessageProps) => {
  const [isPlaying, setIsPlaying] = useState(false);
  const [hasPlayed, setHasPlayed] = useState(false);
  const [playbackProgress, setPlaybackProgress] = useState(0);
  const [showDestroyedNotice, setShowDestroyedNotice] = useState(false);
  const playerRef = useRef<SecureVoicePlayer | null>(null);
  const progressIntervalRef = useRef<ReturnType<typeof setInterval> | null>(null);

  useEffect(() => {
    return () => {
      if (progressIntervalRef.current) {
        clearInterval(progressIntervalRef.current);
      }
      playerRef.current?.stopPlayback();
    };
  }, []);

  const formatDuration = (ms: number) => {
    const seconds = Math.floor(ms / 1000);
    const mins = Math.floor(seconds / 60);
    const secs = seconds % 60;
    return `${mins}:${secs.toString().padStart(2, '0')}`;
  };

  const formatTime = (ts: number) => {
    return new Date(ts).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  };

  const handlePlay = async () => {
    if (hasPlayed) {
      // Already played - show destroyed notice
      setShowDestroyedNotice(true);
      setTimeout(() => setShowDestroyedNotice(false), 3000);
      return;
    }

    try {
      playerRef.current = new SecureVoicePlayer();
      setIsPlaying(true);
      setPlaybackProgress(0);

      // Progress tracking
      const startTime = Date.now();
      progressIntervalRef.current = setInterval(() => {
        const elapsed = Date.now() - startTime;
        const progress = Math.min((elapsed / duration) * 100, 100);
        setPlaybackProgress(progress);
      }, 50);

      await playerRef.current.playVoiceMessage(audioBlob, messageId, () => {
        // Playback ended
        if (progressIntervalRef.current) {
          clearInterval(progressIntervalRef.current);
        }
        setIsPlaying(false);
        setHasPlayed(true);
        setPlaybackProgress(100);
        onPlayed(messageId);
        
        // Show destroyed notice
        setShowDestroyedNotice(true);
        setTimeout(() => setShowDestroyedNotice(false), 3000);
      });
    } catch (error) {
      void error;
      setIsPlaying(false);
      if (progressIntervalRef.current) {
        clearInterval(progressIntervalRef.current);
      }
    }
  };

  const handleStop = () => {
    playerRef.current?.stopPlayback();
    if (progressIntervalRef.current) {
      clearInterval(progressIntervalRef.current);
    }
    setIsPlaying(false);
    // Still mark as played since it was partially heard
    setHasPlayed(true);
    onPlayed(messageId);
  };

  const isMe = sender === 'me';

  // Destroyed state
  if (hasPlayed && !isPlaying) {
    return (
      <div className={cn(
        "flex flex-col max-w-[280px]",
        isMe ? "ml-auto items-end" : "mr-auto items-start"
      )}>
        <div className={cn(
          "px-4 py-3 rounded-2xl opacity-50",
          isMe
            ? "bg-primary/20 rounded-br-md"
            : "glass border border-border/50 rounded-bl-md"
        )}>
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-full bg-muted/30">
              <CheckCircle className="h-4 w-4 text-muted-foreground" />
            </div>
            <div className="flex-1">
              <p className="text-xs text-muted-foreground line-through">
                Voice message
              </p>
              <p className="text-xs text-muted-foreground/60">
                ☢️ Destroyed after playback
              </p>
            </div>
          </div>
        </div>
        <span className="text-xs text-muted-foreground/50 mt-1 px-2">
          {formatTime(timestamp)}
        </span>
        
        {showDestroyedNotice && (
          <div className="mt-2 px-3 py-1.5 rounded-lg bg-accent/10 border border-accent/30 text-xs text-accent">
            This message has been securely destroyed
          </div>
        )}
      </div>
    );
  }

  return (
    <div className={cn(
      "flex flex-col max-w-[280px]",
      isMe ? "ml-auto items-end" : "mr-auto items-start"
    )}>
      <div className={cn(
        "px-4 py-3 rounded-2xl",
        isMe
          ? "bg-primary/20 rounded-br-md"
          : "glass border border-border/50 rounded-bl-md"
      )}>
        <div className="flex items-center gap-3">
          {/* Play/Stop button */}
          <button
            onClick={isPlaying ? handleStop : handlePlay}
            className={cn(
              "p-2 rounded-full transition-colors",
              isPlaying
                ? "bg-destructive/20 text-destructive hover:bg-destructive/30"
                : "bg-accent/20 text-accent hover:bg-accent/30"
            )}
          >
            {isPlaying ? (
              <Square className="h-4 w-4" />
            ) : (
              <Play className="h-4 w-4" />
            )}
          </button>

          {/* Waveform visualization */}
          <div className="flex-1 space-y-1">
            <div className="flex items-center gap-1 h-6">
              {Array.from({ length: 20 }).map((_, i) => {
                const isActive = (i / 20) * 100 <= playbackProgress;
                const height = Math.random() * 100;
                return (
                  <div
                    key={i}
                    className={cn(
                      "w-1 rounded-full transition-all duration-100",
                      isPlaying && isActive
                        ? "bg-accent"
                        : hasPlayed
                          ? "bg-muted-foreground/30"
                          : "bg-muted-foreground/50"
                    )}
                    style={{
                      height: `${Math.max(20, height)}%`,
                      animationDelay: `${i * 50}ms`
                    }}
                  />
                );
              })}
            </div>
            
            {/* Duration */}
            <div className="flex items-center justify-between text-xs text-muted-foreground">
              <span>{formatDuration(duration)}</span>
              {!hasPlayed && (
                <span className="flex items-center gap-1 text-yellow-500">
                  <AlertTriangle className="h-3 w-3" />
                  Plays once
                </span>
              )}
            </div>
          </div>
        </div>

        {/* Progress bar */}
        {isPlaying && (
          <div className="mt-2 h-1 bg-muted/30 rounded-full overflow-hidden">
            <div
              className="h-full bg-accent transition-all duration-100"
              style={{ width: `${playbackProgress}%` }}
            />
          </div>
        )}
      </div>
      
      <span className="text-xs text-muted-foreground/50 mt-1 px-2">
        {formatTime(timestamp)}
      </span>
    </div>
  );
};

export default VoiceMessage;
