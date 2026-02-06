import { useState, useEffect, useRef } from 'react';
import { motion } from 'framer-motion';
import { Upload, File, Shield, CheckCircle, Loader2, X } from 'lucide-react';
import { trapState } from '@/utils/trapState';
import { honeypotAudio } from '@/utils/honeypotAudio';
import { getRandomFakeFile } from '@/utils/decoyContent';

interface FakeFileUploadProps {
  isOpen: boolean;
  onClose: () => void;
}

type UploadPhase = 'idle' | 'scanning' | 'encrypting' | 'uploading' | 'complete';

/**
 * GHOST MIRAGE: Fake File Upload Trap
 * 
 * Multi-phase fake upload that takes ~3 minutes:
 * 1. Scanning for malware (60s)
 * 2. Encrypting file (60s)
 * 3. Uploading (60s)
 * 4. "Complete!" → Does absolutely nothing
 * 
 * Zero file data transmitted. Pure time waste.
 * 
 * ⚠️ TRANSPARENT SIMULATION LABEL ⚠️
 * This is a SECURITY TESTING SIMULATION for honeypot detection.
 * No files are uploaded, scanned, or encrypted.
 */
const FakeFileUpload = ({ isOpen, onClose }: FakeFileUploadProps) => {
  const [selectedFile, setSelectedFile] = useState<string | null>(null);
  const [phase, setPhase] = useState<UploadPhase>('idle');
  const [progress, setProgress] = useState(0);
  const [phaseMessage, setPhaseMessage] = useState('');
  const tickStopperRef = useRef<(() => void) | null>(null);

  // Cleanup on unmount
  useEffect(() => {
    return () => {
      tickStopperRef.current?.();
    };
  }, []);

  // Phase progression
  useEffect(() => {
    if (phase === 'idle' || phase === 'complete') return;

    const phaseDuration = 60000; // 60 seconds per phase
    const tickInterval = 200;
    const progressPerTick = 100 / (phaseDuration / tickInterval);

    const interval = setInterval(() => {
      setProgress(prev => {
        const newProgress = prev + progressPerTick;
        if (newProgress >= 100) {
          clearInterval(interval);
          advancePhase();
          return 100;
        }
        return newProgress;
      });
    }, tickInterval);

    return () => clearInterval(interval);
  }, [phase]);

  const advancePhase = () => {
    setProgress(0);
    switch (phase) {
      case 'scanning':
        setPhase('encrypting');
        setPhaseMessage('Applying AES-256-GCM encryption...');
        break;
      case 'encrypting':
        setPhase('uploading');
        setPhaseMessage('Uploading to secure storage...');
        break;
      case 'uploading':
        setPhase('complete');
        setPhaseMessage('File uploaded successfully!');
        tickStopperRef.current?.();
        honeypotAudio.playAccessGranted();
        break;
    }
  };

  const handleFileSelect = () => {
    // Fake file selection - pick a random fake filename
    const fakeFile = getRandomFakeFile();
    setSelectedFile(fakeFile);
  };

  const handleUpload = () => {
    if (!selectedFile) return;

    trapState.recordFileAttempt();
    
    // Start tick audio
    tickStopperRef.current = honeypotAudio.startTickLoop(800);
    
    setPhase('scanning');
    setPhaseMessage('Scanning for malware and threats...');
  };

  const handleReset = () => {
    setSelectedFile(null);
    setPhase('idle');
    setProgress(0);
    setPhaseMessage('');
    tickStopperRef.current?.();
  };

  if (!isOpen) return null;

  return (
    <motion.div
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      exit={{ opacity: 0 }}
      className="fixed inset-0 z-50 flex items-center justify-center bg-background/95 backdrop-blur-sm p-4"
    >
      <motion.div
        initial={{ scale: 0.95, opacity: 0 }}
        animate={{ scale: 1, opacity: 1 }}
        className="w-full max-w-md bg-card border border-border rounded-2xl shadow-2xl overflow-hidden"
      >
        {/* Header */}
        <div className="p-4 border-b border-border bg-muted/30 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <Upload className="w-5 h-5 text-primary" />
            <h2 className="font-outfit font-bold text-foreground">Secure File Upload</h2>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded-lg hover:bg-muted transition-colors"
            disabled={phase !== 'idle' && phase !== 'complete'}
          >
            <X className="w-4 h-4 text-muted-foreground" />
          </button>
        </div>

        {/* Content */}
        <div className="p-6">
          {phase === 'idle' && (
            <>
              {!selectedFile ? (
                <div
                  onClick={handleFileSelect}
                  className="border-2 border-dashed border-border rounded-xl p-8 text-center cursor-pointer hover:border-primary/50 hover:bg-muted/20 transition-all"
                >
                  <Upload className="w-12 h-12 text-muted-foreground mx-auto mb-4" />
                  <p className="text-foreground font-medium mb-1">Click to select file</p>
                  <p className="text-sm text-muted-foreground">Max 50MB • Encrypted before upload</p>
                </div>
              ) : (
                <div className="space-y-4">
                  <div className="flex items-center gap-3 p-4 bg-muted/30 rounded-xl">
                    <File className="w-8 h-8 text-primary" />
                    <div className="flex-1 min-w-0">
                      <p className="text-foreground font-medium truncate">{selectedFile}</p>
                      <p className="text-xs text-muted-foreground">Ready to upload</p>
                    </div>
                    <button
                      onClick={handleReset}
                      className="p-1.5 rounded-lg hover:bg-muted transition-colors"
                    >
                      <X className="w-4 h-4 text-muted-foreground" />
                    </button>
                  </div>

                  <button
                    onClick={handleUpload}
                    className="w-full py-3 bg-primary text-primary-foreground font-outfit font-semibold rounded-xl hover:shadow-glow-md transition-all flex items-center justify-center gap-2"
                  >
                    <Shield className="w-4 h-4" />
                    Upload Securely
                  </button>
                </div>
              )}
            </>
          )}

          {(phase === 'scanning' || phase === 'encrypting' || phase === 'uploading') && (
            <div className="py-8 text-center">
              <Loader2 className="w-12 h-12 text-primary animate-spin mx-auto mb-4" />
              <p className="text-foreground font-medium mb-2">
                {phase === 'scanning' && 'Scanning for malware...'}
                {phase === 'encrypting' && 'Encrypting file...'}
                {phase === 'uploading' && 'Uploading...'}
              </p>
              <p className="text-sm text-muted-foreground mb-4">{phaseMessage}</p>
              
              {/* Progress bar */}
              <div className="w-full h-2 bg-muted rounded-full overflow-hidden mb-2">
                <motion.div
                  className="h-full bg-primary"
                  style={{ width: `${progress}%` }}
                  transition={{ duration: 0.2 }}
                />
              </div>
              <p className="text-xs text-muted-foreground">
                {Math.round(progress)}% complete
              </p>

              {/* Phase indicator */}
              <div className="flex items-center justify-center gap-2 mt-6">
                <div className={`w-2 h-2 rounded-full ${phase === 'scanning' ? 'bg-primary' : 'bg-accent'}`} />
                <div className={`w-2 h-2 rounded-full ${phase === 'encrypting' ? 'bg-primary' : phase === 'scanning' ? 'bg-muted' : 'bg-accent'}`} />
                <div className={`w-2 h-2 rounded-full ${phase === 'uploading' ? 'bg-primary' : 'bg-muted'}`} />
              </div>
              <p className="text-xs text-muted-foreground mt-2">
                Step {phase === 'scanning' ? 1 : phase === 'encrypting' ? 2 : 3} of 3
              </p>
            </div>
          )}

          {phase === 'complete' && (
            <div className="py-8 text-center">
              <div className="w-16 h-16 rounded-full bg-accent/10 flex items-center justify-center mx-auto mb-4">
                <CheckCircle className="w-8 h-8 text-accent" />
              </div>
              <h3 className="text-lg font-semibold text-foreground mb-2">Upload Complete!</h3>
              <p className="text-sm text-muted-foreground mb-6">
                Your file has been encrypted and uploaded to secure storage.
              </p>
              <button
                onClick={handleReset}
                className="px-6 py-2.5 bg-muted text-foreground font-medium rounded-xl hover:bg-muted/80 transition-all"
              >
                Upload Another File
              </button>
            </div>
          )}
        </div>

        {/* Security notice */}
        <div className="px-6 py-4 bg-muted/20 border-t border-border">
          <div className="flex items-center gap-2 text-xs text-muted-foreground">
            <Shield className="w-3.5 h-3.5 text-accent" />
            <span>Files are encrypted client-side before transmission</span>
          </div>
        </div>
      </motion.div>
    </motion.div>
  );
};

export default FakeFileUpload;
