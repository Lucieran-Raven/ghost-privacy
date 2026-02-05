import { useCallback, type Dispatch, type MouseEvent, type SetStateAction } from 'react';
import { toast } from 'sonner';

interface VerificationState {
  show: boolean;
  localFingerprint: string;
  remoteFingerprint: string;
  verified: boolean;
}

interface UseAttachmentPickerGuardsParams {
  isKeyExchangeComplete: boolean;
  verificationState: VerificationState;
  setVerificationState: Dispatch<SetStateAction<VerificationState>>;
}

/**
 * Guards sensitive attachment pickers until key exchange + verification are complete.
 */
export function useAttachmentPickerGuards({
  isKeyExchangeComplete,
  verificationState,
  setVerificationState
}: UseAttachmentPickerGuardsParams) {
  const showVerificationPrompt = useCallback((message: string) => {
    toast.error(message);
    if (!verificationState.show) {
      setVerificationState((prev) => ({ ...prev, show: true }));
    }
  }, [setVerificationState, verificationState.show]);

  const handleFilePickerGate = useCallback((event: MouseEvent) => {
    if (!isKeyExchangeComplete) {
      event.preventDefault();
      return;
    }
    if (!verificationState.verified) {
      event.preventDefault();
      showVerificationPrompt('Please verify security codes before sending files');
    }
  }, [isKeyExchangeComplete, showVerificationPrompt, verificationState.verified]);

  const handleVideoPickerGate = useCallback((event: MouseEvent) => {
    if (!isKeyExchangeComplete) {
      event.preventDefault();
      return;
    }
    if (!verificationState.verified) {
      event.preventDefault();
      showVerificationPrompt('Please verify security codes before sending videos');
    }
  }, [isKeyExchangeComplete, showVerificationPrompt, verificationState.verified]);

  return { handleFilePickerGate, handleVideoPickerGate };
}
