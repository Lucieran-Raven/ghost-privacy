import { useState } from 'react';
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription } from '@/components/ui/dialog';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
import { Lock, Eye, EyeOff, Shield, AlertTriangle } from 'lucide-react';
import { DeniableEncryption, generateDecoyContent } from '@/utils/deniableEncryption';
import { toast } from 'sonner';
import { cn } from '@/lib/utils';

interface HiddenFileModalProps {
  open: boolean;
  onClose: () => void;
  fileContent: string;
  fileName: string;
  onComplete: (encryptedData: string) => void;
}

const HiddenFileModal = ({ open, onClose, fileContent, fileName, onComplete }: HiddenFileModalProps) => {
  const [step, setStep] = useState<'setup' | 'decoy' | 'passwords'>('setup');
  const [decoyContent, setDecoyContent] = useState('');
  const [outerPassword, setOuterPassword] = useState('');
  const [innerPassword, setInnerPassword] = useState('');
  const [showOuter, setShowOuter] = useState(false);
  const [showInner, setShowInner] = useState(false);
  const [isProcessing, setIsProcessing] = useState(false);
  const MAX_PASSWORD_LEN = 128;
  const MAX_FILE_BASE64_CHARS = 14_000_000;
  const MAX_DECOY_BASE64_CHARS = 2_000_000;
  
  const fileType = fileName.split('.').pop()?.toLowerCase() || 'default';

  const showGenericError = () => {
    toast.error('Unable to proceed');
  };
  
  const handleGenerateDecoy = () => {
    const type = ['jpg', 'jpeg', 'png', 'gif', 'webp'].includes(fileType) ? 'image' :
                 ['doc', 'docx', 'txt', 'pdf'].includes(fileType) ? 'document' :
                 ['xls', 'xlsx', 'csv'].includes(fileType) ? 'spreadsheet' : 'default';
    setDecoyContent(generateDecoyContent(type));
  };
  
  const handleCreateHiddenVolume = async () => {
    const outer = outerPassword.trim();
    const inner = innerPassword.trim();

    if (!outer || !inner) {
      showGenericError();
      return;
    }
    
    if (outer === inner) {
      showGenericError();
      return;
    }
    
    if (outer.length < 6 || inner.length < 6) {
      showGenericError();
      return;
    }

    if (outer.length > MAX_PASSWORD_LEN || inner.length > MAX_PASSWORD_LEN) {
      showGenericError();
      return;
    }

    if (typeof fileContent !== 'string' || fileContent.length === 0 || fileContent.length > MAX_FILE_BASE64_CHARS) {
      showGenericError();
      return;
    }

    if (decoyContent && decoyContent.length > MAX_DECOY_BASE64_CHARS) {
      showGenericError();
      return;
    }
    
    setIsProcessing(true);
    
    try {
      const encryptedData = await DeniableEncryption.createHiddenFile(
        fileContent,
        decoyContent || generateDecoyContent(fileType),
        outer,
        inner
      );
      
      toast.success('Ready');
      onComplete(encryptedData);
      setOuterPassword('');
      setInnerPassword('');
      setDecoyContent('');
      onClose();
    } catch (error) {
      void error;
      showGenericError();
    } finally {
      setIsProcessing(false);
    }
  };
  
  const resetAndClose = () => {
    setStep('setup');
    setDecoyContent('');
    setOuterPassword('');
    setInnerPassword('');
    onClose();
  };

  return (
    <Dialog open={open} onOpenChange={resetAndClose}>
      <DialogContent className="sm:max-w-md bg-background border-border">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2 text-foreground">
            <Shield className="h-5 w-5 text-primary" />
            Hidden Volume Mode
          </DialogTitle>
          <DialogDescription className="text-muted-foreground">
            Create deniable encryption with two plausible unlock states
          </DialogDescription>
        </DialogHeader>
        
        {step === 'setup' && (
          <div className="space-y-4">
            <div className="p-3 rounded-lg bg-primary/10 border border-primary/20">
              <p className="text-sm text-foreground">
                <strong>How it works:</strong> Your file will have two passwords.
                Each password unlocks a different view.
              </p>
            </div>
            
            <div className="p-3 rounded-lg bg-secondary/50 border border-border">
              <p className="text-xs text-muted-foreground mb-1">File to encrypt:</p>
              <p className="text-sm text-foreground font-mono truncate">{fileName}</p>
            </div>
            
            <Button onClick={() => setStep('decoy')} className="w-full">
              Continue
            </Button>
          </div>
        )}
        
        {step === 'decoy' && (
          <div className="space-y-4">
            <div>
              <Label className="text-foreground">Cover Content</Label>
              <Textarea
                value={decoyContent}
                onChange={(e) => setDecoyContent(e.target.value)}
                placeholder="Enter alternate content that can be shown..."
                className="mt-1.5 h-24 bg-secondary/50 border-border text-foreground"
              />
              <Button
                variant="outline"
                size="sm"
                onClick={handleGenerateDecoy}
                className="mt-2"
              >
                Generate Random Cover
              </Button>
            </div>
            
            <div className="flex gap-2">
              <Button variant="outline" onClick={() => setStep('setup')} className="flex-1">
                Back
              </Button>
              <Button onClick={() => setStep('passwords')} className="flex-1">
                Set Passwords
              </Button>
            </div>
          </div>
        )}
        
        {step === 'passwords' && (
          <div className="space-y-4">
            <div className="p-3 rounded-lg bg-destructive/10 border border-destructive/20">
              <div className="flex items-start gap-2">
                <AlertTriangle className="h-4 w-4 text-destructive mt-0.5" />
                <p className="text-xs text-destructive">
                  <strong>Remember both passwords!</strong> There is no recovery.
                  Each password unlocks a different view.
                </p>
              </div>
            </div>
            
            <div>
              <Label className="text-foreground">Password 1</Label>
              <div className="relative mt-1.5">
                <Input
                  type={showOuter ? 'text' : 'password'}
                  value={outerPassword}
                  onChange={(e) => setOuterPassword(e.target.value)}
                  placeholder="Enter password..."
                  className="pr-10 bg-secondary/50 border-border text-foreground"
                />
                <button
                  type="button"
                  onClick={() => setShowOuter(!showOuter)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-muted-foreground"
                >
                  {showOuter ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                </button>
              </div>
            </div>
            
            <div>
              <Label className="text-foreground">Password 2</Label>
              <div className="relative mt-1.5">
                <Input
                  type={showInner ? 'text' : 'password'}
                  value={innerPassword}
                  onChange={(e) => setInnerPassword(e.target.value)}
                  placeholder="Enter password..."
                  className="pr-10 bg-secondary/50 border-border text-foreground"
                />
                <button
                  type="button"
                  onClick={() => setShowInner(!showInner)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-muted-foreground"
                >
                  {showInner ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                </button>
              </div>
            </div>
            
            <div className="flex gap-2">
              <Button variant="outline" onClick={() => setStep('decoy')} className="flex-1">
                Back
              </Button>
              <Button 
                onClick={handleCreateHiddenVolume} 
                disabled={isProcessing}
                className="flex-1"
              >
                {isProcessing ? (
                  <>
                    <Lock className="h-4 w-4 mr-2 animate-pulse" />
                    Encrypting...
                  </>
                ) : (
                  <>
                    <Lock className="h-4 w-4 mr-2" />
                    Create Hidden Volume
                  </>
                )}
              </Button>
            </div>
          </div>
        )}
      </DialogContent>
    </Dialog>
  );
};

export default HiddenFileModal;
