import { useState, useEffect } from 'react';
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription } from '@/components/ui/dialog';
import { Button } from '@/components/ui/button';
import { Label } from '@/components/ui/label';
import { Slider } from '@/components/ui/slider';
import { Switch } from '@/components/ui/switch';
import { Clock, Shuffle, ArrowLeft, ArrowRight, Info } from 'lucide-react';
import { 
  setTimestampConfig, 
  getTimestampConfig, 
  TimestampConfig 
} from '@/utils/plausibleTimestamp';
import { cn } from '@/lib/utils';

interface TimestampSettingsProps {
  open: boolean;
  onClose: () => void;
}

const TimestampSettings = ({ open, onClose }: TimestampSettingsProps) => {
  const [config, setConfig] = useState<TimestampConfig>(getTimestampConfig());
  
  useEffect(() => {
    if (open) {
      setConfig(getTimestampConfig());
    }
  }, [open]);
  
  const handleSave = () => {
    setTimestampConfig(config);
    onClose();
  };
  
  const modeDescriptions = {
    random: 'Timestamps randomly offset ± the window time',
    delayed: 'Messages always appear sent in the past',
    advanced: 'Messages appear sent slightly in the future'
  };

  return (
    <Dialog open={open} onOpenChange={onClose}>
      <DialogContent className="sm:max-w-md bg-background border-border">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2 text-foreground">
            <Clock className="h-5 w-5 text-primary" />
            Plausible Timestamps
          </DialogTitle>
          <DialogDescription className="text-muted-foreground">
            Obfuscate message timing to break surveillance correlation
          </DialogDescription>
        </DialogHeader>
        
        <div className="space-y-6">
          {/* Enable Toggle */}
          <div className="flex items-center justify-between p-3 rounded-lg bg-secondary/30 border border-border">
            <div className="flex items-center gap-3">
              <Switch
                checked={config.enabled}
                onCheckedChange={(enabled) => setConfig({ ...config, enabled })}
              />
              <Label className="text-foreground cursor-pointer">
                Enable timestamp obfuscation
              </Label>
            </div>
          </div>
          
          {config.enabled && (
            <>
              {/* Time Window */}
              <div className="space-y-3">
                <div className="flex items-center justify-between">
                  <Label className="text-foreground">Time Window</Label>
                  <span className="text-sm text-primary font-mono">
                    ±{config.windowMinutes} min
                  </span>
                </div>
                <Slider
                  value={[config.windowMinutes]}
                  onValueChange={([value]) => setConfig({ ...config, windowMinutes: value })}
                  min={5}
                  max={360}
                  step={5}
                  className="w-full"
                />
                <div className="flex justify-between text-xs text-muted-foreground">
                  <span>±5 min</span>
                  <span>±6 hours</span>
                </div>
              </div>
              
              {/* Mode Selection */}
              <div className="space-y-3">
                <Label className="text-foreground">Obfuscation Mode</Label>
                <div className="grid grid-cols-3 gap-2">
                  <button
                    onClick={() => setConfig({ ...config, mode: 'random' })}
                    className={cn(
                      "p-3 rounded-lg border transition-all flex flex-col items-center gap-1.5",
                      config.mode === 'random'
                        ? "border-primary bg-primary/10"
                        : "border-border hover:border-primary/50"
                    )}
                  >
                    <Shuffle className={cn(
                      "h-5 w-5",
                      config.mode === 'random' ? "text-primary" : "text-muted-foreground"
                    )} />
                    <span className={cn(
                      "text-xs font-medium",
                      config.mode === 'random' ? "text-primary" : "text-foreground"
                    )}>
                      Random
                    </span>
                  </button>
                  
                  <button
                    onClick={() => setConfig({ ...config, mode: 'delayed' })}
                    className={cn(
                      "p-3 rounded-lg border transition-all flex flex-col items-center gap-1.5",
                      config.mode === 'delayed'
                        ? "border-primary bg-primary/10"
                        : "border-border hover:border-primary/50"
                    )}
                  >
                    <ArrowLeft className={cn(
                      "h-5 w-5",
                      config.mode === 'delayed' ? "text-primary" : "text-muted-foreground"
                    )} />
                    <span className={cn(
                      "text-xs font-medium",
                      config.mode === 'delayed' ? "text-primary" : "text-foreground"
                    )}>
                      Past
                    </span>
                  </button>
                  
                  <button
                    onClick={() => setConfig({ ...config, mode: 'advanced' })}
                    className={cn(
                      "p-3 rounded-lg border transition-all flex flex-col items-center gap-1.5",
                      config.mode === 'advanced'
                        ? "border-primary bg-primary/10"
                        : "border-border hover:border-primary/50"
                    )}
                  >
                    <ArrowRight className={cn(
                      "h-5 w-5",
                      config.mode === 'advanced' ? "text-primary" : "text-muted-foreground"
                    )} />
                    <span className={cn(
                      "text-xs font-medium",
                      config.mode === 'advanced' ? "text-primary" : "text-foreground"
                    )}>
                      Future
                    </span>
                  </button>
                </div>
                
                <p className="text-xs text-muted-foreground text-center">
                  {modeDescriptions[config.mode]}
                </p>
              </div>
              
              {/* Info Box */}
              <div className="p-3 rounded-lg bg-primary/10 border border-primary/20">
                <div className="flex items-start gap-2">
                  <Info className="h-4 w-4 text-primary mt-0.5" />
                  <p className="text-xs text-foreground">
                    Displayed timestamps are fake. Real timestamps are stored locally
                    for message ordering but never sent to servers or other clients.
                  </p>
                </div>
              </div>
            </>
          )}
          
          <Button onClick={handleSave} className="w-full">
            Save Settings
          </Button>
        </div>
      </DialogContent>
    </Dialog>
  );
};

export default TimestampSettings;
