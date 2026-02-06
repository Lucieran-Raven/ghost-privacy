import { cn } from '@/lib/utils';
import type { ConnectionState } from '@/lib/realtimeManager';

const ConnectionStatusIndicator = ({ state }: { state: ConnectionState }) => {
  const getStatusInfo = () => {
    if (state.status === 'connected') {
      return { text: 'Connected', color: 'text-accent', dot: 'bg-accent' };
    }
    if (state.status === 'reconnecting') {
      return { text: 'Reconnecting...', color: 'text-yellow-500', dot: 'bg-yellow-500' };
    }
    return { text: 'Connecting...', color: 'text-muted-foreground', dot: 'bg-muted-foreground' };
  };

  const { text, color, dot } = getStatusInfo();

  return (
    <div className={cn('flex items-center gap-2 text-xs', color)}>
      <div className={cn('w-2 h-2 rounded-full animate-pulse', dot)} />
      <span>{text}</span>
    </div>
  );
};

export default ConnectionStatusIndicator;
