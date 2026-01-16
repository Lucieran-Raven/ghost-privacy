import { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { User, LogIn, LogOut } from 'lucide-react';
import { getRandomPhantomUser } from '@/utils/decoyContent';
import { trapState } from '@/utils/trapState';
import { trapAudio } from '@/utils/trapAudio';
import { secureRandomInt } from '@/utils/secureRng';

interface PhantomPresenceProps {
  isActive: boolean;
}

interface PhantomEvent {
  id: string;
  type: 'join' | 'leave';
  username: string;
  timestamp: number;
}

/**
 * GHOST MIRAGE: Phantom Presence Indicators
 * 
 * Shows fake "User joined" / "User left" notifications.
 * Creates paranoia that someone is watching.
 * All users are completely fabricated.
 */
const PhantomPresence = ({ isActive }: PhantomPresenceProps) => {
  const [events, setEvents] = useState<PhantomEvent[]>([]);

  useEffect(() => {
    if (!isActive) return;

    const createPhantomEvent = () => {
      const username = getRandomPhantomUser();
      const type = secureRandomInt(10) >= 4 ? 'join' : 'leave';
      
      const event: PhantomEvent = {
        id: `phantom-${Date.now()}-${secureRandomInt(0x100000000)}`,
        type,
        username,
        timestamp: Date.now(),
      };

      trapState.recordPhantomUser(username);
      
      if (type === 'join') {
        trapAudio.playJoin();
      } else {
        trapAudio.playLeave();
      }

      setEvents(prev => [...prev.slice(-4), event]);

      // Remove after 5 seconds
      setTimeout(() => {
        setEvents(prev => prev.filter(e => e.id !== event.id));
      }, 5000);
    };

    // Initial event after 10-30 seconds
    const initialTimeout = setTimeout(createPhantomEvent, 10000 + secureRandomInt(20001));

    // Subsequent events every 30-90 seconds
    const interval = setInterval(() => {
      if (secureRandomInt(10) >= 3) { // 70% chance each interval
        createPhantomEvent();
      }
    }, 30000 + secureRandomInt(60001));

    return () => {
      clearTimeout(initialTimeout);
      clearInterval(interval);
    };
  }, [isActive]);

  if (!isActive) return null;

  return (
    <div className="fixed top-20 right-4 z-50 space-y-2 pointer-events-none">
      <AnimatePresence>
        {events.map(event => (
          <motion.div
            key={event.id}
            initial={{ opacity: 0, x: 50, scale: 0.9 }}
            animate={{ opacity: 1, x: 0, scale: 1 }}
            exit={{ opacity: 0, x: 50, scale: 0.9 }}
            className={`flex items-center gap-2 px-3 py-2 rounded-lg backdrop-blur-sm border ${
              event.type === 'join' 
                ? 'bg-accent/10 border-accent/20' 
                : 'bg-muted/50 border-border/50'
            }`}
          >
            <div className={`w-6 h-6 rounded-full flex items-center justify-center ${
              event.type === 'join' ? 'bg-accent/20' : 'bg-muted'
            }`}>
              {event.type === 'join' ? (
                <LogIn className="w-3 h-3 text-accent" />
              ) : (
                <LogOut className="w-3 h-3 text-muted-foreground" />
              )}
            </div>
            <div>
              <p className="text-xs font-medium text-foreground">
                {event.type === 'join' ? 'User joined' : 'User left'}
              </p>
              <p className="text-[10px] text-muted-foreground font-mono">
                {event.username}
              </p>
            </div>
          </motion.div>
        ))}
      </AnimatePresence>
    </div>
  );
};

export default PhantomPresence;
