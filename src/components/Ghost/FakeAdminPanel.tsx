import { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { 
  Shield, Users, MessageSquare, Server, Activity, 
  AlertTriangle, Database, Lock, Clock, Globe,
  TrendingUp, Cpu, HardDrive, Wifi
} from 'lucide-react';
import { getAdminStats, generateFakeErrorLogs } from '@/utils/decoyContent';
import { trapState } from '@/utils/trapState';
import { trapAudio } from '@/utils/trapAudio';
import { bestEffortRandomInt } from '@/utils/secureRng';

interface FakeAdminPanelProps {
  onTimeout: () => void;
}

/**
 * GHOST MIRAGE: Fake Admin Panel
 * 
 * Triggered after 3+ decoy hits. Shows convincing fake:
 * - User statistics
 * - System metrics  
 * - Error logs
 * - Region data
 * 
 * After 5 minutes → "Session terminated for suspicious activity"
 * All data is synthetic. Zero real information.
 * 
 * ⚠️ TRANSPARENT SIMULATION LABEL ⚠️
 * This is a SECURITY TESTING SIMULATION for honeypot detection.
 * No real data is shown. All metrics are fabricated.
 */
const FakeAdminPanel = ({ onTimeout }: FakeAdminPanelProps) => {
  const [stats, setStats] = useState(getAdminStats());
  const [logs] = useState(generateFakeErrorLogs(30));
  const [activeTab, setActiveTab] = useState<'overview' | 'users' | 'logs' | 'system'>('overview');
  const [sessionRef] = useState(trapState.generateSessionReference());
  const [timeRemaining, setTimeRemaining] = useState(300); // 5 minutes

  // Play access granted sound on mount
  useEffect(() => {
    trapAudio.playAccessGranted();
  }, []);

  // Countdown timer
  useEffect(() => {
    const timer = setInterval(() => {
      setTimeRemaining(prev => {
        if (prev <= 1) {
          clearInterval(timer);
          onTimeout();
          return 0;
        }
        return prev - 1;
      });
    }, 1000);

    return () => clearInterval(timer);
  }, [onTimeout]);

  // Update stats periodically (makes it look "live")
  useEffect(() => {
    const interval = setInterval(() => {
      setStats(prev => ({
        ...prev,
        activeUsers: prev.activeUsers + bestEffortRandomInt(3) - 1,
        messagesTotal: prev.messagesTotal + bestEffortRandomInt(10),
        cpuUsage: Math.min(95, Math.max(30, prev.cpuUsage + bestEffortRandomInt(6) - 3)),
        memoryUsage: Math.min(90, Math.max(50, prev.memoryUsage + bestEffortRandomInt(4) - 2)),
      }));
    }, 3000);

    return () => clearInterval(interval);
  }, []);

  const formatTime = (seconds: number) => {
    const m = Math.floor(seconds / 60);
    const s = seconds % 60;
    return `${m}:${s.toString().padStart(2, '0')}`;
  };

  return (
    <div className="min-h-screen bg-background">
      {/* Top bar */}
      <header className="sticky top-0 z-40 bg-card border-b border-border">
        <div className="container mx-auto px-4 py-3 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <Shield className="w-6 h-6 text-primary" />
            <div>
              <h1 className="font-outfit font-bold text-foreground">Ghost Admin Console</h1>
              <p className="text-xs text-muted-foreground">Session: {sessionRef}</p>
            </div>
          </div>
          <div className="flex items-center gap-4">
            <div className="flex items-center gap-2 text-amber-500">
              <Clock className="w-4 h-4" />
              <span className="text-sm font-mono">{formatTime(timeRemaining)}</span>
            </div>
            <div className="flex items-center gap-1.5 px-3 py-1.5 bg-accent/10 rounded-full">
              <div className="w-2 h-2 bg-accent rounded-full animate-pulse" />
              <span className="text-xs text-accent font-medium">LIVE</span>
            </div>
          </div>
        </div>
      </header>

      {/* Navigation */}
      <nav className="bg-muted/30 border-b border-border">
        <div className="container mx-auto px-4">
          <div className="flex gap-1">
            {[
              { id: 'overview', label: 'Overview', icon: Activity },
              { id: 'users', label: 'Users', icon: Users },
              { id: 'logs', label: 'Logs', icon: AlertTriangle },
              { id: 'system', label: 'System', icon: Server },
            ].map(tab => (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id as any)}
                className={`flex items-center gap-2 px-4 py-3 text-sm font-medium transition-colors border-b-2 -mb-px ${
                  activeTab === tab.id 
                    ? 'text-primary border-primary' 
                    : 'text-muted-foreground border-transparent hover:text-foreground'
                }`}
              >
                <tab.icon className="w-4 h-4" />
                {tab.label}
              </button>
            ))}
          </div>
        </div>
      </nav>

      {/* Content */}
      <main className="container mx-auto px-4 py-6">
        {activeTab === 'overview' && (
          <div className="space-y-6">
            {/* Stats grid */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              <motion.div 
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                className="p-4 bg-card rounded-xl border border-border"
              >
                <div className="flex items-center gap-2 text-muted-foreground mb-2">
                  <Users className="w-4 h-4" />
                  <span className="text-sm">Active Users</span>
                </div>
                <p className="text-2xl font-bold text-foreground">{stats.activeUsers}</p>
                <p className="text-xs text-accent flex items-center gap-1 mt-1">
                  <TrendingUp className="w-3 h-3" /> +12% today
                </p>
              </motion.div>

              <motion.div 
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: 0.1 }}
                className="p-4 bg-card rounded-xl border border-border"
              >
                <div className="flex items-center gap-2 text-muted-foreground mb-2">
                  <MessageSquare className="w-4 h-4" />
                  <span className="text-sm">Messages</span>
                </div>
                <p className="text-2xl font-bold text-foreground">{stats.messagesTotal.toLocaleString()}</p>
                <p className="text-xs text-muted-foreground mt-1">All encrypted</p>
              </motion.div>

              <motion.div 
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: 0.2 }}
                className="p-4 bg-card rounded-xl border border-border"
              >
                <div className="flex items-center gap-2 text-muted-foreground mb-2">
                  <Database className="w-4 h-4" />
                  <span className="text-sm">Sessions</span>
                </div>
                <p className="text-2xl font-bold text-foreground">{stats.sessionsActive}</p>
                <p className="text-xs text-muted-foreground mt-1">Active now</p>
              </motion.div>

              <motion.div 
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: 0.3 }}
                className="p-4 bg-card rounded-xl border border-border"
              >
                <div className="flex items-center gap-2 text-muted-foreground mb-2">
                  <Clock className="w-4 h-4" />
                  <span className="text-sm">Uptime</span>
                </div>
                <p className="text-2xl font-bold text-foreground">{stats.uptime}</p>
                <p className="text-xs text-accent mt-1">99.9% SLA</p>
              </motion.div>
            </div>

            {/* Regions */}
            <motion.div 
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.4 }}
              className="p-6 bg-card rounded-xl border border-border"
            >
              <div className="flex items-center gap-2 mb-4">
                <Globe className="w-5 h-5 text-primary" />
                <h2 className="font-outfit font-bold text-foreground">Active Regions</h2>
              </div>
              <div className="flex flex-wrap gap-2">
                {stats.regionsActive.map(region => (
                  <span 
                    key={region}
                    className="px-3 py-1.5 bg-primary/10 text-primary text-sm rounded-full"
                  >
                    {region}
                  </span>
                ))}
              </div>
            </motion.div>
          </div>
        )}

        {activeTab === 'users' && (
          <div className="bg-card rounded-xl border border-border overflow-hidden">
            <div className="p-4 border-b border-border">
              <h2 className="font-outfit font-bold text-foreground">Recent Users</h2>
            </div>
            <div className="divide-y divide-border">
              {Array.from({ length: 10 }).map((_, i) => (
                <div key={i} className="px-4 py-3 flex items-center justify-between hover:bg-muted/30 transition-colors">
                </div>
              ))}
            </div>
          </div>
        )}

        {activeTab === 'logs' && (
          <div className="bg-card rounded-xl border border-border overflow-hidden">
            <div className="p-4 border-b border-border flex items-center justify-between">
              <h2 className="font-outfit font-bold text-foreground">System Logs</h2>
              <span className="text-xs text-muted-foreground">{logs.length} entries</span>
            </div>
            <div className="max-h-96 overflow-y-auto font-mono text-xs">
              {logs.map((log, i) => (
                <div 
                  key={i} 
                  className={`px-4 py-2 border-b border-border/50 ${
                    log.includes('[ERROR]') ? 'bg-destructive/5 text-destructive' :
                    log.includes('[WARN]') ? 'bg-amber-500/5 text-amber-500' :
                    'text-muted-foreground'
                  }`}
                >
                  {log}
                </div>
              ))}
            </div>
          </div>
        )}

        {activeTab === 'system' && (
          <div className="space-y-6">
            <div className="grid md:grid-cols-2 gap-6">
              <motion.div 
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                className="p-6 bg-card rounded-xl border border-border"
              >
                <div className="flex items-center gap-2 mb-4">
                  <Cpu className="w-5 h-5 text-primary" />
                  <h2 className="font-outfit font-bold text-foreground">CPU Usage</h2>
                </div>
                <div className="space-y-2">
                  <div className="flex justify-between text-sm">
                    <span className="text-muted-foreground">Current</span>
                    <span className="text-foreground font-medium">{stats.cpuUsage}%</span>
                  </div>
                  <div className="h-2 bg-muted rounded-full overflow-hidden">
                    <div 
                      className="h-full bg-primary transition-all duration-500 admin-progress"
                      style={{ '--admin-progress': `${stats.cpuUsage}%` } as React.CSSProperties}
                    />
                  </div>
                </div>
              </motion.div>

              <motion.div 
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: 0.1 }}
                className="p-6 bg-card rounded-xl border border-border"
              >
                <div className="flex items-center gap-2 mb-4">
                  <HardDrive className="w-5 h-5 text-primary" />
                  <h2 className="font-outfit font-bold text-foreground">Memory Usage</h2>
                </div>
                <div className="space-y-2">
                  <div className="flex justify-between text-sm">
                    <span className="text-muted-foreground">Current</span>
                    <span className="text-foreground font-medium">{stats.memoryUsage}%</span>
                  </div>
                  <div className="h-2 bg-muted rounded-full overflow-hidden">
                    <div 
                      className="h-full bg-accent transition-all duration-500 admin-progress"
                      style={{ '--admin-progress': `${stats.memoryUsage}%` } as React.CSSProperties}
                    />
                  </div>
                </div>
              </motion.div>
            </div>

            <motion.div 
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.2 }}
              className="p-6 bg-card rounded-xl border border-border"
            >
              <div className="flex items-center gap-2 mb-4">
                <Wifi className="w-5 h-5 text-primary" />
                <h2 className="font-outfit font-bold text-foreground">Network Status</h2>
              </div>
              <div className="grid grid-cols-3 gap-4">
                <div className="text-center">
                  <p className="text-2xl font-bold text-foreground">12ms</p>
                  <p className="text-xs text-muted-foreground">Latency</p>
                </div>
                <div className="text-center">
                  <p className="text-2xl font-bold text-foreground">847</p>
                  <p className="text-xs text-muted-foreground">Req/sec</p>
                </div>
                <div className="text-center">
                  <p className="text-2xl font-bold text-accent">100%</p>
                  <p className="text-xs text-muted-foreground">Uptime</p>
                </div>
              </div>
            </motion.div>
          </div>
        )}
      </main>

      {/* Warning banner */}
      {timeRemaining < 60 && (
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          className="fixed bottom-0 left-0 right-0 p-4 bg-amber-500/10 border-t border-amber-500/20"
        >
          <div className="container mx-auto flex items-center justify-center gap-2 text-amber-500">
            <AlertTriangle className="w-4 h-4" />
            <span className="text-sm font-medium">
              Session expires in {formatTime(timeRemaining)}
            </span>
          </div>
        </motion.div>
      )}
    </div>
  );
};

export default FakeAdminPanel;
