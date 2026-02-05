import { useState, useRef, useEffect } from 'react';
import { motion } from 'framer-motion';
import { Terminal, X } from 'lucide-react';
import { trapState } from '@/utils/trapState';
import { trapAudio } from '@/utils/deceptionAudioEngine';
import { bestEffortRandomInt } from '@/utils/secureRng';

interface FakeDebugConsoleProps {
  isOpen: boolean;
  onClose: () => void;
}

/**
 * GHOST MIRAGE: Fake Debug Console
 * 
 * Terminal-like interface that accepts commands and returns
 * convincing but completely fictional system information.
 * 
 * Supported fake commands:
 * - ls, dir, cat, whoami, pwd, help, clear, etc.
 * 
 * All output is synthetic. Zero real system access.
 * 
 * ⚠️ TRANSPARENT SIMULATION LABEL ⚠️
 * This is a SECURITY TESTING SIMULATION for honeypot detection.
 * No real system information or commands are executed.
 */

const FAKE_RESPONSES: Record<string, string | (() => string)> = {
  'help': `Available commands:
  ls, dir    - List directory contents
  cat        - Display file contents
  whoami     - Display current user
  pwd        - Print working directory
  ps         - List running processes
  netstat    - Network statistics
  uptime     - System uptime
  df         - Disk usage
  free       - Memory usage
  env        - Environment variables
  clear      - Clear screen
  exit       - Close console`,

  'ls': `total 24
drwxr-xr-x  5 ghost ghost 4096 Dec 16 08:30 .
drwxr-xr-x  3 root  root  4096 Dec 01 00:00 ..
-rw-------  1 ghost ghost  847 Dec 16 08:30 .bash_history
drwx------  2 ghost ghost 4096 Dec 15 14:22 .cache
drwxr-xr-x  3 ghost ghost 4096 Dec 14 09:15 .config
-rw-r--r--  1 ghost ghost  220 Dec 01 00:00 .profile
drwxr-xr-x  4 ghost ghost 4096 Dec 16 08:00 app`,

  'dir': `total 24
drwxr-xr-x  5 ghost ghost 4096 Dec 16 08:30 .
drwxr-xr-x  3 root  root  4096 Dec 01 00:00 ..
-rw-------  1 ghost ghost  847 Dec 16 08:30 .bash_history
drwx------  2 ghost ghost 4096 Dec 15 14:22 .cache
drwxr-xr-x  3 ghost ghost 4096 Dec 14 09:15 .config
-rw-r--r--  1 ghost ghost  220 Dec 01 00:00 .profile
drwxr-xr-x  4 ghost ghost 4096 Dec 16 08:00 app`,

  'cat .bash_history': `cd /var/log
tail -f syslog
grep "error" /var/log/ghost.log
systemctl status ghost-api
curl -s localhost:8080/health
psql -U ghost -d sessions
npm run cleanup
exit`,

  'cat .profile': `# ~/.profile: executed by the command interpreter for login shells.
export GHOST_ENV="production"
export GHOST_REGION="us-east-1"
export DB_HOST="10.0.1.42"
export REDIS_HOST="10.0.1.43"
# Security: API keys loaded from vault`,

  'whoami': 'ghost',
  
  'pwd': '/home/ghost',

  'ps': `  PID TTY          TIME CMD
    1 ?        00:00:03 systemd
  847 ?        00:12:47 ghost-api
  848 ?        00:05:23 ghost-worker
  921 ?        00:00:12 redis-server
 1024 ?        00:00:45 postgres
 1847 pts/0    00:00:00 bash
 1923 pts/0    00:00:00 ps`,

  'ps aux': `USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root         1  0.0  0.1  22552  1824 ?        Ss   Dec14   0:03 /sbin/init
ghost      847  2.4 12.3 847284 126208 ?       Sl   Dec14  12:47 node /app/server.js
ghost      848  1.1  5.7 324156 58432 ?        Sl   Dec14   5:23 node /app/worker.js
redis      921  0.2  0.8  43584  8724 ?        Ssl  Dec14   0:12 redis-server *:6379
postgres  1024  0.5  2.1 215648 21984 ?        Ss   Dec14   0:45 postgres
ghost     1847  0.0  0.1  21456  1984 pts/0    Ss   08:30   0:00 -bash
ghost     1923  0.0  0.1  36080  1792 pts/0    R+   08:35   0:00 ps aux`,

  'netstat': `Active Internet connections
Proto Recv-Q Send-Q Local Address           Foreign Address         State
tcp        0      0 0.0.0.0:443             0.0.0.0:*               LISTEN
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN
tcp        0      0 127.0.0.1:5432          0.0.0.0:*               LISTEN
tcp        0      0 127.0.0.1:6379          0.0.0.0:*               LISTEN
tcp        0    284 10.0.1.10:443           89.123.45.67:52847      ESTABLISHED
tcp        0      0 10.0.1.10:443           12.34.56.78:48291       TIME_WAIT`,

  'uptime': () => {
    const days = bestEffortRandomInt(30) + 1;
    const hours = bestEffortRandomInt(24);
    const mins = bestEffortRandomInt(60);
    return ` 08:35:47 up ${days} days, ${hours}:${mins.toString().padStart(2, '0')},  1 user,  load average: 0.42, 0.38, 0.35`;
  },

  'df': `Filesystem     1K-blocks     Used Available Use% Mounted on
/dev/sda1       51475068 12847392  36007132  27% /
tmpfs            4096000   284720   3811280   7% /dev/shm
/dev/sdb1      103081248 45872104  51949988  47% /data`,

  'df -h': `Filesystem      Size  Used Avail Use% Mounted on
/dev/sda1        50G   13G   35G  27% /
tmpfs           4.0G  279M  3.7G   7% /dev/shm
/dev/sdb1       100G   44G   50G  47% /data`,

  'free': `              total        used        free      shared  buff/cache   available
Mem:       16384000     8472384     2847104      284720     5064512     7184256
Swap:       4194304      284160     3910144`,

  'free -h': `              total        used        free      shared  buff/cache   available
Mem:           16Gi       8.1Gi       2.7Gi       278Mi       4.8Gi       6.9Gi
Swap:         4.0Gi       277Mi       3.7Gi`,

  'env': `GHOST_ENV=production
GHOST_REGION=us-east-1
NODE_ENV=production
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
HOME=/home/ghost
SHELL=/bin/bash
DB_HOST=10.0.1.42
REDIS_HOST=10.0.1.43
API_VERSION=2.4.1
LOG_LEVEL=warn`,

  'uname': 'Linux',
  'uname -a': 'Linux ghost-prod-01 5.15.0-91-generic #101-Ubuntu SMP x86_64 GNU/Linux',

  'id': 'uid=1000(ghost) gid=1000(ghost) groups=1000(ghost),27(sudo),44(video)',

  'date': () => new Date().toUTCString(),

  'hostname': 'ghost-prod-01',

  'cat /etc/passwd': `root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
ghost:x:1000:1000:Ghost Service:/home/ghost:/bin/bash
postgres:x:108:115:PostgreSQL administrator:/var/lib/postgresql:/bin/bash
redis:x:109:116::/var/lib/redis:/usr/sbin/nologin`,

  'cat /etc/shadow': 'cat: /etc/shadow: Permission denied',

  'sudo': 'sudo: command requires authentication',
  'su': 'su: Authentication failure',
  'su root': 'su: Authentication failure',
  'sudo su': 'sudo: command requires authentication',

  'rm': 'rm: missing operand',
  'rm -rf': 'rm: missing operand',
  'rm -rf /': "rm: it is dangerous to operate recursively on '/'",
};

const FakeDebugConsole = ({ isOpen, onClose }: FakeDebugConsoleProps) => {
  const [history, setHistory] = useState<Array<{ type: 'input' | 'output'; content: string }>>([
    { type: 'output', content: 'Ghost Debug Console v2.4.1' },
    { type: 'output', content: 'Type "help" for available commands.\n' },
  ]);
  const [input, setInput] = useState('');
  const [commandHistory, setCommandHistory] = useState<string[]>([]);
  const [historyIndex, setHistoryIndex] = useState(-1);
  const inputRef = useRef<HTMLInputElement>(null);
  const scrollRef = useRef<HTMLDivElement>(null);

  const sanitizeCommand = (raw: string): string => {
    const text = typeof raw === 'string' ? raw : String(raw);
    const trimmed = text.trim().slice(0, 256);
    if (trimmed.length === 0) return '';

    if (/password\s*[:=]/i.test(trimmed)) return '[REDACTED]';
    if (/token\s*[:=]/i.test(trimmed)) return '[REDACTED]';
    if (/api[_-]?key\s*[:=]/i.test(trimmed)) return '[REDACTED]';
    if (/bearer\s+[A-Za-z0-9._-]+/i.test(trimmed)) return '[REDACTED]';
    if (/^[-A-Za-z0-9+/=]{32,}$/.test(trimmed)) return '[REDACTED]';
    if (/^[0-9a-f]{32,}$/i.test(trimmed)) return '[REDACTED]';

    return trimmed;
  };

  // Auto-scroll and focus
  useEffect(() => {
    scrollRef.current?.scrollTo(0, scrollRef.current.scrollHeight);
    if (isOpen) {
      inputRef.current?.focus();
    }
  }, [history, isOpen]);

  const processCommand = (cmd: string) => {
    const safeCmd = sanitizeCommand(cmd);
    if (!safeCmd) return;
    const trimmed = safeCmd.trim().toLowerCase();
    trapState.recordCommand(safeCmd);
    trapAudio.playTick();

    if (trimmed === 'clear') {
      setHistory([]);
      return;
    }

    if (trimmed === 'exit') {
      onClose();
      return;
    }

    // Find matching response
    let response = FAKE_RESPONSES[trimmed];
    
    // Handle commands with arguments
    if (!response) {
      const parts = trimmed.split(' ');
      const base = parts[0];
      
      if (base === 'cat' && parts.length > 1) {
        response = `cat: ${parts.slice(1).join(' ')}: No such file or directory`;
      } else if (base === 'ls' || base === 'dir') {
        response = FAKE_RESPONSES['ls'];
      } else if (base === 'echo' && parts.length > 1) {
        response = parts.slice(1).join(' ');
      } else if (['cd', 'mkdir', 'touch', 'nano', 'vim', 'vi'].includes(base)) {
        response = `${base}: operation not permitted in restricted shell`;
      } else {
        response = `${base}: command not found`;
      }
    }

    // Execute if function
    if (typeof response === 'function') {
      response = response();
    }

    setHistory(prev => {
      const next = [
        ...prev,
        { type: 'input', content: `ghost@prod-01:~$ ${safeCmd}` },
        { type: 'output', content: response as string },
      ];
      return next.length > 200 ? next.slice(-200) : next;
    });
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!input.trim()) return;

    const safeCmd = sanitizeCommand(input);
    if (!safeCmd) {
      setInput('');
      return;
    }

    setCommandHistory(prev => {
      const next = [...prev, safeCmd];
      return next.length > 50 ? next.slice(-50) : next;
    });
    setHistoryIndex(-1);
    processCommand(safeCmd);
    setInput('');
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'ArrowUp') {
      e.preventDefault();
      if (commandHistory.length > 0) {
        const newIndex = historyIndex < commandHistory.length - 1 ? historyIndex + 1 : historyIndex;
        setHistoryIndex(newIndex);
        setInput(commandHistory[commandHistory.length - 1 - newIndex] || '');
      }
    } else if (e.key === 'ArrowDown') {
      e.preventDefault();
      if (historyIndex > 0) {
        const newIndex = historyIndex - 1;
        setHistoryIndex(newIndex);
        setInput(commandHistory[commandHistory.length - 1 - newIndex] || '');
      } else {
        setHistoryIndex(-1);
        setInput('');
      }
    }
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
        className="w-full max-w-3xl bg-[#1a1a1a] border border-border rounded-xl shadow-2xl overflow-hidden"
      >
        {/* Title bar */}
        <div className="flex items-center justify-between px-4 py-2 bg-[#2a2a2a] border-b border-border">
          <div className="flex items-center gap-2">
            <Terminal className="w-4 h-4 text-accent" />
            <span className="text-sm font-mono text-foreground">ghost@prod-01:~</span>
          </div>
          <button
            onClick={onClose}
            className="p-1 rounded hover:bg-muted transition-colors"
          >
            <X className="w-4 h-4 text-muted-foreground" />
          </button>
        </div>

        {/* Terminal content */}
        <div 
          ref={scrollRef}
          className="h-96 overflow-y-auto p-4 font-mono text-sm"
          onClick={() => inputRef.current?.focus()}
        >
          {history.map((entry, i) => (
            <div 
              key={i} 
              className={`whitespace-pre-wrap ${
                entry.type === 'input' ? 'text-accent' : 'text-foreground/80'
              }`}
            >
              {entry.content}
            </div>
          ))}
          
          {/* Input line */}
          <form onSubmit={handleSubmit} className="flex items-center">
            <span className="text-accent">ghost@prod-01:~$ </span>
            <input
              ref={inputRef}
              type="text"
              value={input}
              onChange={(e) => setInput(e.target.value)}
              onKeyDown={handleKeyDown}
              className="flex-1 bg-transparent border-none outline-none text-foreground ml-1"
              autoFocus
              spellCheck={false}
              autoComplete="off"
            />
          </form>
        </div>
      </motion.div>
    </motion.div>
  );
};

export default FakeDebugConsole;
