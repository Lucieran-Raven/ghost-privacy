import { useState } from 'react';
import { motion } from 'framer-motion';
import { 
  Code, ChevronRight, Copy, CheckCircle, 
  Lock, Globe, Server, X 
} from 'lucide-react';
import { trapAudio } from '@/utils/deceptionAudioEngine';
import { writeEphemeralClipboard } from '@/utils/ephemeralClipboard';

interface FakeApiDocsProps {
  isOpen: boolean;
  onClose: () => void;
}

/**
 * GHOST MIRAGE: Fake API Documentation
 * 
 * Swagger-like interface showing "internal" API endpoints.
 * All endpoints return convincing but fake data.
 * Creates illusion of discoverable attack surface.
 * 
 * ⚠️ TRANSPARENT SIMULATION LABEL ⚠️
 * This is a SECURITY TESTING SIMULATION for honeypot detection.
 * All endpoints and responses are fabricated.
 */

const FAKE_ENDPOINTS = [
  {
    method: 'GET',
    path: '/api/v1/sessions',
    description: 'List all active sessions',
    auth: 'Bearer token required',
    response: `{
  "sessions": [
    {
      "id": "GHOST-XXXX-YYYY",
      "created_at": "2024-12-16T08:30:00Z",
      "expires_at": "2024-12-16T20:30:00Z",
      "participants": 2,
      "encrypted": true
    }
  ],
  "total": 47,
  "page": 1
}`,
  },
  {
    method: 'POST',
    path: '/api/v1/sessions',
    description: 'Create a new session',
    auth: 'Bearer token required',
    response: `{
  "session_id": "GHOST-ABCD-1234",
  "host_key": "pk_live_...",
  "join_url": "https://ghost.app/session?id=GHOST-ABCD-1234",
  "expires_at": "2024-12-16T20:30:00Z"
}`,
  },
  {
    method: 'GET',
    path: '/api/v1/sessions/{id}',
    description: 'Get session details',
    auth: 'Bearer token required',
    response: `{
  "id": "GHOST-XXXX-YYYY",
  "status": "active",
  "participants": [
    { "id": "host", "connected": true },
    { "id": "guest", "connected": true }
  ],
  "messages_count": 24,
  "created_at": "2024-12-16T08:30:00Z"
}`,
  },
  {
    method: 'DELETE',
    path: '/api/v1/sessions/{id}',
    description: 'Terminate a session and purge all data',
    auth: 'Bearer token required',
    response: `{
  "success": true,
  "message": "Session terminated. All data purged.",
  "purged_at": "2024-12-16T10:45:00Z"
}`,
  },
  {
    method: 'GET',
    path: '/api/v1/users/me',
    description: 'Get current user profile',
    auth: 'Bearer token required',
    response: `{
  "id": "usr_abc123",
  "fingerprint": "fp_8a7b6c5d4e3f",
  "created_at": "2024-12-01T00:00:00Z",
  "sessions_created": 12,
  "last_active": "2024-12-16T08:30:00Z"
}`,
  },
  {
    method: 'POST',
    path: '/api/v1/messages/send',
    description: 'Send encrypted message to session',
    auth: 'Bearer token + Session key',
    response: `{
  "message_id": "msg_xyz789",
  "encrypted": true,
  "delivered": true,
  "timestamp": "2024-12-16T10:45:23Z"
}`,
  },
  {
    method: 'GET',
    path: '/api/v1/keys/public/{session_id}',
    description: 'Get public key for session encryption',
    auth: 'None (public)',
    response: `{
  "session_id": "GHOST-XXXX-YYYY",
  "public_key": "-----BEGIN PUBLIC KEY-----\\nMIIB...",
  "algorithm": "ECDH-P256",
  "expires_at": "2024-12-16T20:30:00Z"
}`,
  },
  {
    method: 'POST',
    path: '/api/v1/verify/key',
    description: 'Verify key fingerprint',
    auth: 'Bearer token required',
    response: `{
  "valid": true,
  "fingerprint": "SHA256:abc123def456...",
  "match": true
}`,
  },
];

const FakeApiDocs = ({ isOpen, onClose }: FakeApiDocsProps) => {
  const [selectedEndpoint, setSelectedEndpoint] = useState<number | null>(null);
  const [copied, setCopied] = useState<string | null>(null);

  const handleCopy = (text: string, id: string) => {
    void writeEphemeralClipboard(text, 30000);
    setCopied(id);
    trapAudio.playTick();
    setTimeout(() => setCopied(null), 2000);
  };

  const getMethodColor = (method: string) => {
    switch (method) {
      case 'GET': return 'bg-emerald-500/20 text-emerald-400';
      case 'POST': return 'bg-blue-500/20 text-blue-400';
      case 'DELETE': return 'bg-red-500/20 text-red-400';
      case 'PUT': return 'bg-amber-500/20 text-amber-400';
      default: return 'bg-muted text-muted-foreground';
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
        className="w-full max-w-4xl max-h-[90vh] bg-card border border-border rounded-xl shadow-2xl overflow-hidden flex flex-col"
      >
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-border bg-muted/30">
          <div className="flex items-center gap-3">
            <Code className="w-5 h-5 text-primary" />
            <div>
              <h2 className="font-outfit font-bold text-foreground">Ghost API Documentation</h2>
              <p className="text-xs text-muted-foreground">Internal API Reference v2.4.1</p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-2 rounded-lg hover:bg-muted transition-colors"
          >
            <X className="w-4 h-4 text-muted-foreground" />
          </button>
        </div>

        {/* Info banner */}
        <div className="px-6 py-3 bg-amber-500/5 border-b border-amber-500/20">
          <div className="flex items-center gap-2 text-amber-500 text-sm">
            <Lock className="w-4 h-4" />
            <span>Internal API - Authentication required for most endpoints</span>
          </div>
        </div>

        {/* Content */}
        <div className="flex-1 overflow-y-auto">
          <div className="p-6 space-y-3">
            {FAKE_ENDPOINTS.map((endpoint, i) => (
              <motion.div
                key={i}
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: i * 0.05 }}
                className="border border-border rounded-lg overflow-hidden"
              >
                {/* Endpoint header */}
                <button
                  onClick={() => setSelectedEndpoint(selectedEndpoint === i ? null : i)}
                  className="w-full px-4 py-3 flex items-center gap-3 hover:bg-muted/30 transition-colors"
                >
                  <span className={`px-2 py-0.5 rounded text-xs font-mono font-bold ${getMethodColor(endpoint.method)}`}>
                    {endpoint.method}
                  </span>
                  <span className="font-mono text-sm text-foreground">{endpoint.path}</span>
                  <span className="text-sm text-muted-foreground flex-1 text-left ml-4">
                    {endpoint.description}
                  </span>
                  <ChevronRight className={`w-4 h-4 text-muted-foreground transition-transform ${
                    selectedEndpoint === i ? 'rotate-90' : ''
                  }`} />
                </button>

                {/* Expanded details */}
                {selectedEndpoint === i && (
                  <motion.div
                    initial={{ height: 0 }}
                    animate={{ height: 'auto' }}
                    className="border-t border-border bg-muted/20"
                  >
                    <div className="p-4 space-y-4">
                      {/* Auth info */}
                      <div className="flex items-center gap-2 text-sm">
                        <Lock className="w-4 h-4 text-muted-foreground" />
                        <span className="text-muted-foreground">Authentication:</span>
                        <span className="text-foreground">{endpoint.auth}</span>
                      </div>

                      {/* Example response */}
                      <div>
                        <div className="flex items-center justify-between mb-2">
                          <span className="text-sm text-muted-foreground">Example Response:</span>
                          <button
                            onClick={() => handleCopy(endpoint.response, `resp-${i}`)}
                            className="flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground transition-colors"
                          >
                            {copied === `resp-${i}` ? (
                              <CheckCircle className="w-3.5 h-3.5 text-accent" />
                            ) : (
                              <Copy className="w-3.5 h-3.5" />
                            )}
                            Copy
                          </button>
                        </div>
                        <pre className="p-3 bg-background rounded-lg text-xs font-mono text-foreground/80 overflow-x-auto">
                          {endpoint.response}
                        </pre>
                      </div>

                      {/* Try it button (fake) */}
                      <button
                        onClick={() => {
                          trapAudio.playAccessGranted();
                          // Just plays sound, does nothing
                        }}
                        className="px-4 py-2 bg-primary text-primary-foreground text-sm font-medium rounded-lg hover:shadow-glow-sm transition-all"
                      >
                        Try Request
                      </button>
                    </div>
                  </motion.div>
                )}
              </motion.div>
            ))}
          </div>
        </div>

        {/* Footer */}
        <div className="px-6 py-4 bg-muted/20 border-t border-border">
          <div className="flex items-center justify-between text-xs text-muted-foreground">
            <div className="flex items-center gap-4">
              <span className="flex items-center gap-1">
                <Globe className="w-3.5 h-3.5" />
                Base URL: https://api.ghost.app
              </span>
              <span className="flex items-center gap-1">
                <Server className="w-3.5 h-3.5" />
                Version: 2.4.1
              </span>
            </div>
            <span>Last updated: {new Date().toLocaleDateString()}</span>
          </div>
        </div>
      </motion.div>
    </motion.div>
  );
};

export default FakeApiDocs;
