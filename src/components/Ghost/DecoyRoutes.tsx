import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { trapState } from '@/utils/trapState';
import { honeypotAudio } from '@/utils/honeypotAudio';
import SimulatedAdminConsole from './SimulatedAdminConsole';
import SimulatedApiDocs from './SimulatedApiDocs';
import SimulatedDebugConsole from './SimulatedDebugConsole';
import { generateFakeDatabasePreview } from '@/utils/decoyContent';

interface DecoyRoutesProps {
  type: 'debug' | 'api' | 'backup' | 'admin' | 'env' | 'config';
}

/**
 * GHOST MIRAGE: Decoy Routes Component
 * 
 * Handles all decoy endpoint hits and routes attackers to appropriate traps.
 * Records hits for behavior-based escalation.
 */
const DecoyRoutes = ({ type }: DecoyRoutesProps) => {
  const navigate = useNavigate();
  const [showAdmin, setShowAdmin] = useState(false);
  const [showApi, setShowApi] = useState(false);
  const [showDebug, setShowDebug] = useState(false);
  const [showBackup, setShowBackup] = useState(false);

  useEffect(() => {
    // Record the decoy hit
    const hits = trapState.recordDecoyHit();
    honeypotAudio.playAccessGranted();

    // Route to appropriate trap based on type
    switch (type) {
      case 'admin':
        setShowAdmin(true);
        break;
      case 'api':
        setShowApi(true);
        break;
      case 'debug':
        setShowDebug(true);
        break;
      case 'backup':
        setShowBackup(true);
        break;
      case 'env':
      case 'config':
        // Show fake sensitive data then redirect
        setTimeout(() => navigate('/'), 5000);
        break;
    }

    // Check for escalation
    if (trapState.shouldShowAdminPanel() && type !== 'admin') {
      setTimeout(() => setShowAdmin(true), 2000);
    }
  }, [type, navigate]);

  // Admin panel trap
  if (showAdmin) {
    return <SimulatedAdminConsole onTimeout={() => navigate('/')} />;
  }

  // API docs trap
  if (showApi) {
    return <SimulatedApiDocs isOpen={true} onClose={() => navigate('/')} />;
  }

  // Debug console trap
  if (showDebug) {
    return <SimulatedDebugConsole isOpen={true} onClose={() => navigate('/')} />;
  }

  // Backup file trap - show fake database dump
  if (showBackup) {
    return (
      <div className="min-h-screen bg-[#1a1a1a] p-4 font-mono text-xs text-foreground/80 overflow-auto">
        <pre className="whitespace-pre-wrap">{generateFakeDatabasePreview()}</pre>
      </div>
    );
  }

  // Env/config trap - show fake sensitive data
  if (type === 'env' || type === 'config') {
    return (
      <div className="min-h-screen bg-[#1a1a1a] p-4 font-mono text-xs text-foreground/80">
        <pre>{`# Ghost Configuration - INTERNAL USE ONLY
# Last updated: ${new Date().toISOString()}

GHOST_ENV=production
GHOST_REGION=us-east-1
NODE_ENV=production

# Database (encrypted)
DATABASE_URL=postgres://ghost:****@10.0.1.42:5432/ghost_prod
REDIS_URL=redis://10.0.1.43:6379

# API Keys (redacted)
STRIPE_KEY=sk_live_****
SENDGRID_KEY=SG.****
TWILIO_SID=AC****

# Security
JWT_SECRET=****
ENCRYPTION_KEY=****

# Monitoring
SENTRY_DSN=https://****@sentry.io/****
DATADOG_KEY=****

# WARNING: Do not share this file
# Rotating credentials in 24h...`}</pre>
      </div>
    );
  }

  // Default loading state
  return (
    <div className="min-h-screen bg-background flex items-center justify-center">
      <div className="animate-spin w-8 h-8 border-2 border-primary border-t-transparent rounded-full" />
    </div>
  );
};

export default DecoyRoutes;
