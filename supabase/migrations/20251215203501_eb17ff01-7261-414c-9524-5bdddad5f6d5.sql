-- Ghost Privacy Backend - Complete Schema
-- Zero-knowledge session management

-- Create ghost_sessions table for ephemeral session management
CREATE TABLE public.ghost_sessions (
  id UUID NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
  session_id TEXT NOT NULL UNIQUE,
  host_fingerprint TEXT NOT NULL,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
  expires_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT (now() + interval '30 minutes')
);

-- Create rate_limits table for IP-based rate limiting
CREATE TABLE public.rate_limits (
  id UUID NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
  ip_hash TEXT NOT NULL,
  action TEXT NOT NULL,
  count INTEGER NOT NULL DEFAULT 1,
  window_start TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
  UNIQUE(ip_hash, action)
);

-- Enable RLS on both tables
ALTER TABLE public.ghost_sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.rate_limits ENABLE ROW LEVEL SECURITY;

-- Ghost sessions: No direct client access - all via edge functions with service_role
-- Rate limits: No direct client access - managed by edge functions only

-- Create indexes for performance
CREATE INDEX idx_ghost_sessions_session_id ON public.ghost_sessions(session_id);
CREATE INDEX idx_ghost_sessions_expires_at ON public.ghost_sessions(expires_at);
CREATE INDEX idx_rate_limits_ip_action ON public.rate_limits(ip_hash, action);

-- Enable realtime for sessions (for participant join notifications)
ALTER PUBLICATION supabase_realtime ADD TABLE public.ghost_sessions;