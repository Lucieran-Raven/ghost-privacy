-- Ghost Sessions table for ephemeral session management
CREATE TABLE IF NOT EXISTS public.ghost_sessions (
  id UUID NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
  session_id TEXT NOT NULL UNIQUE,
  host_fingerprint TEXT NOT NULL,
  expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);

-- Rate limits table for distributed rate limiting
CREATE TABLE IF NOT EXISTS public.rate_limits (
  id UUID NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
  ip_hash TEXT NOT NULL,
  action TEXT NOT NULL,
  count INTEGER NOT NULL DEFAULT 1,
  window_start TIMESTAMP WITH TIME ZONE NOT NULL,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);

-- Create indexes for performance
CREATE INDEX IF NOT EXISTS idx_ghost_sessions_session_id ON public.ghost_sessions(session_id);
CREATE INDEX IF NOT EXISTS idx_ghost_sessions_expires_at ON public.ghost_sessions(expires_at);
CREATE INDEX IF NOT EXISTS idx_rate_limits_ip_action_window ON public.rate_limits(ip_hash, action, window_start);

-- Enable RLS on both tables
ALTER TABLE public.ghost_sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.rate_limits ENABLE ROW LEVEL SECURITY;

-- SECURITY: No direct client access to these tables
-- All operations go through Edge Functions using service_role
-- This is defense-in-depth: even if anon key is compromised, RLS blocks access

-- Deny all policies for anon users (Edge Functions use service_role which bypasses RLS)
-- No SELECT, INSERT, UPDATE, DELETE policies = complete lockdown for anon

-- Enable realtime for ghost_sessions (for session presence awareness)
ALTER PUBLICATION supabase_realtime ADD TABLE public.ghost_sessions;