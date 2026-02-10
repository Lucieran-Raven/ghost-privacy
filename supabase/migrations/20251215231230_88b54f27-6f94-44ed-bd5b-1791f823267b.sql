-- Ghost Sessions table for ephemeral session management
DO $$
BEGIN
  CREATE EXTENSION IF NOT EXISTS pgcrypto;
EXCEPTION
  WHEN others THEN
    -- ignore
END $$;

DO $$
BEGIN
  CREATE TABLE IF NOT EXISTS public.ghost_sessions (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id text NOT NULL UNIQUE,
    host_fingerprint text NOT NULL,
    guest_fingerprint text,
    ip_hash bytea NOT NULL,
    capability_hash bytea,
    expires_at timestamptz NOT NULL DEFAULT (now() + interval '5 minutes')
  );
END $$;

-- Rate limits table for distributed rate limiting
DO $$
BEGIN
  CREATE TABLE IF NOT EXISTS public.rate_limits (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    ip_hash text NOT NULL,
    action text NOT NULL,
    count integer NOT NULL DEFAULT 1,
    window_start timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (ip_hash, action, window_start)
  );
END $$;

-- Create indexes for performance
DO $$
BEGIN
  CREATE INDEX IF NOT EXISTS idx_ghost_sessions_session_id ON public.ghost_sessions (session_id);
  CREATE INDEX IF NOT EXISTS idx_rate_limits_window ON public.rate_limits (ip_hash, action, window_start);
END $$;

-- Enable RLS on both tables
DO $$
BEGIN
  BEGIN
    ALTER TABLE public.ghost_sessions ENABLE ROW LEVEL SECURITY;
  EXCEPTION
    WHEN others THEN
      -- ignore
  END;

  BEGIN
    ALTER TABLE public.rate_limits ENABLE ROW LEVEL SECURITY;
  EXCEPTION
    WHEN others THEN
      -- ignore
  END;
END $$;

-- SECURITY: No direct client access to these tables
-- All operations go through Edge Functions using service_role
-- This is defense-in-depth: even if anon key is compromised, RLS blocks access

-- Deny all policies for anon users (Edge Functions use service_role which bypasses RLS)
-- No SELECT, INSERT, UPDATE, DELETE policies = complete lockdown for anon

-- Enable realtime for ghost_sessions (for session presence awareness)
DO $$
BEGIN
  BEGIN
    DROP POLICY IF EXISTS deny_all ON public.ghost_sessions;
    CREATE POLICY deny_all ON public.ghost_sessions FOR ALL TO PUBLIC USING (false) WITH CHECK (false);
  EXCEPTION
    WHEN others THEN
      -- ignore
  END;

  BEGIN
    DROP POLICY IF EXISTS deny_all ON public.rate_limits;
    CREATE POLICY deny_all ON public.rate_limits FOR ALL TO PUBLIC USING (false) WITH CHECK (false);
  EXCEPTION
    WHEN others THEN
      -- ignore
  END;
END $$;