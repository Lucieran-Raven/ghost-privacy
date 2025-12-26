-- Drop existing overly permissive RLS policies
DROP POLICY IF EXISTS "Session creation via edge function" ON ghost_sessions;
DROP POLICY IF EXISTS "Session deletion" ON ghost_sessions;
DROP POLICY IF EXISTS "Session extension" ON ghost_sessions;
DROP POLICY IF EXISTS "Session lookup by exact id" ON ghost_sessions;

-- Create restrictive RLS policies that only allow exact ID lookups
-- SELECT: Only allow selecting a session if the request provides the exact session ID via header
CREATE POLICY "Session lookup by exact id only" 
ON ghost_sessions 
FOR SELECT 
USING (
  id = COALESCE(
    current_setting('request.headers', true)::json->>'x-ghost-session-id',
    ''
  )
);

-- INSERT: Only via service role (Edge Functions) - block anon key inserts
CREATE POLICY "Session creation via service role only" 
ON ghost_sessions 
FOR INSERT 
WITH CHECK (
  (SELECT current_setting('request.jwt.claims', true)::json->>'role') = 'service_role'
);

-- UPDATE: Only via service role for session extension
CREATE POLICY "Session extension via service role only" 
ON ghost_sessions 
FOR UPDATE 
USING (
  (SELECT current_setting('request.jwt.claims', true)::json->>'role') = 'service_role'
)
WITH CHECK (expires_at >= now());

-- DELETE: Only via service role for cleanup
CREATE POLICY "Session deletion via service role only" 
ON ghost_sessions 
FOR DELETE 
USING (
  (SELECT current_setting('request.jwt.claims', true)::json->>'role') = 'service_role'
);

-- Create rate_limits table for distributed rate limiting
CREATE TABLE IF NOT EXISTS public.rate_limits (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  identifier text NOT NULL,
  action text NOT NULL,
  count integer NOT NULL DEFAULT 1,
  window_start timestamp with time zone NOT NULL DEFAULT now(),
  created_at timestamp with time zone NOT NULL DEFAULT now(),
  UNIQUE(identifier, action, window_start)
);

-- Enable RLS on rate_limits
ALTER TABLE public.rate_limits ENABLE ROW LEVEL SECURITY;

-- Only service role can access rate_limits
CREATE POLICY "Rate limits service role only" 
ON public.rate_limits 
FOR ALL 
USING (
  (SELECT current_setting('request.jwt.claims', true)::json->>'role') = 'service_role'
);

-- Create index for fast rate limit lookups
CREATE INDEX IF NOT EXISTS idx_rate_limits_lookup ON public.rate_limits(identifier, action, window_start);

-- Create cleanup function for old rate limit entries
CREATE OR REPLACE FUNCTION cleanup_old_rate_limits()
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
  DELETE FROM rate_limits WHERE window_start < now() - interval '2 hours';
END;
$$;