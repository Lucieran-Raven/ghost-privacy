-- Secure baseline schema (authoritative)

-- ghost_sessions: ephemeral session metadata only
CREATE TABLE IF NOT EXISTS public.ghost_sessions (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  session_id text NOT NULL UNIQUE,
  host_fingerprint text NOT NULL,
  guest_fingerprint text,
  ip_hash bytea NOT NULL,
  capability_hash bytea NOT NULL,
  expires_at timestamptz NOT NULL DEFAULT (now() + interval '5 minutes')
);

-- RLS: block ALL client access (service_role bypasses RLS)
ALTER TABLE public.ghost_sessions ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS deny_all ON public.ghost_sessions;
CREATE POLICY deny_all ON public.ghost_sessions FOR ALL TO PUBLIC USING (false) WITH CHECK (false);


-- rate_limits: server-controlled only (service_role via RPC)
CREATE TABLE IF NOT EXISTS public.rate_limits (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  ip_hash text NOT NULL,
  action text NOT NULL,
  count integer NOT NULL DEFAULT 1,
  window_start timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (ip_hash, action, window_start)
);

ALTER TABLE public.rate_limits ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS deny_all ON public.rate_limits;
CREATE POLICY deny_all ON public.rate_limits FOR ALL TO PUBLIC USING (false) WITH CHECK (false);


-- Atomic sliding-window rate limiting
CREATE OR REPLACE FUNCTION public.increment_rate_limit(
  p_ip_hash text,
  p_action text,
  p_window_start timestamptz,
  p_max_count integer
) RETURNS boolean AS $$
DECLARE
  v_new_count integer;
BEGIN
  INSERT INTO public.rate_limits (ip_hash, action, window_start, count)
  VALUES (p_ip_hash, p_action, p_window_start, 1)
  ON CONFLICT (ip_hash, action, window_start)
  DO UPDATE SET count = public.rate_limits.count + 1
  RETURNING count INTO v_new_count;

  RETURN v_new_count <= p_max_count;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

GRANT EXECUTE ON FUNCTION public.increment_rate_limit(text, text, timestamptz, integer) TO service_role;
REVOKE EXECUTE ON FUNCTION public.increment_rate_limit(text, text, timestamptz, integer) FROM anon, authenticated;
