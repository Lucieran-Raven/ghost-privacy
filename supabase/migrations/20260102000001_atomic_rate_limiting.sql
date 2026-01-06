-- SECURITY FIX: Atomic rate limiting function
-- Prevents TOCTOU race conditions in concurrent session creation
-- Returns TRUE if under limit, FALSE if rate limited

-- Grant execute permission to service role only
-- REVOKE EXECUTE ON FUNCTION increment_rate_limit FROM anon, authenticated;

-- Add comment for documentation
-- COMMENT ON FUNCTION increment_rate_limit IS 'Atomically increments rate limit counter and returns TRUE if under limit, FALSE if exceeded. Prevents TOCTOU race conditions.';

DO $$
BEGIN
  CREATE EXTENSION IF NOT EXISTS pgcrypto;
EXCEPTION
  WHEN others THEN
    -- ignore
END $$;

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

DO $$
BEGIN
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
END $$;

DO $$
BEGIN
  GRANT EXECUTE ON FUNCTION public.increment_rate_limit(text, text, timestamptz, integer) TO service_role;
  REVOKE EXECUTE ON FUNCTION public.increment_rate_limit(text, text, timestamptz, integer) FROM anon, authenticated;
EXCEPTION
  WHEN others THEN
    -- ignore
END $$;
