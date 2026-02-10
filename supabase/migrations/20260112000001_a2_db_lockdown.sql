-- A2 SECURITY HARDENING: DB & persistence lockdown

-- 1) Enforce RLS even for table owners (service_role still bypasses via BYPASSRLS).
-- 2) Explicitly revoke table privileges from client roles.
-- 3) Harden SECURITY DEFINER function(s): safe search_path + basic argument validation.

DO $$
BEGIN
  -- ghost_sessions: force RLS + revoke table privileges
  IF EXISTS (
    SELECT 1 FROM information_schema.tables
    WHERE table_schema = 'public' AND table_name = 'ghost_sessions'
  ) THEN
    BEGIN
      ALTER TABLE public.ghost_sessions ENABLE ROW LEVEL SECURITY;
    EXCEPTION
      WHEN others THEN
        -- ignore
    END;

    BEGIN
      ALTER TABLE public.ghost_sessions FORCE ROW LEVEL SECURITY;
    EXCEPTION
      WHEN others THEN
        -- ignore
    END;

    BEGIN
      REVOKE ALL ON TABLE public.ghost_sessions FROM anon, authenticated;
    EXCEPTION
      WHEN others THEN
        -- ignore
    END;
  END IF;

  -- rate_limits: force RLS + revoke table privileges
  IF EXISTS (
    SELECT 1 FROM information_schema.tables
    WHERE table_schema = 'public' AND table_name = 'rate_limits'
  ) THEN
    BEGIN
      ALTER TABLE public.rate_limits ENABLE ROW LEVEL SECURITY;
    EXCEPTION
      WHEN others THEN
        -- ignore
    END;

    BEGIN
      ALTER TABLE public.rate_limits FORCE ROW LEVEL SECURITY;
    EXCEPTION
      WHEN others THEN
        -- ignore
    END;

    BEGIN
      REVOKE ALL ON TABLE public.rate_limits FROM anon, authenticated;
    EXCEPTION
      WHEN others THEN
        -- ignore
    END;
  END IF;
END $$;

-- Harden SECURITY DEFINER rate limiting function
CREATE OR REPLACE FUNCTION public.increment_rate_limit(
  p_ip_hash text,
  p_action text,
  p_window_start timestamptz,
  p_max_count integer
) RETURNS boolean AS $$
DECLARE
  v_new_count integer;
BEGIN
  -- Fail-closed on obviously invalid inputs
  IF p_ip_hash IS NULL OR length(p_ip_hash) = 0 OR length(p_ip_hash) > 512 THEN
    RETURN false;
  END IF;
  IF p_action IS NULL OR length(p_action) = 0 OR length(p_action) > 64 THEN
    RETURN false;
  END IF;
  IF p_max_count IS NULL OR p_max_count <= 0 OR p_max_count > 10000 THEN
    RETURN false;
  END IF;

  INSERT INTO public.rate_limits (ip_hash, action, window_start, count)
  VALUES (p_ip_hash, p_action, p_window_start, 1)
  ON CONFLICT (ip_hash, action, window_start)
  DO UPDATE SET count = public.rate_limits.count + 1
  RETURNING count INTO v_new_count;

  RETURN v_new_count <= p_max_count;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public;

DO $$
BEGIN
  GRANT EXECUTE ON FUNCTION public.increment_rate_limit(text, text, timestamptz, integer) TO service_role;
  REVOKE EXECUTE ON FUNCTION public.increment_rate_limit(text, text, timestamptz, integer) FROM anon, authenticated;
EXCEPTION
  WHEN others THEN
    -- ignore
END $$;
