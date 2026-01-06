DO $$
BEGIN
  CREATE EXTENSION IF NOT EXISTS pgcrypto;
EXCEPTION
  WHEN insufficient_privilege THEN
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
    capability_hash bytea NOT NULL,
    expires_at timestamptz NOT NULL DEFAULT (now() + interval '5 minutes')
  );
END $$;

-- Converge existing schemas (idempotent)
DO $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM information_schema.tables
    WHERE table_schema = 'public' AND table_name = 'ghost_sessions'
  ) THEN
    IF NOT EXISTS (
      SELECT 1 FROM information_schema.columns
      WHERE table_schema = 'public' AND table_name = 'ghost_sessions' AND column_name = 'guest_fingerprint'
    ) THEN
      ALTER TABLE public.ghost_sessions ADD COLUMN guest_fingerprint text;
    END IF;

    IF NOT EXISTS (
      SELECT 1 FROM information_schema.columns
      WHERE table_schema = 'public' AND table_name = 'ghost_sessions' AND column_name = 'capability_hash'
    ) THEN
      ALTER TABLE public.ghost_sessions ADD COLUMN capability_hash bytea;
    END IF;

    -- Backfill capability_hash if needed (defense-in-depth)
    UPDATE public.ghost_sessions
    SET capability_hash = gen_random_bytes(32)
    WHERE capability_hash IS NULL;

    BEGIN
      ALTER TABLE public.ghost_sessions ALTER COLUMN capability_hash SET NOT NULL;
    EXCEPTION
      WHEN others THEN
        -- ignore
    END;

    BEGIN
      ALTER TABLE public.ghost_sessions ALTER COLUMN session_id SET NOT NULL;
      ALTER TABLE public.ghost_sessions ALTER COLUMN host_fingerprint SET NOT NULL;
      ALTER TABLE public.ghost_sessions ALTER COLUMN ip_hash SET NOT NULL;
      ALTER TABLE public.ghost_sessions ALTER COLUMN expires_at SET NOT NULL;
    EXCEPTION
      WHEN others THEN
        -- ignore
    END;

    BEGIN
      ALTER TABLE public.ghost_sessions ADD CONSTRAINT ghost_sessions_session_id_key UNIQUE (session_id);
    EXCEPTION
      WHEN duplicate_object THEN
        -- ignore
      WHEN others THEN
        -- ignore
    END;
  END IF;
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
  IF EXISTS (
    SELECT 1 FROM information_schema.tables
    WHERE table_schema = 'public' AND table_name = 'rate_limits'
  ) THEN
    BEGIN
      ALTER TABLE public.rate_limits ADD CONSTRAINT rate_limits_ip_action_window_key UNIQUE (ip_hash, action, window_start);
    EXCEPTION
      WHEN duplicate_object THEN
        -- ignore
      WHEN others THEN
        -- ignore
    END;
  END IF;
END $$;

DO $$
BEGIN
  ALTER TABLE public.ghost_sessions ENABLE ROW LEVEL SECURITY;
EXCEPTION
  WHEN others THEN
    -- ignore
END $$;

DO $$
BEGIN
  ALTER TABLE public.rate_limits ENABLE ROW LEVEL SECURITY;
EXCEPTION
  WHEN others THEN
    -- ignore
END $$;

DO $$
BEGIN
  DROP POLICY IF EXISTS deny_all ON public.ghost_sessions;
  CREATE POLICY deny_all ON public.ghost_sessions FOR ALL TO PUBLIC USING (false) WITH CHECK (false);
EXCEPTION
  WHEN others THEN
    -- ignore
END $$;

DO $$
BEGIN
  DROP POLICY IF EXISTS deny_all ON public.rate_limits;
  CREATE POLICY deny_all ON public.rate_limits FOR ALL TO PUBLIC USING (false) WITH CHECK (false);
EXCEPTION
  WHEN others THEN
    -- ignore
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

DO $$
BEGIN
  CREATE INDEX IF NOT EXISTS idx_ghost_sessions_session_id ON public.ghost_sessions (session_id);
  CREATE INDEX IF NOT EXISTS idx_rate_limits_window ON public.rate_limits (ip_hash, action, window_start);
END $$;
