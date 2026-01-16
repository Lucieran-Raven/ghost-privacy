-- LAYER 8: Schema convergence (capability-scoped, no correlation columns)
-- Idempotently aligns the DB schema with the current security model.

DO $$
BEGIN
  CREATE EXTENSION IF NOT EXISTS pgcrypto;
EXCEPTION
  WHEN insufficient_privilege THEN
    -- ignore
  WHEN others THEN
    -- ignore
END $$;

DO $$
BEGIN
  -- Ensure ghost_sessions table exists
  IF EXISTS (
    SELECT 1 FROM information_schema.tables
    WHERE table_schema = 'public' AND table_name = 'ghost_sessions'
  ) THEN

    -- Ensure capability_hash exists
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

    -- Ensure used exists
    IF NOT EXISTS (
      SELECT 1 FROM information_schema.columns
      WHERE table_schema = 'public' AND table_name = 'ghost_sessions' AND column_name = 'used'
    ) THEN
      ALTER TABLE public.ghost_sessions ADD COLUMN used boolean NOT NULL DEFAULT false;
    END IF;

    -- Drop correlation columns if present
    IF EXISTS (
      SELECT 1 FROM information_schema.columns
      WHERE table_schema = 'public' AND table_name = 'ghost_sessions' AND column_name = 'host_fingerprint'
    ) THEN
      ALTER TABLE public.ghost_sessions DROP COLUMN host_fingerprint;
    END IF;

    IF EXISTS (
      SELECT 1 FROM information_schema.columns
      WHERE table_schema = 'public' AND table_name = 'ghost_sessions' AND column_name = 'guest_fingerprint'
    ) THEN
      ALTER TABLE public.ghost_sessions DROP COLUMN guest_fingerprint;
    END IF;

    IF EXISTS (
      SELECT 1 FROM information_schema.columns
      WHERE table_schema = 'public' AND table_name = 'ghost_sessions' AND column_name = 'ip_hash'
    ) THEN
      ALTER TABLE public.ghost_sessions DROP COLUMN ip_hash;
    END IF;

    -- Ensure expires_at default matches current behavior (10 minutes)
    BEGIN
      ALTER TABLE public.ghost_sessions ALTER COLUMN expires_at SET DEFAULT (now() + interval '10 minutes');
    EXCEPTION
      WHEN others THEN
        -- ignore
    END;

    -- RLS lockdown (defense in depth)
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

    BEGIN
      DROP POLICY IF EXISTS deny_all ON public.ghost_sessions;
      CREATE POLICY deny_all ON public.ghost_sessions FOR ALL TO PUBLIC USING (false) WITH CHECK (false);
    EXCEPTION
      WHEN others THEN
        -- ignore
    END;
  END IF;

  -- Rate limits table should remain service-only; keep deny-all RLS.
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

    BEGIN
      DROP POLICY IF EXISTS deny_all ON public.rate_limits;
      CREATE POLICY deny_all ON public.rate_limits FOR ALL TO PUBLIC USING (false) WITH CHECK (false);
    EXCEPTION
      WHEN others THEN
        -- ignore
    END;
  END IF;
END $$;
