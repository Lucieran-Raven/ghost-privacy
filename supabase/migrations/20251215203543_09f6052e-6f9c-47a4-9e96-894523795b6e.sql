-- Explicit deny-all policies for Ghost tables
-- Service role bypasses RLS by default, so these block anon/authenticated only

DO $$
BEGIN
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
      DROP POLICY IF EXISTS deny_all ON public.ghost_sessions;
      CREATE POLICY deny_all ON public.ghost_sessions FOR ALL TO PUBLIC USING (false) WITH CHECK (false);
    EXCEPTION
      WHEN others THEN
        -- ignore
    END;
  END IF;

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
      DROP POLICY IF EXISTS deny_all ON public.rate_limits;
      CREATE POLICY deny_all ON public.rate_limits FOR ALL TO PUBLIC USING (false) WITH CHECK (false);
    EXCEPTION
      WHEN others THEN
        -- ignore
    END;
  END IF;
END $$;