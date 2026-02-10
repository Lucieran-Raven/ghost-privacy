-- --------------------------------------------
-- GHOST SESSIONS: SERVICE ROLE ONLY ACCESS
-- --------------------------------------------

-- --------------------------------------------
-- RATE LIMITS: SERVICE ROLE ONLY ACCESS  
-- --------------------------------------------

-- --------------------------------------------
-- VERIFY RLS IS ENABLED ON BOTH TABLES
-- --------------------------------------------

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
  END IF;
END $$;