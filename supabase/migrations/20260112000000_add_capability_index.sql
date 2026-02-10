DO $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM information_schema.tables
    WHERE table_schema = 'public' AND table_name = 'ghost_sessions'
  ) THEN
    BEGIN
      CREATE INDEX IF NOT EXISTS idx_ghost_sessions_capability_hash
      ON public.ghost_sessions (capability_hash)
      WHERE capability_hash IS NOT NULL;
    EXCEPTION
      WHEN others THEN
        -- ignore
    END;
  END IF;
END $$;
