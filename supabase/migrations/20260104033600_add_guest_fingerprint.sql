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
  END IF;
END $$;
