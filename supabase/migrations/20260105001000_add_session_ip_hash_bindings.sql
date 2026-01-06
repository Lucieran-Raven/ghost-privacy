-- Add IP hash bindings for session hijack mitigation
-- Stores truncated SHA-256 of client IP (non-reversible) for ephemeral session binding

DO $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM information_schema.tables
    WHERE table_schema = 'public' AND table_name = 'ghost_sessions'
  ) THEN
    IF NOT EXISTS (
      SELECT 1 FROM information_schema.columns
      WHERE table_schema = 'public' AND table_name = 'ghost_sessions' AND column_name = 'ip_hash'
    ) THEN
      ALTER TABLE public.ghost_sessions ADD COLUMN ip_hash bytea;
    END IF;
  END IF;
END $$;
