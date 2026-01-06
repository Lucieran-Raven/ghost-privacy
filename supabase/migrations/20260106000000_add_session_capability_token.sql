-- Add capability token hash for session authorization (server-minted secret)
-- This enables capability-based access control without IP binding.

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_schema = 'public'
      AND table_name = 'ghost_sessions'
      AND column_name = 'capability_hash'
  ) THEN
    ALTER TABLE public.ghost_sessions ADD COLUMN capability_hash bytea;
  END IF;
END $$;

-- Backfill for any pre-existing rows (defense-in-depth)
DO $$
BEGIN
  UPDATE public.ghost_sessions
  SET capability_hash = gen_random_bytes(32)
  WHERE capability_hash IS NULL;
END $$;

DO $$
BEGIN
  ALTER TABLE public.ghost_sessions ALTER COLUMN capability_hash SET NOT NULL;
EXCEPTION
  WHEN others THEN
    -- If the column is already NOT NULL (or table doesn't exist), ignore.
END $$;

DO $$
BEGIN
  CREATE INDEX IF NOT EXISTS idx_ghost_sessions_session_capability
    ON public.ghost_sessions (session_id, capability_hash);
END $$;
