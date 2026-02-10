DO $$
BEGIN
  CREATE EXTENSION IF NOT EXISTS pgcrypto;
EXCEPTION
  WHEN insufficient_privilege THEN
    -- ignore
END $$;

DO $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM information_schema.tables
    WHERE table_schema = 'public' AND table_name = 'ghost_sessions'
  ) THEN
    IF NOT EXISTS (
      SELECT 1 FROM information_schema.columns
      WHERE table_schema = 'public' AND table_name = 'ghost_sessions' AND column_name = 'used'
    ) THEN
      ALTER TABLE public.ghost_sessions ADD COLUMN used boolean NOT NULL DEFAULT false;
    END IF;

    -- Backfill used from legacy guest_fingerprint if present

    IF EXISTS (
      SELECT 1 FROM information_schema.columns
      WHERE table_schema = 'public' AND table_name = 'ghost_sessions' AND column_name = 'guest_fingerprint'
    ) THEN
      UPDATE public.ghost_sessions SET used = true WHERE guest_fingerprint IS NOT NULL;
    END IF;

    -- Drop fingerprint binding columns if present
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

    BEGIN
      ALTER TABLE public.ghost_sessions ALTER COLUMN expires_at SET DEFAULT (now() + interval '10 minutes');
    EXCEPTION
      WHEN others THEN
        -- ignore
    END;
  END IF;
END $$;
