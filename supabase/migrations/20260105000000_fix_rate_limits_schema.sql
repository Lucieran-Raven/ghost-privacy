-- SECURITY FIX: Normalize rate_limits schema for atomic sliding-window rate limiting
-- Ensures increment_rate_limit() ON CONFLICT (ip_hash, action, window_start) is valid

DO $$
BEGIN
  CREATE EXTENSION IF NOT EXISTS pgcrypto;
EXCEPTION
  WHEN others THEN
    -- ignore
END $$;

DO $$
BEGIN
  CREATE TABLE IF NOT EXISTS public.rate_limits (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    ip_hash text NOT NULL,
    action text NOT NULL,
    count integer NOT NULL DEFAULT 1,
    window_start timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
  );
END $$;

DO $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM information_schema.tables
    WHERE table_schema = 'public' AND table_name = 'rate_limits'
  ) THEN
    -- Add missing columns (idempotent)
    IF NOT EXISTS (
      SELECT 1 FROM information_schema.columns
      WHERE table_schema = 'public' AND table_name = 'rate_limits' AND column_name = 'action'
    ) THEN
      ALTER TABLE public.rate_limits ADD COLUMN action text;
    END IF;

    IF NOT EXISTS (
      SELECT 1 FROM information_schema.columns
      WHERE table_schema = 'public' AND table_name = 'rate_limits' AND column_name = 'count'
    ) THEN
      ALTER TABLE public.rate_limits ADD COLUMN count integer;
    END IF;

    IF NOT EXISTS (
      SELECT 1 FROM information_schema.columns
      WHERE table_schema = 'public' AND table_name = 'rate_limits' AND column_name = 'window_start'
    ) THEN
      ALTER TABLE public.rate_limits ADD COLUMN window_start timestamptz;
    END IF;

    IF NOT EXISTS (
      SELECT 1 FROM information_schema.columns
      WHERE table_schema = 'public' AND table_name = 'rate_limits' AND column_name = 'created_at'
    ) THEN
      ALTER TABLE public.rate_limits ADD COLUMN created_at timestamptz;
    END IF;

    -- Backfill defaults / NULLs (safe: rate limiting is ephemeral)
    UPDATE public.rate_limits SET action = 'unknown' WHERE action IS NULL;
    UPDATE public.rate_limits SET count = 1 WHERE count IS NULL;
    UPDATE public.rate_limits SET window_start = now() WHERE window_start IS NULL;
    UPDATE public.rate_limits SET created_at = now() WHERE created_at IS NULL;

    -- Enforce NOT NULLs where possible
    BEGIN
      ALTER TABLE public.rate_limits ALTER COLUMN ip_hash SET NOT NULL;
      ALTER TABLE public.rate_limits ALTER COLUMN action SET NOT NULL;
      ALTER TABLE public.rate_limits ALTER COLUMN count SET NOT NULL;
      ALTER TABLE public.rate_limits ALTER COLUMN window_start SET NOT NULL;
      ALTER TABLE public.rate_limits ALTER COLUMN created_at SET NOT NULL;
    EXCEPTION
      WHEN others THEN
        -- ignore
    END;

    -- Ensure unique constraint for atomic upsert
    BEGIN
      ALTER TABLE public.rate_limits ADD CONSTRAINT rate_limits_ip_action_window_key UNIQUE (ip_hash, action, window_start);
    EXCEPTION
      WHEN duplicate_object THEN
        -- ignore
      WHEN others THEN
        -- ignore
    END;

    -- Helpful index
    BEGIN
      CREATE INDEX IF NOT EXISTS idx_rate_limits_window ON public.rate_limits (ip_hash, action, window_start);
    EXCEPTION
      WHEN others THEN
        -- ignore
    END;

    -- RLS lockdown
    BEGIN
      ALTER TABLE public.rate_limits ENABLE ROW LEVEL SECURITY;
      DROP POLICY IF EXISTS deny_all ON public.rate_limits;
      CREATE POLICY deny_all ON public.rate_limits FOR ALL TO PUBLIC USING (false) WITH CHECK (false);
    EXCEPTION
      WHEN others THEN
        -- ignore
    END;
  END IF;
END $$;
