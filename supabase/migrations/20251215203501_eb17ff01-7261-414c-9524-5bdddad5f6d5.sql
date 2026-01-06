-- Ghost Privacy Backend - Complete Schema
-- Zero-knowledge session management

DO $$
BEGIN
  CREATE EXTENSION IF NOT EXISTS pgcrypto;
EXCEPTION
  WHEN others THEN
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
    capability_hash bytea,
    expires_at timestamptz NOT NULL DEFAULT (now() + interval '5 minutes')
  );
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
  BEGIN
    ALTER TABLE public.ghost_sessions ENABLE ROW LEVEL SECURITY;
  EXCEPTION
    WHEN others THEN
      -- ignore
  END;

  BEGIN
    ALTER TABLE public.rate_limits ENABLE ROW LEVEL SECURITY;
  EXCEPTION
    WHEN others THEN
      -- ignore
  END;
END $$;