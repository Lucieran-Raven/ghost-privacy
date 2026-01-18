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
  IF EXISTS (
    SELECT 1 FROM information_schema.tables
    WHERE table_schema = 'public' AND table_name = 'ghost_sessions'
  ) THEN
    IF NOT EXISTS (
      SELECT 1 FROM information_schema.columns
      WHERE table_schema = 'public' AND table_name = 'ghost_sessions' AND column_name = 'host_capability_hash'
    ) THEN
      ALTER TABLE public.ghost_sessions ADD COLUMN host_capability_hash bytea;
    END IF;

    IF NOT EXISTS (
      SELECT 1 FROM information_schema.columns
      WHERE table_schema = 'public' AND table_name = 'ghost_sessions' AND column_name = 'guest_capability_hash'
    ) THEN
      ALTER TABLE public.ghost_sessions ADD COLUMN guest_capability_hash bytea;
    END IF;

    IF NOT EXISTS (
      SELECT 1 FROM information_schema.columns
      WHERE table_schema = 'public' AND table_name = 'ghost_sessions' AND column_name = 'channel_token_hash'
    ) THEN
      ALTER TABLE public.ghost_sessions ADD COLUMN channel_token_hash bytea;
    END IF;

    IF NOT EXISTS (
      SELECT 1 FROM information_schema.columns
      WHERE table_schema = 'public' AND table_name = 'ghost_sessions' AND column_name = 'created_at'
    ) THEN
      ALTER TABLE public.ghost_sessions ADD COLUMN created_at timestamptz;
    END IF;

    IF NOT EXISTS (
      SELECT 1 FROM information_schema.columns
      WHERE table_schema = 'public' AND table_name = 'ghost_sessions' AND column_name = 'max_expires_at'
    ) THEN
      ALTER TABLE public.ghost_sessions ADD COLUMN max_expires_at timestamptz;
    END IF;

    UPDATE public.ghost_sessions
    SET host_capability_hash = capability_hash
    WHERE host_capability_hash IS NULL AND capability_hash IS NOT NULL;

    UPDATE public.ghost_sessions
    SET guest_capability_hash = capability_hash
    WHERE guest_capability_hash IS NULL AND capability_hash IS NOT NULL;

    UPDATE public.ghost_sessions
    SET channel_token_hash = gen_random_bytes(32)
    WHERE channel_token_hash IS NULL;

    UPDATE public.ghost_sessions
    SET host_capability_hash = gen_random_bytes(32)
    WHERE host_capability_hash IS NULL;

    UPDATE public.ghost_sessions
    SET guest_capability_hash = gen_random_bytes(32)
    WHERE guest_capability_hash IS NULL;

    UPDATE public.ghost_sessions
    SET created_at = now()
    WHERE created_at IS NULL;

    UPDATE public.ghost_sessions
    SET max_expires_at = (created_at + interval '30 minutes')
    WHERE max_expires_at IS NULL;

    BEGIN
      ALTER TABLE public.ghost_sessions ALTER COLUMN host_capability_hash SET NOT NULL;
      ALTER TABLE public.ghost_sessions ALTER COLUMN guest_capability_hash SET NOT NULL;
      ALTER TABLE public.ghost_sessions ALTER COLUMN channel_token_hash SET NOT NULL;
      ALTER TABLE public.ghost_sessions ALTER COLUMN created_at SET NOT NULL;
      ALTER TABLE public.ghost_sessions ALTER COLUMN created_at SET DEFAULT now();
      ALTER TABLE public.ghost_sessions ALTER COLUMN max_expires_at SET NOT NULL;
      ALTER TABLE public.ghost_sessions ALTER COLUMN max_expires_at SET DEFAULT (now() + interval '30 minutes');
    EXCEPTION
      WHEN others THEN
        -- ignore
    END;

    CREATE INDEX IF NOT EXISTS idx_ghost_sessions_host_capability
      ON public.ghost_sessions (session_id, host_capability_hash);

    CREATE INDEX IF NOT EXISTS idx_ghost_sessions_guest_capability
      ON public.ghost_sessions (session_id, guest_capability_hash);

    CREATE INDEX IF NOT EXISTS idx_ghost_sessions_channel_token
      ON public.ghost_sessions (session_id, channel_token_hash);

    CREATE INDEX IF NOT EXISTS idx_ghost_sessions_max_expires
      ON public.ghost_sessions (max_expires_at);
  END IF;
END $$;
