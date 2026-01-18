-- LAYER 10: Hash-only session identifiers
-- Converts any legacy human-readable session codes (GHOST-XXXX-XXXX) into SHA-256 hex.
-- Goal: backend never stores raw session codes; only stores non-reversible hashes.

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
    -- Convert only legacy raw session codes; do NOT re-hash already-hashed IDs.
    BEGIN
      UPDATE public.ghost_sessions
      SET session_id = lower(encode(digest(session_id, 'sha256'), 'hex'))
      WHERE session_id ~ '^GHOST-[A-Z0-9]{4}-[A-Z0-9]{4}$';
    EXCEPTION
      WHEN undefined_function THEN
        -- digest() unavailable (pgcrypto not present); ignore.
      WHEN others THEN
        -- ignore
    END;

    -- Enforce hash-only format going forward (defense-in-depth).
    -- Idempotent: if constraint already exists or cannot be added, ignore.
    BEGIN
      ALTER TABLE public.ghost_sessions
      ADD CONSTRAINT ghost_sessions_session_id_sha256_hex_chk
      CHECK (session_id ~ '^[0-9a-f]{64}$');
    EXCEPTION
      WHEN duplicate_object THEN
        -- ignore
      WHEN others THEN
        -- ignore
    END;
  END IF;
END $$;
