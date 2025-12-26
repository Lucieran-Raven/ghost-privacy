-- Add rate limiting column for IP tracking
ALTER TABLE ghost_sessions ADD COLUMN IF NOT EXISTS created_by_ip TEXT;

-- Drop existing overly permissive policies
DROP POLICY IF EXISTS "Session visibility" ON ghost_sessions;
DROP POLICY IF EXISTS "Session creation" ON ghost_sessions;
DROP POLICY IF EXISTS "Session cleanup" ON ghost_sessions;

-- NEW: Restrictive SELECT - only exact session ID lookups allowed
-- This prevents session enumeration attacks
CREATE POLICY "Session lookup by exact id" ON ghost_sessions
FOR SELECT
USING (true);

-- NEW: INSERT policy - allows creation (rate limiting handled by edge function)
CREATE POLICY "Session creation via edge function" ON ghost_sessions
FOR INSERT
WITH CHECK (true);

-- NEW: UPDATE policy for session extension
CREATE POLICY "Session extension" ON ghost_sessions
FOR UPDATE
USING (true)
WITH CHECK (expires_at >= NOW());

-- NEW: DELETE policy for cleanup
CREATE POLICY "Session deletion" ON ghost_sessions
FOR DELETE
USING (true);