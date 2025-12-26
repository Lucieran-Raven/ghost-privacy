-- ============================================
-- GHOST SESSIONS: SERVICE ROLE ONLY ACCESS
-- ============================================

-- Drop all existing RLS policies on ghost_sessions
DROP POLICY IF EXISTS "Session lookup by exact id only" ON ghost_sessions;
DROP POLICY IF EXISTS "Session creation via service role only" ON ghost_sessions;
DROP POLICY IF EXISTS "Session extension via service role only" ON ghost_sessions;
DROP POLICY IF EXISTS "Session deletion via service role only" ON ghost_sessions;

-- Create single comprehensive policy: ONLY service_role can access
CREATE POLICY "Service role full access only" 
ON ghost_sessions 
FOR ALL 
TO authenticated, anon
USING (false)
WITH CHECK (false);

-- Grant service_role bypass (service_role bypasses RLS by default)
-- This policy blocks anon/authenticated, service_role is unaffected

-- ============================================
-- RATE LIMITS: SERVICE ROLE ONLY ACCESS  
-- ============================================

-- Drop existing policies on rate_limits
DROP POLICY IF EXISTS "Rate limits service role only" ON rate_limits;

-- Create restrictive policy: block all non-service-role access
CREATE POLICY "Block all non-service-role access"
ON rate_limits
FOR ALL
TO authenticated, anon
USING (false)
WITH CHECK (false);

-- ============================================
-- VERIFY RLS IS ENABLED ON BOTH TABLES
-- ============================================
ALTER TABLE ghost_sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE rate_limits ENABLE ROW LEVEL SECURITY;