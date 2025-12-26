-- Explicit deny-all policies for Ghost tables
-- Service role bypasses RLS by default, so these block anon/authenticated only

-- Ghost sessions: Block all non-service-role access
CREATE POLICY "Block all client access" 
ON ghost_sessions 
FOR ALL 
TO authenticated, anon
USING (false)
WITH CHECK (false);

-- Rate limits: Block all non-service-role access
CREATE POLICY "Block all client access"
ON rate_limits
FOR ALL
TO authenticated, anon
USING (false)
WITH CHECK (false);