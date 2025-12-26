-- Ephemeral session tracking for Ghost
CREATE TABLE IF NOT EXISTS public.ghost_sessions (
  id TEXT PRIMARY KEY,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at TIMESTAMPTZ NOT NULL DEFAULT (NOW() + INTERVAL '5 minutes'),
  host_fingerprint TEXT NOT NULL
);

-- Enable Row Level Security
ALTER TABLE public.ghost_sessions ENABLE ROW LEVEL SECURITY;

-- Anyone can view sessions (to check if they exist)
CREATE POLICY "Session visibility" ON public.ghost_sessions 
  FOR SELECT USING (true);

-- Anyone can create sessions
CREATE POLICY "Session creation" ON public.ghost_sessions 
  FOR INSERT WITH CHECK (true);

-- Anyone can delete expired sessions
CREATE POLICY "Session cleanup" ON public.ghost_sessions 
  FOR DELETE USING (expires_at < NOW());

-- Enable realtime for session coordination
ALTER PUBLICATION supabase_realtime ADD TABLE public.ghost_sessions;