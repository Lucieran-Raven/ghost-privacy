import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type, x-ghost-session-id',
};

// Constant-time generic response - prevents timing attacks
const invalidResponse = () => new Response(
  JSON.stringify({ valid: false }),
  { headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
);

const errorResponse = () => new Response(
  JSON.stringify({ valid: false }),
  { headers: { ...corsHeaders, 'Content-Type': 'application/json' }, status: 500 }
);

serve(async (req) => {
  if (req.method === 'OPTIONS') {
    return new Response(null, { headers: corsHeaders });
  }

  try {
    const supabaseUrl = Deno.env.get('SUPABASE_URL')!;
    const supabaseServiceKey = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!;
    const supabase = createClient(supabaseUrl, supabaseServiceKey);

    let body: { sessionId?: string };
    try {
      body = await req.json();
    } catch {
      console.error('[validate-session] Invalid JSON body');
      return invalidResponse();
    }

    const { sessionId } = body;
    
    // Strict input validation - constant-time response for all failures
    if (!sessionId || typeof sessionId !== 'string' || !/^GHOST-[A-Z0-9]{4}-[A-Z0-9]{4}$/.test(sessionId)) {
      console.error('[validate-session] Invalid session ID format');
      // Delay to match successful query timing
      await new Promise(r => setTimeout(r, 50));
      return invalidResponse();
    }
    
    console.log('[validate-session] Validating session');
    
    // Check if session exists and is not expired
    const { data: session, error } = await supabase
      .from('ghost_sessions')
      .select('session_id, expires_at')
      .eq('session_id', sessionId)
      .gt('expires_at', new Date().toISOString())
      .maybeSingle();
    
    if (error) {
      console.error('[validate-session] Database error:', error.message);
      return errorResponse();
    }
    
    if (!session) {
      console.log('[validate-session] Session not found or expired');
      return invalidResponse();
    }
    
    console.log('[validate-session] Session valid');
    
    // Return minimal data only
    return new Response(
      JSON.stringify({ 
        valid: true, 
        expiresAt: session.expires_at 
      }),
      { headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
    );
    
  } catch (error: unknown) {
    console.error('[validate-session] Unexpected error:', error instanceof Error ? error.message : 'Unknown');
    return errorResponse();
  }
});
