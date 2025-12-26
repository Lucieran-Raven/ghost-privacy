import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type, x-ghost-session-id',
};

// Generic error responses - never leak internal details
const errorResponse = (status: number) => new Response(
  JSON.stringify({ success: false }),
  { headers: { ...corsHeaders, 'Content-Type': 'application/json' }, status }
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
      console.error('[extend-session] Invalid JSON body');
      return errorResponse(400);
    }

    const { sessionId } = body;
    
    // Strict input validation
    if (!sessionId || typeof sessionId !== 'string' || !/^GHOST-[A-Z0-9]{4}-[A-Z0-9]{4}$/.test(sessionId)) {
      console.error('[extend-session] Invalid session ID format');
      return errorResponse(400);
    }
    
    console.log('[extend-session] Extending session');
    
    // Verify session exists and is not expired before extending
    const { data: existingSession, error: checkError } = await supabase
      .from('ghost_sessions')
      .select('session_id, expires_at')
      .eq('session_id', sessionId)
      .gt('expires_at', new Date().toISOString())
      .maybeSingle();
    
    if (checkError) {
      console.error('[extend-session] Check error:', checkError.message);
      return errorResponse(500);
    }
    
    if (!existingSession) {
      console.log('[extend-session] Session not found or expired');
      return errorResponse(404);
    }
    
    // Extend session by 30 minutes
    const newExpiry = new Date(Date.now() + 30 * 60 * 1000).toISOString();
    
    const { error: updateError } = await supabase
      .from('ghost_sessions')
      .update({ expires_at: newExpiry })
      .eq('session_id', sessionId);
    
    if (updateError) {
      console.error('[extend-session] Update error:', updateError.message);
      return errorResponse(500);
    }
    
    console.log('[extend-session] Session extended successfully');
    
    return new Response(
      JSON.stringify({ 
        success: true, 
        expiresAt: newExpiry 
      }),
      { headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
    );
    
  } catch (error: unknown) {
    console.error('[extend-session] Unexpected error:', error instanceof Error ? error.message : 'Unknown');
    return errorResponse(500);
  }
});
