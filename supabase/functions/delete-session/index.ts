import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
};

// Generic error response - never expose internals
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

    const { sessionId } = await req.json();

    // Validate session ID format (GHOST-XXXX-XXXX)
    const sessionIdPattern = /^GHOST-[A-Z0-9]{4}-[A-Z0-9]{4}$/;
    if (!sessionId || !sessionIdPattern.test(sessionId)) {
      console.log('[delete-session] Invalid session ID format');
      return errorResponse(400);
    }

    console.log(`[delete-session] Deleting session: ${sessionId}`);

    // Delete the session - service_role bypasses RLS
    const { error } = await supabase
      .from('ghost_sessions')
      .delete()
      .eq('session_id', sessionId);

    if (error) {
      console.error('[delete-session] Database error:', error.message);
      return errorResponse(500);
    }

    console.log(`[delete-session] Session ${sessionId} deleted`);

    return new Response(
      JSON.stringify({ success: true }),
      { headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
    );

  } catch (error: unknown) {
    console.error('[delete-session] Unexpected error:', error instanceof Error ? error.message : 'Unknown');
    return errorResponse(500);
  }
});
