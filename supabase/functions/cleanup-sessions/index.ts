import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
};

// Generic error response
const errorResponse = () => new Response(
  JSON.stringify({ success: false }),
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

    console.log('[cleanup-sessions] Starting cleanup');
    
    // Delete all expired sessions
    const { data, error } = await supabase
      .from('ghost_sessions')
      .delete()
      .lt('expires_at', new Date().toISOString())
      .select('session_id');
    
    if (error) {
      console.error('[cleanup-sessions] Database error:', error.message);
      return errorResponse();
    }
    
    const deletedCount = data?.length || 0;
    console.log(`[cleanup-sessions] Deleted ${deletedCount} expired sessions`);
    
    // Also cleanup old rate limit entries (older than 2 hours)
    const twoHoursAgo = new Date(Date.now() - 2 * 60 * 60 * 1000).toISOString();
    const { error: rateLimitError } = await supabase
      .from('rate_limits')
      .delete()
      .lt('window_start', twoHoursAgo);
    
    if (rateLimitError) {
      console.warn('[cleanup-sessions] Rate limit cleanup warning:', rateLimitError.message);
    }
    
    return new Response(
      JSON.stringify({ 
        success: true, 
        deletedCount
      }),
      { headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
    );
    
  } catch (error: unknown) {
    console.error('[cleanup-sessions] Unexpected error:', error instanceof Error ? error.message : 'Unknown');
    return errorResponse();
  }
});
