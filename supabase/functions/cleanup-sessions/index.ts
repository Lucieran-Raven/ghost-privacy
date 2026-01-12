import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { corsHeaders, getAllowedOrigins, isAllowedOrigin } from "../_shared/cors.ts";
import { jsonError, requireCronAuth } from "../_shared/security.ts";
import { getSupabaseServiceClient } from "../_shared/client.ts";

const ALLOWED_ORIGINS = getAllowedOrigins();

// Generic error response
const errorResponse = (req: Request) =>
  jsonError('Internal error', 'SERVER_ERROR', {
    status: 500,
    headers: corsHeaders(req, ALLOWED_ORIGINS)
  });

serve(async (req: Request) => {
  const origin = req.headers.get('origin') || '';
  if (origin && !isAllowedOrigin(origin, ALLOWED_ORIGINS)) {
    return new Response(null, { status: 403 });
  }

  if (req.method === 'OPTIONS') {
    return new Response(null, { headers: corsHeaders(req, ALLOWED_ORIGINS) });
  }

  const cronAuthError = requireCronAuth(req, corsHeaders(req, ALLOWED_ORIGINS));
  if (cronAuthError) {
    return cronAuthError;
  }

  if (req.method !== 'POST') {
    return new Response(null, { status: 405, headers: corsHeaders(req, ALLOWED_ORIGINS) });
  }
  try {
    const supabase = getSupabaseServiceClient();

    // Delete all expired sessions
    const { data, error } = await supabase
      .from('ghost_sessions')
      .delete()
      .lt('expires_at', new Date().toISOString())
      .select('session_id');
    
    if (error) {
      return errorResponse(req);
    }
    
    const deletedCount = data?.length || 0;
    
    // Also cleanup old rate limit entries (older than 2 hours)
    const twoHoursAgo = new Date(Date.now() - 2 * 60 * 60 * 1000).toISOString();
    const { error: rateLimitError } = await supabase
      .from('rate_limits')
      .delete()
      .lt('window_start', twoHoursAgo);
    
    void rateLimitError;
    
    return new Response(
      JSON.stringify({ 
        success: true, 
        deletedCount
      }),
      { headers: { ...corsHeaders(req, ALLOWED_ORIGINS), 'Content-Type': 'application/json' } }
    );
    
  } catch (error: unknown) {
    return errorResponse(req);
  }
});
