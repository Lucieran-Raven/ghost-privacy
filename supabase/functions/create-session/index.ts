import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type, x-ghost-session-id',
};

const RATE_LIMIT_MAX_SESSIONS = 10;
const RATE_LIMIT_WINDOW_MINUTES = 60;

// Generic error response - never leak internal details
const errorResponse = (status: number, code: string) => {
  const messages: Record<string, string> = {
    'INVALID_REQUEST': 'Invalid request',
    'RATE_LIMITED': 'Too many requests',
    'CONFLICT': 'Resource conflict',
    'SERVER_ERROR': 'Unable to process request',
  };
  return new Response(
    JSON.stringify({ success: false, error: messages[code] || 'Unable to process request' }),
    { headers: { ...corsHeaders, 'Content-Type': 'application/json' }, status }
  );
};

// Get trusted client IP (prefer x-real-ip, never trust x-forwarded-for alone)
const getClientIp = (req: Request): string => {
  const realIp = req.headers.get('x-real-ip');
  if (realIp) return realIp.trim();
  
  const cfIp = req.headers.get('cf-connecting-ip');
  if (cfIp) return cfIp.trim();
  
  return 'unknown';
};

serve(async (req) => {
  if (req.method === 'OPTIONS') {
    return new Response(null, { headers: corsHeaders });
  }

  try {
    const supabaseUrl = Deno.env.get('SUPABASE_URL')!;
    const supabaseServiceKey = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!;
    const supabase = createClient(supabaseUrl, supabaseServiceKey);

    let body: { sessionId?: string; hostFingerprint?: string };
    try {
      body = await req.json();
    } catch {
      console.error('[create-session] Invalid JSON body');
      return errorResponse(400, 'INVALID_REQUEST');
    }

    const { sessionId, hostFingerprint } = body;
    const clientIp = getClientIp(req);
    
    console.log(`[create-session] Request from IP hash: ${clientIp.substring(0, 8)}...`);
    
    // Strict input validation - no details leaked
    if (!sessionId || typeof sessionId !== 'string' || !/^GHOST-[A-Z0-9]{4}-[A-Z0-9]{4}$/.test(sessionId)) {
      console.error('[create-session] Invalid session ID format');
      return errorResponse(400, 'INVALID_REQUEST');
    }
    
    if (!hostFingerprint || typeof hostFingerprint !== 'string' || hostFingerprint.length < 8 || hostFingerprint.length > 128) {
      console.error('[create-session] Invalid host fingerprint');
      return errorResponse(400, 'INVALID_REQUEST');
    }

    // Distributed rate limiting using rate_limits table
    const windowStart = new Date();
    windowStart.setMinutes(Math.floor(windowStart.getMinutes() / RATE_LIMIT_WINDOW_MINUTES) * RATE_LIMIT_WINDOW_MINUTES, 0, 0);
    
    const { data: rateData, error: rateError } = await supabase
      .from('rate_limits')
      .select('count')
      .eq('ip_hash', clientIp)
      .eq('action', 'create_session')
      .gte('window_start', windowStart.toISOString())
      .maybeSingle();

    if (rateError) {
      console.error('[create-session] Rate limit check failed:', rateError.message);
    }

    const currentCount = rateData?.count || 0;
    
    if (currentCount >= RATE_LIMIT_MAX_SESSIONS) {
      console.warn(`[create-session] Rate limit exceeded for IP`);
      return errorResponse(429, 'RATE_LIMITED');
    }

    // Increment rate limit counter
    if (currentCount === 0) {
      await supabase.from('rate_limits').insert({
        ip_hash: clientIp,
        action: 'create_session',
        count: 1,
        window_start: windowStart.toISOString()
      });
    } else {
      await supabase.from('rate_limits')
        .update({ count: currentCount + 1 })
        .eq('ip_hash', clientIp)
        .eq('action', 'create_session')
        .gte('window_start', windowStart.toISOString());
    }
    
    // Create session with 30-minute TTL
    const expiresAt = new Date(Date.now() + 30 * 60 * 1000).toISOString();
    
    const { data, error } = await supabase
      .from('ghost_sessions')
      .insert({
        session_id: sessionId,
        host_fingerprint: hostFingerprint,
        expires_at: expiresAt
      })
      .select('session_id, expires_at')
      .single();
    
    if (error) {
      if (error.code === '23505') {
        console.error('[create-session] Session ID collision');
        return errorResponse(409, 'CONFLICT');
      }
      console.error('[create-session] Database error:', error.message);
      return errorResponse(500, 'SERVER_ERROR');
    }
    
    console.log(`[create-session] Session created successfully`);
    
    return new Response(
      JSON.stringify({ 
        success: true, 
        sessionId: data.session_id,
        expiresAt: data.expires_at
      }),
      { headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
    );
    
  } catch (error: unknown) {
    console.error('[create-session] Unexpected error:', error instanceof Error ? error.message : 'Unknown');
    return errorResponse(500, 'SERVER_ERROR');
  }
});
