import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { corsHeaders, getAllowedOrigins, isAllowedOrigin } from "../_shared/cors.ts";
import {
  generateCapabilityToken,
  getClientIpHashHex,
  hashCapabilityTokenToBytea,
  jsonError
} from "../_shared/security.ts";
import { getSupabaseServiceClient } from "../_shared/client.ts";

const ALLOWED_ORIGINS = getAllowedOrigins();

const RATE_LIMIT_MAX_SESSIONS = 10;
const RATE_LIMIT_WINDOW_MINUTES = 60;

// Generic error response - never leak internal details
const errorResponse = (req: Request, status: number, code: string) => {
  const messages: Record<string, string> = {
    INVALID_REQUEST: 'Invalid request',
    IP_UNAVAILABLE: 'Client IP unavailable',
    RATE_LIMITED: 'Too many requests',
    CONFLICT: 'Resource conflict',
    SERVER_ERROR: 'Unable to process request',
  };
  return jsonError(messages[code] || 'Unable to process request', code, {
    status,
    headers: corsHeaders(req, ALLOWED_ORIGINS)
  });
};

serve(async (req: Request) => {
  const origin = req.headers.get('origin') || '';
  if (origin && !isAllowedOrigin(origin, ALLOWED_ORIGINS)) {
    return new Response(null, { status: 403 });
  }

  if (req.method === 'OPTIONS') {
    return new Response(null, { headers: corsHeaders(req, ALLOWED_ORIGINS) });
  }

  try {
    const supabase = getSupabaseServiceClient();

    let body: { sessionId?: string };
    try {
      body = await req.json();
    } catch {
      return errorResponse(req, 400, 'INVALID_REQUEST');
    }

    const { sessionId } = body;

    let clientIpHashHex: string;
    try {
      clientIpHashHex = await getClientIpHashHex(req);
    } catch {
      return errorResponse(req, 400, 'IP_UNAVAILABLE');
    }

    // Strict input validation - no details leaked
    if (!sessionId || typeof sessionId !== 'string' || !/^GHOST-[A-Z0-9]{4}-[A-Z0-9]{4}$/.test(sessionId)) {
      return errorResponse(req, 400, 'INVALID_REQUEST');
    }

    // SECURITY FIX: Atomic rate limiting with fixed windows
    // IMPORTANT: window_start must be stable within the window, otherwise the UPSERT never conflicts.
    const windowMs = RATE_LIMIT_WINDOW_MINUTES * 60 * 1000;
    const windowStart = new Date(Math.floor(Date.now() / windowMs) * windowMs);

    // Atomic increment using PostgreSQL ON CONFLICT
    const { data: rateResult, error: rateError } = await supabase.rpc('increment_rate_limit', {
      p_ip_hash: clientIpHashHex,
      p_action: 'create_session',
      p_window_start: windowStart.toISOString(),
      p_max_count: RATE_LIMIT_MAX_SESSIONS
    });

    if (rateError) {
      // SECURITY FIX: Fail closed on rate limit errors to prevent DoS/Abuse
      return errorResponse(req, 500, 'SERVER_ERROR');
    } else if (rateResult === false) {
      // RPC returns false when rate limit exceeded
      return errorResponse(req, 429, 'RATE_LIMITED');
    }

    // Create session with strict 10-minute TTL
    const expiresAt = new Date(Date.now() + 10 * 60 * 1000).toISOString();

    const capabilityToken = generateCapabilityToken();
    const capabilityHashBytea = await hashCapabilityTokenToBytea(capabilityToken);

    const { data, error } = await supabase
      .from('ghost_sessions')
      .insert({
        session_id: sessionId,
        capability_hash: capabilityHashBytea,
        used: false,
        expires_at: expiresAt
      })
      .select('session_id, expires_at')
      .single();

    if (error) {
      if (error.code === '23505') {
        return errorResponse(req, 409, 'CONFLICT');
      }
      return errorResponse(req, 500, 'SERVER_ERROR');
    }

    return new Response(
      JSON.stringify({
        success: true,
        sessionId: data.session_id,
        expiresAt: data.expires_at,
        capabilityToken
      }),
      { headers: { ...corsHeaders(req, ALLOWED_ORIGINS), 'Content-Type': 'application/json' } }
    );

  } catch (error: unknown) {
    return errorResponse(req, 500, 'SERVER_ERROR');
  }
});
