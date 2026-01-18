import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { corsHeaders, getAllowedOrigins, isAllowedOrigin } from "../_shared/cors.ts";
import {
  generateCapabilityToken,
  getRateLimitKeyHex,
  hashCapabilityTokenToBytea,
  hashSessionIdHex,
  jsonResponse
} from "../_shared/security.ts";
import { getSupabaseServiceClient } from "../_shared/client.ts";

const ALLOWED_ORIGINS = getAllowedOrigins();

const RATE_LIMIT_MAX_SESSIONS = 10;
const RATE_LIMIT_WINDOW_MINUTES = 60;

// Generic error response - never leak internal details
const errorResponse = (req: Request, code: string) => {
  const messages: Record<string, string> = {
    INVALID_REQUEST: 'Invalid request',
    IP_UNAVAILABLE: 'Client IP unavailable',
    RATE_LIMITED: 'Rate limited',
    CONFLICT: 'Resource conflict',
    SERVER_ERROR: 'Unable to process request',
  };

  return jsonResponse(
    {
      success: false,
      error: messages[code] || 'Unable to process request',
      code
    },
    {
      status: 200,
      headers: { ...corsHeaders(req, ALLOWED_ORIGINS), 'Content-Type': 'application/json' }
    }
  );
};

serve(async (req: Request) => {
  const origin = req.headers.get('origin') || '';
  if (origin && !isAllowedOrigin(origin, ALLOWED_ORIGINS)) {
    return new Response(null, { status: 403 });
  }

  if (req.method === 'OPTIONS') {
    return new Response(null, { headers: corsHeaders(req, ALLOWED_ORIGINS) });
  }

  if (req.method !== 'POST') {
    return new Response(null, { status: 405, headers: corsHeaders(req, ALLOWED_ORIGINS) });
  }

  try {
    const supabase = getSupabaseServiceClient();

    let body: { sessionId?: string };
    try {
      body = await req.json();
    } catch {
      return errorResponse(req, 'INVALID_REQUEST');
    }

    const { sessionId } = body;

    // Strict input validation - no details leaked
    if (!sessionId || typeof sessionId !== 'string' || !/^GHOST-[A-Z0-9]{4}-[A-Z0-9]{4}$/.test(sessionId)) {
      return errorResponse(req, 'INVALID_REQUEST');
    }

    let storedSessionId: string;
    try {
      storedSessionId = await hashSessionIdHex(sessionId);
    } catch {
      return errorResponse(req, 'INVALID_REQUEST');
    }

    // SECURITY FIX: Atomic rate limiting with fixed windows
    // IMPORTANT: window_start must be stable within the window, otherwise the UPSERT never conflicts.
    const windowMs = RATE_LIMIT_WINDOW_MINUTES * 60 * 1000;
    const windowStart = new Date(Math.floor(Date.now() / windowMs) * windowMs);
    const windowStartIso = windowStart.toISOString();

    let rateKey: string;
    const action = 'create_session';
    try {
      rateKey = await getRateLimitKeyHex(req, action, windowStartIso);
    } catch {
      return errorResponse(req, 'IP_UNAVAILABLE');
    }

    // Atomic increment using PostgreSQL ON CONFLICT
    const { data: rateResult, error: rateError } = await supabase.rpc('increment_rate_limit', {
      p_ip_hash: rateKey,
      p_action: action,
      p_window_start: windowStartIso,
      p_max_count: RATE_LIMIT_MAX_SESSIONS
    });

    if (rateError) {
      // SECURITY FIX: Fail closed on rate limit errors to prevent DoS/Abuse
      return errorResponse(req, 'SERVER_ERROR');
    } else if (rateResult === false) {
      // RPC returns false when rate limit exceeded
      return errorResponse(req, 'RATE_LIMITED');
    }

    // Create session with strict 10-minute TTL
    const expiresAt = new Date(Date.now() + 10 * 60 * 1000).toISOString();

    const hostToken = generateCapabilityToken();
    const guestToken = generateCapabilityToken();
    const channelToken = generateCapabilityToken();

    const hostHashBytea = await hashCapabilityTokenToBytea(hostToken);
    const guestHashBytea = await hashCapabilityTokenToBytea(guestToken);
    const channelHashBytea = await hashCapabilityTokenToBytea(channelToken);

    const createdAt = new Date().toISOString();
    const maxExpiresAt = new Date(Date.now() + 30 * 60 * 1000).toISOString();

    const { data, error } = await supabase
      .from('ghost_sessions')
      .insert({
        session_id: storedSessionId,
        capability_hash: hostHashBytea,
        host_capability_hash: hostHashBytea,
        guest_capability_hash: guestHashBytea,
        channel_token_hash: channelHashBytea,
        used: false,
        expires_at: expiresAt,
        created_at: createdAt,
        max_expires_at: maxExpiresAt
      })
      .select('expires_at')
      .single();

    if (error) {
      if (error.code === '23505') {
        return errorResponse(req, 'CONFLICT');
      }
      return errorResponse(req, 'SERVER_ERROR');
    }

    return new Response(
      JSON.stringify({
        success: true,
        sessionId,
        expiresAt: data.expires_at,
        hostToken,
        guestToken,
        channelToken
      }),
      { headers: { ...corsHeaders(req, ALLOWED_ORIGINS), 'Content-Type': 'application/json' } }
    );

  } catch (error: unknown) {
    return errorResponse(req, 'SERVER_ERROR');
  }
});
