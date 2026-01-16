import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { corsHeaders, getAllowedOrigins, isAllowedOrigin } from "../_shared/cors.ts";
import {
  jsonError,
  getRateLimitKeyHex,
  verifyCapabilityHash
} from "../_shared/security.ts";
import { getSupabaseServiceClient } from "../_shared/client.ts";

const ALLOWED_ORIGINS = getAllowedOrigins();

// Generic error responses - never leak internal details
const errorResponse = async (req: Request, status: number, code: string) => {
  if (status === 404) {
    await new Promise(r => setTimeout(r, 50));
  }
  const messages: Record<string, string> = {
    INVALID_REQUEST: 'Invalid request',
    IP_UNAVAILABLE: 'Client IP unavailable',
    NOT_FOUND: 'Not found',
    SERVER_ERROR: 'Internal error'
  };

  return jsonError(messages[code] || 'Internal error', code, {
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

  if (req.method !== 'POST') {
    return new Response(null, { status: 405, headers: corsHeaders(req, ALLOWED_ORIGINS) });
  }

  try {
    const supabase = getSupabaseServiceClient();

    let body: { sessionId?: string; capabilityToken?: string };
    try {
      body = await req.json();
    } catch {
      return errorResponse(req, 400, 'INVALID_REQUEST');
    }

    const { sessionId, capabilityToken } = body;
    // Strict input validation
    if (!sessionId || typeof sessionId !== 'string' || !/^GHOST-[A-Z0-9]{4}-[A-Z0-9]{4}$/.test(sessionId)) {
      return errorResponse(req, 400, 'INVALID_REQUEST');
    }
    if (
      !capabilityToken ||
      typeof capabilityToken !== 'string' ||
      capabilityToken.length < 16 ||
      capabilityToken.length > 64 ||
      !/^[A-Za-z0-9_-]+$/.test(capabilityToken)
    ) {
      return errorResponse(req, 400, 'INVALID_REQUEST');
    }

    const { data: session, error: readError } = await supabase
      .from('ghost_sessions')
      .select('capability_hash, expires_at')
      .eq('session_id', sessionId)
      .maybeSingle();

    if (readError) {
      return errorResponse(req, 500, 'SERVER_ERROR');
    }
    if (!session) {
      return errorResponse(req, 404, 'NOT_FOUND');
    }

    const capabilityOk = await verifyCapabilityHash(session.capability_hash, capabilityToken);
    if (!capabilityOk) {
      return errorResponse(req, 404, 'NOT_FOUND');
    }

    const windowMs = 60 * 60 * 1000;
    const windowStart = new Date(Math.floor(Date.now() / windowMs) * windowMs);
    const windowStartIso = windowStart.toISOString();

    let rateKey: string;
    try {
      rateKey = await getRateLimitKeyHex(req, windowStartIso);
    } catch {
      return errorResponse(req, 404, 'NOT_FOUND');
    }

    const { data: rateOk, error: rateErr } = await supabase.rpc('increment_rate_limit', {
      p_ip_hash: rateKey,
      p_action: 'extend_session',
      p_window_start: windowStartIso,
      p_max_count: 300
    });

    if (rateErr || rateOk === false) {
      return errorResponse(req, 404, 'NOT_FOUND');
    }

    const now = Date.now();
    const currentExpiryMs = Date.parse(session.expires_at);
    if (Number.isNaN(currentExpiryMs) || currentExpiryMs <= now) {
      return errorResponse(req, 404, 'NOT_FOUND');
    }

    const extendThresholdMs = 5 * 60 * 1000;
    const shouldExtend = currentExpiryMs - now <= extendThresholdMs;
    const nextExpiryIso = shouldExtend
      ? new Date(now + 10 * 60 * 1000).toISOString()
      : session.expires_at;

    if (!shouldExtend) {
      return new Response(
        JSON.stringify({ success: true, expiresAt: nextExpiryIso }),
        { headers: { ...corsHeaders(req, ALLOWED_ORIGINS), 'Content-Type': 'application/json' } }
      );
    }

    const { data: updated, error: updateError } = await supabase
      .from('ghost_sessions')
      .update({ expires_at: nextExpiryIso })
      .eq('session_id', sessionId)
      .gt('expires_at', new Date().toISOString())
      .select('expires_at')
      .maybeSingle();

    if (updateError) {
      return errorResponse(req, 500, 'SERVER_ERROR');
    }
    if (!updated?.expires_at) {
      return errorResponse(req, 404, 'NOT_FOUND');
    }

    return new Response(
      JSON.stringify({ success: true, expiresAt: updated.expires_at }),
      { headers: { ...corsHeaders(req, ALLOWED_ORIGINS), 'Content-Type': 'application/json' } }
    );

  } catch (error: unknown) {
    return errorResponse(req, 500, 'SERVER_ERROR');
  }
});
