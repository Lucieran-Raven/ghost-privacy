import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { corsHeaders, getAllowedOrigins, isAllowedOrigin } from "../_shared/cors.ts";
import {
  generateCapabilityToken,
  getRateLimitKeyHex,
  hashCapabilityTokenToBytea,
  jsonError,
} from "../_shared/security.ts";
import { getSupabaseServiceClient } from "../_shared/client.ts";

const ALLOWED_ORIGINS = getAllowedOrigins();

// Generic error response - never expose internals
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

    let body: { sessionId?: string; hostToken?: string; channelToken?: string };
    try {
      body = await req.json();
    } catch {
      return errorResponse(req, 400, 'INVALID_REQUEST');
    }

    const { sessionId, hostToken, channelToken } = body;

    // Validate session ID format (GHOST-XXXX-XXXX)
    const sessionIdPattern = /^GHOST-[A-Z0-9]{4}-[A-Z0-9]{4}$/;
    if (!sessionId || !sessionIdPattern.test(sessionId)) {
      return errorResponse(req, 400, 'INVALID_REQUEST');
    }

    if (!hostToken || typeof hostToken !== 'string' || hostToken.length !== 22) {
      return errorResponse(req, 400, 'INVALID_REQUEST');
    }

    if (!/^[A-Za-z0-9_-]+$/.test(hostToken)) {
      return errorResponse(req, 400, 'INVALID_REQUEST');
    }

    if (!channelToken || typeof channelToken !== 'string' || channelToken.length !== 22) {
      return errorResponse(req, 400, 'INVALID_REQUEST');
    }

    if (!/^[A-Za-z0-9_-]+$/.test(channelToken)) {
      return errorResponse(req, 400, 'INVALID_REQUEST');
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
      p_action: 'delete_session',
      p_window_start: windowStartIso,
      p_max_count: 120
    });

    if (rateErr || rateOk === false) {
      return errorResponse(req, 404, 'NOT_FOUND');
    }

    let hostHashBytea: string;
    let channelHashBytea: string;
    try {
      hostHashBytea = await hashCapabilityTokenToBytea(hostToken);
      channelHashBytea = await hashCapabilityTokenToBytea(channelToken);
    } catch {
      return errorResponse(req, 404, 'NOT_FOUND');
    }

    const revokedExpiryIso = new Date(0).toISOString();

    const rotatedHostToken = generateCapabilityToken();
    const rotatedGuestToken = generateCapabilityToken();
    const rotatedChannelToken = generateCapabilityToken();

    const rotatedHostHashBytea = await hashCapabilityTokenToBytea(rotatedHostToken);
    const rotatedGuestHashBytea = await hashCapabilityTokenToBytea(rotatedGuestToken);
    const rotatedChannelHashBytea = await hashCapabilityTokenToBytea(rotatedChannelToken);

    const { data: revoked, error: revokeError } = await supabase
      .from('ghost_sessions')
      .update({
        expires_at: revokedExpiryIso,
        capability_hash: rotatedHostHashBytea,
        host_capability_hash: rotatedHostHashBytea,
        guest_capability_hash: rotatedGuestHashBytea,
        channel_token_hash: rotatedChannelHashBytea
      })
      .eq('session_id', sessionId)
      .eq('host_capability_hash', hostHashBytea)
      .eq('channel_token_hash', channelHashBytea)
      .select('session_id')
      .maybeSingle();

    if (revokeError) {
      return errorResponse(req, 500, 'SERVER_ERROR');
    }

    if (!revoked?.session_id) {
      return errorResponse(req, 404, 'NOT_FOUND');
    }

    return new Response(
      JSON.stringify({ success: true }),
      { headers: { ...corsHeaders(req, ALLOWED_ORIGINS), 'Content-Type': 'application/json' } }
    );

  } catch (error: unknown) {
    return errorResponse(req, 500, 'SERVER_ERROR');
  }
});
