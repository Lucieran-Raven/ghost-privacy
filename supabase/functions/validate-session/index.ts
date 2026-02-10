import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { corsHeaders, getAllowedOrigins, isAllowedOrigin } from "../_shared/cors.ts";
import {
  getRateLimitKeyHex,
  generateCapabilityToken,
  hashCapabilityTokenToBytea,
  hashSessionIdHex
} from "../_shared/security.ts";
import { getSupabaseServiceClient } from "../_shared/client.ts";

const ALLOWED_ORIGINS = getAllowedOrigins();

// Constant-time generic response - prevents timing attacks
const invalidResponse = (req: Request) => new Response(
  JSON.stringify({ valid: false }),
  { headers: { ...corsHeaders(req, ALLOWED_ORIGINS), 'Content-Type': 'application/json' } }
);

const errorResponse = async (req: Request) => {
  await new Promise(r => setTimeout(r, 50));
  return invalidResponse(req);
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

    let body: { sessionId?: string; token?: string; channelToken?: string; role?: string };
    try {
      body = await req.json();
    } catch {
      return invalidResponse(req);
    }

    const { sessionId, token, channelToken, role } = body;
    // Strict input validation - constant-time response for all failures
    if (!sessionId || typeof sessionId !== 'string' || !/^GHOST-[A-Z0-9]{4}-[A-Z0-9]{4}$/.test(sessionId)) {
      // Delay to match successful query timing
      await new Promise(r => setTimeout(r, 50));
      return invalidResponse(req);
    }

    let storedSessionId: string;
    try {
      storedSessionId = await hashSessionIdHex(sessionId);
    } catch {
      await new Promise(r => setTimeout(r, 50));
      return invalidResponse(req);
    }

    if (!token || typeof token !== 'string' || token.length !== 22 || !/^[A-Za-z0-9_-]+$/.test(token)) {
      await new Promise(r => setTimeout(r, 50));
      return invalidResponse(req);
    }

    if (!channelToken || typeof channelToken !== 'string' || channelToken.length !== 22 || !/^[A-Za-z0-9_-]+$/.test(channelToken)) {
      await new Promise(r => setTimeout(r, 50));
      return invalidResponse(req);
    }

    const normalizedRole = role === 'host' || role === 'guest' ? role : null;
    if (!normalizedRole) {
      await new Promise(r => setTimeout(r, 50));
      return invalidResponse(req);
    }

    const windowMs = 60 * 60 * 1000;
    const windowStart = new Date(Math.floor(Date.now() / windowMs) * windowMs);
    const windowStartIso = windowStart.toISOString();

    let rateKey: string;
    const action = 'validate_session';
    try {
      rateKey = await getRateLimitKeyHex(req, action, windowStartIso);
    } catch {
      await new Promise(r => setTimeout(r, 50));
      return invalidResponse(req);
    }

    const { data: rateOk, error: rateErr } = await supabase.rpc('increment_rate_limit', {
      p_ip_hash: rateKey,
      p_action: action,
      p_window_start: windowStartIso,
      p_max_count: 200
    });

    if (rateErr || rateOk === false) {
      await new Promise(r => setTimeout(r, 50));
      return invalidResponse(req);
    }

    const nowIso = new Date().toISOString();

    let tokenHashBytea: string;
    let channelHashBytea: string;
    try {
      tokenHashBytea = await hashCapabilityTokenToBytea(token);
      channelHashBytea = await hashCapabilityTokenToBytea(channelToken);
    } catch {
      await new Promise(r => setTimeout(r, 50));
      return invalidResponse(req);
    }

    if (normalizedRole === 'guest') {
      const rotatedGuestToken = generateCapabilityToken();
      const rotatedGuestHashBytea = await hashCapabilityTokenToBytea(rotatedGuestToken);

      const { data: updated, error: updateError } = await supabase
        .from('ghost_sessions')
        .update({ used: true, guest_capability_hash: rotatedGuestHashBytea })
        .eq('session_id', storedSessionId)
        .eq('guest_capability_hash', tokenHashBytea)
        .eq('channel_token_hash', channelHashBytea)
        .is('used', false)
        .gt('expires_at', nowIso)
        .select('expires_at')
        .maybeSingle();

      if (updateError) {
        return await errorResponse(req);
      }

      if (updated?.expires_at) {
        return new Response(
          JSON.stringify({ valid: true, expiresAt: updated.expires_at, rotatedGuestToken }),
          { headers: { ...corsHeaders(req, ALLOWED_ORIGINS), 'Content-Type': 'application/json' } }
        );
      }

      await new Promise(r => setTimeout(r, 50));
      return invalidResponse(req);
    }

    const { data: session, error } = await supabase
      .from('ghost_sessions')
      .select('expires_at')
      .eq('session_id', storedSessionId)
      .eq('host_capability_hash', tokenHashBytea)
      .eq('channel_token_hash', channelHashBytea)
      .gt('expires_at', nowIso)
      .maybeSingle();

    if (error) {
      return await errorResponse(req);
    }

    if (!session?.expires_at) {
      await new Promise(r => setTimeout(r, 50));
      return invalidResponse(req);
    }

    return new Response(
      JSON.stringify({ valid: true, expiresAt: session.expires_at }),
      { headers: { ...corsHeaders(req, ALLOWED_ORIGINS), 'Content-Type': 'application/json' } }
    );
    
  } catch (error: unknown) {
    return await errorResponse(req);
  }
});
