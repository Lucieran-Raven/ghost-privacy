import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { corsHeaders, getAllowedOrigins, isAllowedOrigin } from "../_shared/cors.ts";
import { getRateLimitKeyHex, jsonError } from "../_shared/security.ts";
import { getSupabaseServiceClient } from "../_shared/client.ts";

declare const Deno: {
  env: {
    get(key: string): string | undefined;
  };
};

const ALLOWED_ORIGINS = getAllowedOrigins();

/**
 * GHOST MIRAGE: Honeypot Detection System
 *
 * Detects if a session ID is a honeytoken (trap session).
 */

serve(async (req) => {
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

    let body: { sessionId?: string; accessorFingerprint?: string };
    try {
      body = await req.json();
    } catch {
      return new Response(
        JSON.stringify({ isHoneypot: false, trapType: null }),
        { headers: { ...corsHeaders(req, ALLOWED_ORIGINS), 'Content-Type': 'application/json' } }
      );
    }

    const sessionId = (body.sessionId || '').toString();
    if (!sessionId) {
      return new Response(
        JSON.stringify({ isHoneypot: false, trapType: null }),
        { headers: { ...corsHeaders(req, ALLOWED_ORIGINS), 'Content-Type': 'application/json' } }
      );
    }

    const windowMs = 60 * 60 * 1000;
    const windowStart = new Date(Math.floor(Date.now() / windowMs) * windowMs);
    const windowStartIso = windowStart.toISOString();

    let rateKey: string;
    try {
      rateKey = await getRateLimitKeyHex(req, windowStartIso);
    } catch {
      return new Response(
        JSON.stringify({ isHoneypot: false, trapType: null }),
        { headers: { ...corsHeaders(req, ALLOWED_ORIGINS), 'Content-Type': 'application/json' } }
      );
    }

    const { data: rateOk, error: rateErr } = await supabase.rpc('increment_rate_limit', {
      p_ip_hash: rateKey,
      p_action: 'detect_honeypot',
      p_window_start: windowStartIso,
      p_max_count: 400
    });

    if (rateErr || rateOk === false) {
      return new Response(
        JSON.stringify({ isHoneypot: false, trapType: null }),
        { headers: { ...corsHeaders(req, ALLOWED_ORIGINS), 'Content-Type': 'application/json' } }
      );
    }

    if (sessionId.startsWith('GHOST-TRAP-') || sessionId.startsWith('GHOST-DECOY-')) {
      return new Response(
        JSON.stringify({ isHoneypot: true, trapType: 'explicit_trap' }),
        { headers: { ...corsHeaders(req, ALLOWED_ORIGINS), 'Content-Type': 'application/json' } }
      );
    }

    return new Response(
      JSON.stringify({ isHoneypot: false, trapType: null }),
      { headers: { ...corsHeaders(req, ALLOWED_ORIGINS), 'Content-Type': 'application/json' } }
    );

  } catch {
    return jsonError('Internal error', 'SERVER_ERROR', {
      status: 500,
      headers: corsHeaders(req, ALLOWED_ORIGINS)
    });
  }
});
