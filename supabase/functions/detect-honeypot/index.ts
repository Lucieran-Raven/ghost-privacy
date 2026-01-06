import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";
import { corsHeaders, getAllowedOrigins, isAllowedOrigin } from "../_shared/cors.ts";
import { jsonError } from "../_shared/security.ts";

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

  try {
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

    if (sessionId.startsWith('GHOST-TRAP-') || sessionId.startsWith('GHOST-DECOY-')) {
      return new Response(
        JSON.stringify({ isHoneypot: true, trapType: 'explicit_trap' }),
        { headers: { ...corsHeaders(req, ALLOWED_ORIGINS), 'Content-Type': 'application/json' } }
      );
    }

    const supabaseUrl = Deno.env.get('SUPABASE_URL')!;
    const supabaseServiceKey = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!;
    const supabase = createClient(supabaseUrl, supabaseServiceKey);

    const { data: session, error } = await supabase
      .from('ghost_sessions')
      .select('expires_at')
      .eq('session_id', sessionId)
      .maybeSingle();

    if (error) {
      return new Response(
        JSON.stringify({ isHoneypot: false, trapType: null }),
        { headers: { ...corsHeaders(req, ALLOWED_ORIGINS), 'Content-Type': 'application/json' } }
      );
    }

    if (session?.expires_at) {
      const expiresAt = Date.parse(session.expires_at);
      if (!Number.isNaN(expiresAt) && expiresAt < Date.now()) {
        return new Response(
          JSON.stringify({ isHoneypot: true, trapType: 'dead_session' }),
          { headers: { ...corsHeaders(req, ALLOWED_ORIGINS), 'Content-Type': 'application/json' } }
        );
      }
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
