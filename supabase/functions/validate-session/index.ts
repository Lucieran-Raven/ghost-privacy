import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { corsHeaders, getAllowedOrigins, isAllowedOrigin } from "../_shared/cors.ts";
import {
  jsonError,
  verifyCapabilityHash
} from "../_shared/security.ts";
import { getSupabaseServiceClient } from "../_shared/client.ts";

const ALLOWED_ORIGINS = getAllowedOrigins();

// Constant-time generic response - prevents timing attacks
const invalidResponse = (req: Request) => new Response(
  JSON.stringify({ valid: false }),
  { headers: { ...corsHeaders(req, ALLOWED_ORIGINS), 'Content-Type': 'application/json' } }
);

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

  try {
    const supabase = getSupabaseServiceClient();

    let body: { sessionId?: string; capabilityToken?: string; role?: string };
    try {
      body = await req.json();
    } catch {
      return invalidResponse(req);
    }

    const { sessionId, capabilityToken, role } = body;
    // Strict input validation - constant-time response for all failures
    if (!sessionId || typeof sessionId !== 'string' || !/^GHOST-[A-Z0-9]{4}-[A-Z0-9]{4}$/.test(sessionId)) {
      // Delay to match successful query timing
      await new Promise(r => setTimeout(r, 50));
      return invalidResponse(req);
    }

    if (!capabilityToken || typeof capabilityToken !== 'string' || capabilityToken.length < 16 || capabilityToken.length > 64) {
      await new Promise(r => setTimeout(r, 50));
      return invalidResponse(req);
    }

    const normalizedRole = role === 'host' || role === 'guest' ? role : null;
    if (!normalizedRole) {
      await new Promise(r => setTimeout(r, 50));
      return invalidResponse(req);
    }

    const { data: session, error } = await supabase
      .from('ghost_sessions')
      .select('session_id, expires_at, capability_hash, used')
      .eq('session_id', sessionId)
      .gt('expires_at', new Date().toISOString())
      .maybeSingle();
    if (error) {
      return errorResponse(req);
    }
    
    if (!session) {
      return invalidResponse(req);
    }

    const capabilityOk = await verifyCapabilityHash(session.capability_hash, capabilityToken);
    if (!capabilityOk) {
      await new Promise(r => setTimeout(r, 50));
      return invalidResponse(req);
    }

    if (normalizedRole === 'guest') {
      if (session.used === true) {
        await new Promise(r => setTimeout(r, 50));
        return invalidResponse(req);
      }

      const { data: updated, error: updateError } = await supabase
        .from('ghost_sessions')
        .update({ used: true })
        .eq('session_id', sessionId)
        .is('used', false)
        .gt('expires_at', new Date().toISOString())
        .select('expires_at')
        .maybeSingle();

      if (updateError) {
        return errorResponse(req);
      }

      if (updated?.expires_at) {
        return new Response(
          JSON.stringify({ valid: true, expiresAt: updated.expires_at }),
          { headers: { ...corsHeaders(req, ALLOWED_ORIGINS), 'Content-Type': 'application/json' } }
        );
      }

      await new Promise(r => setTimeout(r, 50));
      return invalidResponse(req);
    }

    // Host validation (no fingerprint binding)
    return new Response(
      JSON.stringify({ valid: true, expiresAt: session.expires_at }),
      { headers: { ...corsHeaders(req, ALLOWED_ORIGINS), 'Content-Type': 'application/json' } }
    );
    
  } catch (error: unknown) {
    return errorResponse(req);
  }
});
