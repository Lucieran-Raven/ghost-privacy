import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { corsHeaders, getAllowedOrigins, isAllowedOrigin } from "../_shared/cors.ts";
import {
  generateCapabilityToken,
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

    let body: { sessionId?: string; capabilityToken?: string };
    try {
      body = await req.json();
    } catch {
      return errorResponse(req, 400, 'INVALID_REQUEST');
    }

    const { sessionId, capabilityToken } = body;

    // Validate session ID format (GHOST-XXXX-XXXX)
    const sessionIdPattern = /^GHOST-[A-Z0-9]{4}-[A-Z0-9]{4}$/;
    if (!sessionId || !sessionIdPattern.test(sessionId)) {
      return errorResponse(req, 400, 'INVALID_REQUEST');
    }

    if (!capabilityToken || typeof capabilityToken !== 'string' || capabilityToken.length < 16 || capabilityToken.length > 64) {
      return errorResponse(req, 400, 'INVALID_REQUEST');
    }

    if (!/^[A-Za-z0-9_-]+$/.test(capabilityToken)) {
      return errorResponse(req, 400, 'INVALID_REQUEST');
    }

    let capabilityHashBytea: string;
    try {
      capabilityHashBytea = await hashCapabilityTokenToBytea(capabilityToken);
    } catch {
      return errorResponse(req, 404, 'NOT_FOUND');
    }

    const revokedExpiryIso = new Date(0).toISOString();

    const rotatedToken = generateCapabilityToken();
    const rotatedCapabilityHashBytea = await hashCapabilityTokenToBytea(rotatedToken);

    const { data: revoked, error: revokeError } = await supabase
      .from('ghost_sessions')
      .update({ expires_at: revokedExpiryIso, capability_hash: rotatedCapabilityHashBytea })
      .eq('session_id', sessionId)
      .eq('capability_hash', capabilityHashBytea)
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
