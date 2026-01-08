import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";
import { corsHeaders, getAllowedOrigins, isAllowedOrigin } from "../_shared/cors.ts";
import {
  getClientIpHashHex,
  jsonError,
  parseSessionIpHash,
  timingSafeEqualString,
  verifyCapabilityHash
} from "../_shared/security.ts";

declare const Deno: {
  env: {
    get(key: string): string | undefined;
  };
};

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

  try {
    const supabaseUrl = Deno.env.get('SUPABASE_URL')!;
    const supabaseServiceKey = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!;
    const supabase = createClient(supabaseUrl, supabaseServiceKey);

    let body: { sessionId?: string; fingerprint?: string; capabilityToken?: string };
    try {
      body = await req.json();
    } catch {
      return errorResponse(req, 400, 'INVALID_REQUEST');
    }

    const { sessionId, fingerprint, capabilityToken } = body;

    // Validate session ID format (GHOST-XXXX-XXXX)
    const sessionIdPattern = /^GHOST-[A-Z0-9]{4}-[A-Z0-9]{4}$/;
    if (!sessionId || !sessionIdPattern.test(sessionId)) {
      return errorResponse(req, 400, 'INVALID_REQUEST');
    }

    if (!fingerprint || typeof fingerprint !== 'string' || fingerprint.length < 8 || fingerprint.length > 128) {
      return errorResponse(req, 400, 'INVALID_REQUEST');
    }

    if (!capabilityToken || typeof capabilityToken !== 'string' || capabilityToken.length < 16 || capabilityToken.length > 64) {
      return errorResponse(req, 400, 'INVALID_REQUEST');
    }
    const fp = fingerprint.trim();

    const { data: session, error: readError } = await supabase
      .from('ghost_sessions')
      .select('session_id, host_fingerprint, guest_fingerprint, capability_hash, ip_hash')
      .eq('session_id', sessionId)
      .maybeSingle();

    if (readError || !session) {
      return errorResponse(req, 404, 'NOT_FOUND');
    }

    const capabilityOk = await verifyCapabilityHash(session.capability_hash, capabilityToken);
    if (!capabilityOk) {
      return errorResponse(req, 404, 'NOT_FOUND');
    }

    const isHost = timingSafeEqualString(fp, session.host_fingerprint);
    const isGuest = Boolean(session.guest_fingerprint && timingSafeEqualString(fp, session.guest_fingerprint));

    if (!isHost && !isGuest) {
      return errorResponse(req, 404, 'NOT_FOUND');
    }

    let clientIpHex: string;
    try {
      clientIpHex = await getClientIpHashHex(req);
    } catch {
      return errorResponse(req, 400, 'IP_UNAVAILABLE');
    }

    const ipParts = parseSessionIpHash(session.ip_hash);
    if (!ipParts) {
      return errorResponse(req, 500, 'SERVER_ERROR');
    }

    if (isHost && !timingSafeEqualString(ipParts.hostHex, clientIpHex)) {
      return errorResponse(req, 404, 'NOT_FOUND');
    }

    if (isGuest && !timingSafeEqualString(ipParts.guestHex, clientIpHex)) {
      return errorResponse(req, 404, 'NOT_FOUND');
    }

    // Build delete query with appropriate fingerprint filter
    const baseQuery = supabase
      .from('ghost_sessions')
      .delete()
      .eq('session_id', sessionId);
    
    const filteredQuery = isHost
      ? baseQuery.eq('host_fingerprint', fp)
      : baseQuery.eq('guest_fingerprint', fp);

    const { data: deleted, error: deleteError } = await filteredQuery
      .select('session_id')
      .maybeSingle();

    if (deleteError || !deleted?.session_id) {
      return errorResponse(req, 500, 'SERVER_ERROR');
    }

    return new Response(
      JSON.stringify({ success: true }),
      { headers: { ...corsHeaders(req, ALLOWED_ORIGINS), 'Content-Type': 'application/json' } }
    );

  } catch (error: unknown) {
    return errorResponse(req, 500, 'SERVER_ERROR');
  }
});
