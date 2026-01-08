import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";
import { corsHeaders, getAllowedOrigins, isAllowedOrigin } from "../_shared/cors.ts";
import {
  buildSessionIpHashBytea,
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
    const supabaseUrl = Deno.env.get('SUPABASE_URL')!;
    const supabaseServiceKey = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!;
    const supabase = createClient(supabaseUrl, supabaseServiceKey);

    let body: { sessionId?: string; fingerprint?: string; capabilityToken?: string };
    try {
      body = await req.json();
    } catch {
      return invalidResponse(req);
    }

    const { sessionId, fingerprint, capabilityToken } = body;
    // Strict input validation - constant-time response for all failures
    if (!sessionId || typeof sessionId !== 'string' || !/^GHOST-[A-Z0-9]{4}-[A-Z0-9]{4}$/.test(sessionId)) {
      // Delay to match successful query timing
      await new Promise(r => setTimeout(r, 50));
      return invalidResponse(req);
    }

    if (!fingerprint || typeof fingerprint !== 'string' || fingerprint.length < 8 || fingerprint.length > 128) {
      await new Promise(r => setTimeout(r, 50));
      return invalidResponse(req);
    }

    if (!capabilityToken || typeof capabilityToken !== 'string' || capabilityToken.length < 16 || capabilityToken.length > 64) {
      await new Promise(r => setTimeout(r, 50));
      return invalidResponse(req);
    }

    const { data: session, error } = await supabase
      .from('ghost_sessions')
      .select('session_id, expires_at, host_fingerprint, guest_fingerprint, capability_hash, ip_hash')
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

    let clientIpHex: string;
    try {
      clientIpHex = await getClientIpHashHex(req);
    } catch {
      await new Promise(r => setTimeout(r, 50));
      return invalidResponse(req);
    }

    const ipParts = parseSessionIpHash(session.ip_hash);
    if (!ipParts) {
      await new Promise(r => setTimeout(r, 50));
      return invalidResponse(req);
    }

    const fp = fingerprint.trim();

    if (timingSafeEqualString(fp, session.host_fingerprint)) {
      if (!timingSafeEqualString(ipParts.hostHex, clientIpHex)) {
        await new Promise(r => setTimeout(r, 50));
        return invalidResponse(req);
      }
      return new Response(
        JSON.stringify({
          valid: true,
          expiresAt: session.expires_at
        }),
        { headers: { ...corsHeaders(req, ALLOWED_ORIGINS), 'Content-Type': 'application/json' } }
      );
    }

    if (session.guest_fingerprint && timingSafeEqualString(fp, session.guest_fingerprint)) {
      if (!timingSafeEqualString(ipParts.guestHex, clientIpHex)) {
        await new Promise(r => setTimeout(r, 50));
        return invalidResponse(req);
      }
      return new Response(
        JSON.stringify({
          valid: true,
          expiresAt: session.expires_at
        }),
        { headers: { ...corsHeaders(req, ALLOWED_ORIGINS), 'Content-Type': 'application/json' } }
      );
    }

    // First guest join: atomically bind guest fingerprint (fail-closed on race)
    if (!session.guest_fingerprint) {
      const nextIpHash = buildSessionIpHashBytea({ hostHex: ipParts.hostHex, guestHex: clientIpHex });
      const { data: updated, error: updateError } = await supabase
        .from('ghost_sessions')
        .update({ guest_fingerprint: fp, ip_hash: nextIpHash })
        .eq('session_id', sessionId)
        .is('guest_fingerprint', null)
        .gt('expires_at', new Date().toISOString())
        .select('expires_at')
        .maybeSingle();

      if (updateError) {
        return errorResponse(req);
      }

      if (updated?.expires_at) {
        return new Response(
          JSON.stringify({
            valid: true,
            expiresAt: updated.expires_at
          }),
          { headers: { ...corsHeaders(req, ALLOWED_ORIGINS), 'Content-Type': 'application/json' } }
        );
      }
    }

    return invalidResponse(req);
    
  } catch (error: unknown) {
    return errorResponse(req);
  }
});
