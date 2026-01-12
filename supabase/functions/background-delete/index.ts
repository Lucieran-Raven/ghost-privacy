import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { corsHeaders, getAllowedOrigins, isAllowedOrigin } from "../_shared/cors.ts";
import { jsonError, requireCronAuth } from "../_shared/security.ts";
import { getSupabaseServiceClient } from "../_shared/client.ts";

declare const Deno: {
  env: {
    get(key: string): string | undefined;
  };
};

const ALLOWED_ORIGINS = getAllowedOrigins();

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

  const cronAuthError = requireCronAuth(req, corsHeaders(req, ALLOWED_ORIGINS));
  if (cronAuthError) {
    return cronAuthError;
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
      return jsonError('Invalid request', 'INVALID_REQUEST', {
        status: 400,
        headers: corsHeaders(req, ALLOWED_ORIGINS)
      });
    }

    const { sessionId } = body;
    if (!sessionId || typeof sessionId !== 'string' || !/^GHOST-[A-Z0-9]{4}-[A-Z0-9]{4}$/.test(sessionId)) {
      return jsonError('Invalid request', 'INVALID_REQUEST', {
        status: 400,
        headers: corsHeaders(req, ALLOWED_ORIGINS)
      });
    }

    const { error } = await supabase
      .from('ghost_sessions')
      .delete()
      .eq('session_id', sessionId);

    if (error) {
      return errorResponse(req);
    }

    return new Response(
      JSON.stringify({ success: true }),
      { headers: { ...corsHeaders(req, ALLOWED_ORIGINS), 'Content-Type': 'application/json' } }
    );
  } catch (error: unknown) {
    return errorResponse(req);
  }
});
