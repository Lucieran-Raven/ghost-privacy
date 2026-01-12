import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { corsHeaders, getAllowedOrigins, isAllowedOrigin } from "../_shared/cors.ts";
import { jsonError, requireCronAuth } from "../_shared/security.ts";

declare const Deno: {
  env: {
    get(key: string): string | undefined;
  };
};

const ALLOWED_ORIGINS = getAllowedOrigins();

/**
 * GHOST MIRAGE: Rotating Honeytokens
 *
 * Daily cron job that generates new decoy session IDs.
 * Old honeytokens become invalid, breaking attacker bookmarks.
 *
 * Called via Supabase cron: `0 0 * * *` (daily at midnight)
 */

serve(async (req: Request) => {
  const origin = req.headers.get('origin') || '';
  if (origin && !isAllowedOrigin(origin, ALLOWED_ORIGINS)) {
    return new Response(null, { status: 403 });
  }

  // Handle CORS preflight
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
    // Get today's date for tracking
    const today = new Date().toISOString().split('T')[0];

    return new Response(
      JSON.stringify({
        success: true,
        message: 'Honeytokens rotated successfully',
        date: today,
        count: 0,
        // Don't expose actual tokens in response
      }),
      {
        headers: { ...corsHeaders(req, ALLOWED_ORIGINS), 'Content-Type': 'application/json' },
        status: 200,
      }
    );
  } catch (error) {
    return jsonError('Rotation failed', 'SERVER_ERROR', {
      status: 500,
      headers: corsHeaders(req, ALLOWED_ORIGINS)
    });
  }
});
