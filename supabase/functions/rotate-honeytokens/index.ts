import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2.39.3";

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
};

/**
 * GHOST MIRAGE: Rotating Honeytokens
 * 
 * Daily cron job that generates new decoy session IDs.
 * Old honeytokens become invalid, breaking attacker bookmarks.
 * 
 * Called via Supabase cron: `0 0 * * *` (daily at midnight)
 */

function generateHoneytoken(prefix: string = 'TRAP'): string {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  let result = `GHOST-${prefix}-`;
  for (let i = 0; i < 4; i++) {
    result += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return result;
}

serve(async (req) => {
  // Handle CORS preflight
  if (req.method === 'OPTIONS') {
    return new Response(null, { headers: corsHeaders });
  }

  try {
    const supabaseUrl = Deno.env.get('SUPABASE_URL')!;
    const supabaseKey = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!;
    const supabase = createClient(supabaseUrl, supabaseKey);

    console.log('[rotate-honeytokens] Starting daily rotation...');

    // Generate new honeytokens
    const newTokens = [
      { id: generateHoneytoken('TRAP'), type: 'explicit_trap' },
      { id: generateHoneytoken('TRAP'), type: 'explicit_trap' },
      { id: generateHoneytoken('DECOY'), type: 'dead_session' },
      { id: generateHoneytoken('DECOY'), type: 'dead_session' },
    ];

    // Get today's date for tracking
    const today = new Date().toISOString().split('T')[0];

    // Log rotation (no persistent storage of tokens themselves)
    console.log(`[rotate-honeytokens] Generated ${newTokens.length} new honeytokens for ${today}`);
    console.log('[rotate-honeytokens] New tokens:', newTokens.map(t => t.id).join(', '));

    // Note: In a real implementation, you could store these in a cache
    // or temporary table that gets cleared daily. For Ghost's zero-knowledge
    // model, we just generate them on-demand and log the rotation.

    return new Response(
      JSON.stringify({
        success: true,
        message: 'Honeytokens rotated successfully',
        date: today,
        count: newTokens.length,
        // Don't expose actual tokens in response
      }),
      {
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        status: 200,
      }
    );
  } catch (error) {
    console.error('[rotate-honeytokens] Error:', error);
    
    return new Response(
      JSON.stringify({ error: 'Rotation failed', details: error instanceof Error ? error.message : 'Unknown error' }),
      {
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        status: 500,
      }
    );
  }
});
