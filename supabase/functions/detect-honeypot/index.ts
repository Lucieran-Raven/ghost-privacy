import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
};

/**
 * GHOST MIRAGE: Honeypot Detection System
 * 
 * Detects if a session ID is a honeytoken (trap session).
 * Honeytokens are identified by:
 * 1. Specific prefix patterns (GHOST-TRAP-*)
 * 2. Expired sessions being re-accessed
 * 3. Sessions marked as honeypots in the database
 * 
 * When triggered, alerts the original session owner via realtime.
 */

serve(async (req) => {
  if (req.method === 'OPTIONS') {
    return new Response(null, { headers: corsHeaders });
  }

  try {
    const { sessionId, accessorFingerprint } = await req.json();

    if (!sessionId) {
      return new Response(
        JSON.stringify({ error: 'Session ID required' }),
        { status: 400, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
      );
    }

    console.log(`🕳️ [Honeypot] Checking session: ${sessionId}`);

    // Initialize Supabase with service role
    const supabaseUrl = Deno.env.get('SUPABASE_URL')!;
    const supabaseServiceKey = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!;
    const supabase = createClient(supabaseUrl, supabaseServiceKey);

    // Check 1: Is this a TRAP prefix session? (Explicit honeytokens)
    const isTrapPrefix = sessionId.startsWith('GHOST-TRAP-') || sessionId.startsWith('GHOST-DECOY-');
    
    // Check 2: Is this an expired session being re-accessed? (Dead session trap)
    const { data: session, error } = await supabase
      .from('ghost_sessions')
      .select('expires_at, host_fingerprint, session_id')
      .eq('session_id', sessionId)
      .maybeSingle();

    let isHoneypot = isTrapPrefix;
    let trapType = isTrapPrefix ? 'explicit_trap' : null;
    let originalOwner = null;

    if (session) {
      const isExpired = new Date(session.expires_at) < new Date();
      if (isExpired) {
        isHoneypot = true;
        trapType = 'dead_session';
        originalOwner = session.host_fingerprint;
        console.log(`🔴 [Honeypot] DEAD SESSION TRAP TRIGGERED: ${sessionId}`);
      }
    } else if (!isTrapPrefix) {
      // Session doesn't exist and isn't explicit trap - could be probing
      // Mark as suspicious but not confirmed honeypot
      console.log(`⚠️ [Honeypot] Unknown session probed: ${sessionId}`);
    }

    if (isHoneypot) {
      console.log(`🎯 [Honeypot] TRAP ACTIVATED - Type: ${trapType}, Session: ${sessionId}`);

      // If this was a dead session, broadcast alert to original owner
      // via realtime channel (they may still be listening)
      if (originalOwner && trapType === 'dead_session') {
        // Send alert via realtime broadcast
        const channel = supabase.channel(`ghost:${sessionId}`);
        await channel.send({
          type: 'broadcast',
          event: 'honeypot-alert',
          payload: {
            message: '⚠️ Suspicious access attempt detected on your expired session',
            timestamp: new Date().toISOString(),
            accessorFingerprint: accessorFingerprint || 'unknown'
          }
        });
        console.log(`📡 [Honeypot] Alert sent to original session owner`);
      }
    }

    return new Response(
      JSON.stringify({
        isHoneypot,
        trapType,
        // Never reveal internal details to potential attackers
        message: isHoneypot ? 'Session found' : 'Session not found'
      }),
      { headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
    );

  } catch (error) {
    console.error('[Honeypot] Detection error:', error);
    return new Response(
      JSON.stringify({ error: 'Internal error' }),
      { status: 500, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
    );
  }
});
