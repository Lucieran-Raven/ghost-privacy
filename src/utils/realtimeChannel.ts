import { deriveRealtimeChannelName as deriveRealtimeChannelNameAlgorithm } from '@/utils/algorithms/session/realtimeChannel';
import { isTauriRuntime, tauriInvoke } from '@/utils/runtime';

export async function deriveRealtimeChannelName(sessionId: string, capabilityToken: string): Promise<string> {
  if (isTauriRuntime()) {
    try {
      const name = await tauriInvoke<string>('derive_realtime_channel_name', {
        sessionId,
        capabilityToken
      });
      if (
        typeof name === 'string' &&
        /^ghost-session-GHOST-[A-Z0-9]{4}-[A-Z0-9]{4}-[a-f0-9]{32}$/.test(name)
      ) {
        return name;
      }
    } catch {
      // Ignore
    }
  }

  return deriveRealtimeChannelNameAlgorithm({ subtle: crypto.subtle }, sessionId, capabilityToken);
}
