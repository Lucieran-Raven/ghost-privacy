import { deriveRealtimeChannelName as deriveRealtimeChannelNameAlgorithm } from '@/utils/algorithms/session/realtimeChannel';
import { isTauriRuntime, tauriInvoke } from '@/utils/runtime';

export async function deriveRealtimeChannelName(sessionId: string, capabilityToken: string): Promise<string> {
  if (isTauriRuntime()) {
    try {
      const name = await tauriInvoke<string>('derive_realtime_channel_name', {
        sessionId,
        capabilityToken
      });
      if (typeof name === 'string' && name.length > 0) {
        return name;
      }
    } catch {
      // Ignore
    }
  }

  return deriveRealtimeChannelNameAlgorithm({ subtle: crypto.subtle }, sessionId, capabilityToken);
}
