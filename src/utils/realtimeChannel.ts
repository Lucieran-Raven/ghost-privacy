import { deriveRealtimeChannelName as deriveRealtimeChannelNameAlgorithm } from '@/utils/algorithms/session/realtimeChannel';
import { isValidCapabilityToken, isValidSessionId } from '@/utils/algorithms/session/binding';
import { isTauriRuntime, tauriInvoke } from '@/utils/runtime';

export async function deriveRealtimeChannelName(sessionId: string, channelToken: string): Promise<string> {
  if (!isValidSessionId(sessionId)) {
    throw new Error('invalid session id');
  }
  if (!isValidCapabilityToken(channelToken)) {
    throw new Error('invalid capability token');
  }

  if (isTauriRuntime()) {
    try {
      const name = await tauriInvoke<string>('derive_realtime_channel_name', {
        session_id: sessionId,
        capability_token: channelToken
      });
      if (
        typeof name === 'string' &&
        /^ghost-session-[a-f0-9]{32}$/.test(name)
      ) {
        return name;
      }
    } catch {
      // Ignore
    }
  }

  return deriveRealtimeChannelNameAlgorithm({ subtle: crypto.subtle }, sessionId, channelToken);
}
