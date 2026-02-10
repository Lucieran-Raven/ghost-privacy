/**
 * Session Revocation (fail-closed deletion)
 * Purpose: Construct inputs for fail-closed session deletion.
 * Input: sessionId, fingerprint.
 * Output: Edge function name + body payload.
 * Privacy: NEVER logs, NEVER stores, NEVER makes network requests, NEVER persists beyond caller-managed memory.
 */

import { createSessionHostActionBody, type SessionHostActionBody } from './binding';
import { isValidCapabilityToken, isValidSessionId } from './binding';

export const DELETE_SESSION_FUNCTION_NAME = 'delete-session' as const;

export interface DeleteSessionInvokeRequest {
  functionName: typeof DELETE_SESSION_FUNCTION_NAME;
  body: SessionHostActionBody;
}

export function createDeleteSessionInvokeRequest(
  sessionId: string,
  hostToken: string,
  channelToken: string
): DeleteSessionInvokeRequest {
  if (!isValidSessionId(sessionId)) {
    throw new Error('invalid session id');
  }
  if (!isValidCapabilityToken(hostToken)) {
    throw new Error('invalid host token');
  }
  if (!isValidCapabilityToken(channelToken)) {
    throw new Error('invalid channel token');
  }
  return {
    functionName: DELETE_SESSION_FUNCTION_NAME,
    body: createSessionHostActionBody(sessionId, hostToken, channelToken)
  };
}
