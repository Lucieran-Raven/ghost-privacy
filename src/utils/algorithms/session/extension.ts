/**
 * Session Extension
 * Purpose: Construct inputs for fail-closed session TTL extension.
 * Input: sessionId, fingerprint.
 * Output: Edge function name + body payload.
 * Privacy: NEVER logs, NEVER stores, NEVER makes network requests, NEVER persists beyond caller-managed memory.
 */

import { createSessionHostActionBody, type SessionHostActionBody } from './binding';

export const EXTEND_SESSION_FUNCTION_NAME = 'extend-session' as const;

export interface ExtendSessionInvokeRequest {
  functionName: typeof EXTEND_SESSION_FUNCTION_NAME;
  body: SessionHostActionBody;
}

export function createExtendSessionInvokeRequest(
  sessionId: string,
  hostToken: string,
  channelToken: string
): ExtendSessionInvokeRequest {
  return {
    functionName: EXTEND_SESSION_FUNCTION_NAME,
    body: createSessionHostActionBody(sessionId, hostToken, channelToken)
  };
}
