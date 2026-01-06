/**
 * Session Revocation (fail-closed deletion)
 * Purpose: Construct inputs for fail-closed session deletion.
 * Input: sessionId, fingerprint.
 * Output: Edge function name + body payload.
 * Privacy: NEVER logs, NEVER stores, NEVER makes network requests, NEVER persists beyond caller-managed memory.
 */

import { createSessionCapabilityBindingBody, type SessionCapabilityBindingBody } from './binding';

export const DELETE_SESSION_FUNCTION_NAME = 'delete-session' as const;

export interface DeleteSessionInvokeRequest {
  functionName: typeof DELETE_SESSION_FUNCTION_NAME;
  body: SessionCapabilityBindingBody;
}

export function createDeleteSessionInvokeRequest(
  sessionId: string,
  fingerprint: string,
  capabilityToken: string
): DeleteSessionInvokeRequest {
  return {
    functionName: DELETE_SESSION_FUNCTION_NAME,
    body: createSessionCapabilityBindingBody(sessionId, fingerprint, capabilityToken)
  };
}
