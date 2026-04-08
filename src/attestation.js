/**
 * Provider-agnostic attestation utilities.
 *
 * Generic functions live here. Provider-specific code lives in ./signing/.
 */

import { createHash } from 'node:crypto';

const ATTESTATION_VERSION = 1;

export function buildAttestationPayload({
  executionId,
  timestamp,
  source,
  commandHash,
  principal,
  actorContext = null,
}) {
  const payload = {
    v: ATTESTATION_VERSION,
    command_hash: commandHash,
    execution_id: executionId,
    principal: principal || null,
    source,
    timestamp,
    ...(actorContext ? { actor_context: actorContext } : {}),
  };
  return JSON.stringify(payload);
}

export function commandHash(shell) {
  const h = createHash('sha256');
  h.update(shell.program || '');
  for (const arg of (shell.args || [])) {
    h.update('\0');
    h.update(arg);
  }
  if (shell.cwd) {
    h.update('\0cwd:');
    h.update(shell.cwd);
  }
  return `sha256:${h.digest('hex')}`;
}
