export function replayClaimAccepted(result) {
  if (result === true) return true;
  if (!result || typeof result !== 'object' || Array.isArray(result)) return false;
  if (!Object.hasOwn(result, 'claimed') || result.claimed !== true) return false;
  if (Object.hasOwn(result, 'ok') && result.ok !== true) return false;
  return true;
}
