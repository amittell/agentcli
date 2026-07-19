/**
 * Normalize the trusted clock inputs used by authorization-proof verifiers.
 * Explicit invalid values fail closed instead of disabling temporal checks
 * through NaN arithmetic or throwing while formatting audit timestamps.
 */
export function normalizeProofTimeContext(
  context = {},
  { defaultClockSkewSeconds = 60 } = {},
) {
  const clockSkewInput = context.clockSkewSeconds ?? defaultClockSkewSeconds;
  const clockSkewSeconds = (
    (typeof clockSkewInput === 'number' || typeof clockSkewInput === 'string')
    && !(typeof clockSkewInput === 'string' && clockSkewInput.trim() === '')
  )
    ? Number(clockSkewInput)
    : Number.NaN;
  const clockSkewMs = clockSkewSeconds * 1000;
  if (!Number.isFinite(clockSkewSeconds) || clockSkewSeconds < 0 || !Number.isFinite(clockSkewMs)) {
    return {
      ok: false,
      reason: 'clockSkewSeconds must be a finite non-negative number',
    };
  }

  const nowInput = context.now;
  const nowMs = nowInput === undefined
    ? Date.now()
    : typeof nowInput === 'number'
      ? nowInput
      : nowInput instanceof Date
        ? nowInput.getTime()
        : Number.NaN;
  if (!Number.isFinite(nowMs)) {
    return {
      ok: false,
      reason: 'now must be a valid Date or finite millisecond timestamp',
    };
  }

  return {
    ok: true,
    nowMs,
    clockSkewSeconds,
    clockSkewMs,
  };
}
