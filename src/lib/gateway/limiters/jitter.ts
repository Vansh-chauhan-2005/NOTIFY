/**
 * Adds bounded random jitter to Retry-After (seconds) so throttled clients
 * spread retries instead of creating thundering-herd spikes at reset boundaries.
 */
export function addRetryJitter(
  baseSeconds: number,
  rng: () => number = Math.random
): number {
  const safeBase = Math.max(1, Math.ceil(baseSeconds));
  const maxJitter = Math.max(1, Math.min(5, Math.ceil(safeBase * 0.15)));
  const jitter = Math.floor(Math.max(0, Math.min(0.9999, rng())) * (maxJitter + 1));
  return safeBase + jitter;
}
