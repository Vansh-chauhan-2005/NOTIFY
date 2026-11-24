import type { ClockFn, RateLimitResult } from '../types.js';
import { addRetryJitter } from './jitter.js';

export interface SlidingWindowEntry {
  ts: number;
  cost: number;
}

export interface SlidingWindowState {
  entries: SlidingWindowEntry[];
}

export interface SlidingWindowOptions {
  limit: number;
  windowMs: number;
  cost?: number;
  clock?: ClockFn;
  rng?: () => number;
}

/**
 * Pure Sliding-Window Log limiter with strict boundary semantics:
 * an event at `ts` expires when `now - ts >= windowMs` (i.e. `ts > now - windowMs`).
 * Supports cost-weighted consumption and injected virtual clocks.
 */
export function evaluateSlidingWindow(
  prevState: SlidingWindowState | null,
  options: SlidingWindowOptions
): { nextState: SlidingWindowState; result: RateLimitResult } {
  const now = (options.clock ?? Date.now)();
  const limit = Math.max(1, options.limit);
  const windowMs = Math.max(1000, options.windowMs);
  const cost = Math.max(1, options.cost ?? 1);
  const cutoff = now - windowMs;

  const activeEntries = (prevState?.entries || []).filter((e) => e.ts > cutoff);
  const usedCost = activeEntries.reduce((acc, e) => acc + e.cost, 0);

  const oldestTs = activeEntries.length > 0 ? activeEntries[0].ts : now;
  const resetAtMs = oldestTs + windowMs;

  if (usedCost + cost <= limit) {
    const nextEntries = [...activeEntries, { ts: now, cost }];
    const remaining = Math.max(0, limit - (usedCost + cost));
    return {
      nextState: { entries: nextEntries },
      result: {
        allowed: true,
        limit,
        remaining,
        resetAtMs: nextEntries[0].ts + windowMs,
        retryAfterSeconds: 0,
      },
    };
  }

  // Compute earliest timestamp when enough cost expires to fit the requested cost
  let freed = 0;
  let releaseAtMs = now + windowMs;
  const needed = usedCost + cost - limit;
  for (const entry of activeEntries) {
    freed += entry.cost;
    if (freed >= needed) {
      releaseAtMs = entry.ts + windowMs;
      break;
    }
  }

  const baseWaitSeconds = Math.max(1, Math.ceil((releaseAtMs - now) / 1000));
  return {
    nextState: { entries: activeEntries },
    result: {
      allowed: false,
      limit,
      remaining: Math.max(0, limit - usedCost),
      resetAtMs,
      retryAfterSeconds: addRetryJitter(baseWaitSeconds, options.rng),
    },
  };
}
