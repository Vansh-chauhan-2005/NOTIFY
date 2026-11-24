import type { ClockFn, RateLimitResult } from '../types.js';
import { addRetryJitter } from './jitter.js';

export interface TokenBucketState {
  tokens: number;
  lastRefillMs: number;
}

export interface TokenBucketOptions {
  capacity: number;
  refillPerSec: number;
  cost?: number;
  clock?: ClockFn;
  rng?: () => number;
}

/**
 * Pure Token Bucket transition supporting burst capacity, steady refill, and weighted cost.
 */
export function evaluateTokenBucket(
  prevState: TokenBucketState | null,
  options: TokenBucketOptions
): { nextState: TokenBucketState; result: RateLimitResult } {
  const now = (options.clock ?? Date.now)();
  const capacity = Math.max(1, options.capacity);
  const refillPerSec = Math.max(0.01, options.refillPerSec);
  const cost = Math.max(1, options.cost ?? 1);

  const initialTokens = prevState ? prevState.tokens : capacity;
  const lastRefillMs = prevState ? prevState.lastRefillMs : now;

  const elapsedSec = Math.max(0, (now - lastRefillMs) / 1000);
  const replenished = Math.min(capacity, initialTokens + elapsedSec * refillPerSec);

  const fullRefillSeconds = Math.ceil((capacity - replenished) / refillPerSec);

  if (replenished + 1e-9 >= cost) {
    const remainingTokens = Math.max(0, replenished - cost);
    const secToFull = Math.ceil((capacity - remainingTokens) / refillPerSec);
    return {
      nextState: {
        tokens: remainingTokens,
        lastRefillMs: now,
      },
      result: {
        allowed: true,
        limit: capacity,
        remaining: Math.floor(remainingTokens),
        resetAtMs: now + secToFull * 1000,
        retryAfterSeconds: 0,
      },
    };
  }

  const deficit = cost - replenished;
  const waitSeconds = Math.max(1, Math.ceil(deficit / refillPerSec));

  return {
    nextState: {
      tokens: replenished,
      lastRefillMs: now,
    },
    result: {
      allowed: false,
      limit: capacity,
      remaining: Math.floor(replenished),
      resetAtMs: now + Math.max(waitSeconds, fullRefillSeconds) * 1000,
      retryAfterSeconds: addRetryJitter(waitSeconds, options.rng),
    },
  };
}
