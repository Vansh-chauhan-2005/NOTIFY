import { evaluateSlidingWindow, type SlidingWindowState } from '../limiters/slidingWindow.js';
import { evaluateTokenBucket, type TokenBucketState } from '../limiters/tokenBucket.js';
import type { ClockFn, RateLimitResult } from '../types.js';
import {
  GatewayStoreUnavailableError,
  type ConsumeLimitRequest,
  type GatewayStoreAdapter,
  type StoreStats,
} from './types.js';

interface LruEntry<T = unknown> {
  value: T;
  expiresAt: number;
}

/**
 * Bounded In-Memory LRU Gateway Store.
 *
 * Notice: In-memory storage tracks counters strictly per server instance.
 * Configure UPSTASH_REDIS_REST_URL + UPSTASH_REDIS_REST_TOKEN to share counters
 * across multiple horizontal Node/Express instances.
 */
export class MemoryLruGatewayStore implements GatewayStoreAdapter {
  readonly mode = 'memory' as const;
  private readonly map = new Map<string, LruEntry>();
  private readonly maxKeys: number;
  private readonly clock: ClockFn;
  private evictionCount = 0;
  private forcedFailure = false;
  private cleanupTimer: ReturnType<typeof setInterval> | null = null;

  constructor(options: { maxKeys?: number; clock?: ClockFn; cleanupIntervalMs?: number } = {}) {
    this.maxKeys = Math.max(10, Math.floor(options.maxKeys ?? 50_000));
    this.clock = options.clock ?? Date.now;

    if (options.cleanupIntervalMs && options.cleanupIntervalMs > 0) {
      this.cleanupTimer = setInterval(() => {
        this.cleanupExpired();
      }, options.cleanupIntervalMs);
      this.cleanupTimer.unref?.();
    }
  }

  setSimulatedFailure(enabled: boolean): void {
    this.forcedFailure = enabled;
  }

  private assertAvailable(): void {
    if (this.forcedFailure) {
      throw new GatewayStoreUnavailableError('Simulated gateway store outage.');
    }
  }

  private touch(key: string, entry: LruEntry): void {
    // Re-insert so Map iteration order keeps Least Recently Used key at the front
    this.map.delete(key);
    this.map.set(key, entry);
  }

  private evictIfNeeded(now: number): void {
    while (this.map.size >= this.maxKeys) {
      const first = this.map.entries().next();
      if (first.done) break;
      const [oldestKey, entry] = first.value;
      this.map.delete(oldestKey);
      if (entry.expiresAt > now) {
        this.evictionCount += 1;
      }
    }
  }

  cleanupExpired(): number {
    const now = this.clock();
    let removed = 0;
    for (const [k, entry] of this.map.entries()) {
      if (entry.expiresAt <= now) {
        this.map.delete(k);
        removed += 1;
      }
    }
    return removed;
  }

  async get<T = unknown>(key: string): Promise<T | null> {
    this.assertAvailable();
    const now = this.clock();
    const entry = this.map.get(key);
    if (!entry) return null;
    if (entry.expiresAt <= now) {
      this.map.delete(key);
      return null;
    }
    this.touch(key, entry);
    return entry.value as T;
  }

  async set<T = unknown>(key: string, value: T, ttlMs: number): Promise<void> {
    this.assertAvailable();
    const now = this.clock();
    const safeTtl = Math.max(100, ttlMs);
    if (this.map.has(key)) {
      this.map.delete(key);
    } else {
      this.evictIfNeeded(now);
    }
    this.map.set(key, {
      value,
      expiresAt: now + safeTtl,
    });
  }

  async del(key: string): Promise<void> {
    this.assertAvailable();
    this.map.delete(key);
  }

  async incr(key: string, ttlMs: number, delta = 1): Promise<number> {
    this.assertAvailable();
    const now = this.clock();
    const existing = this.map.get(key);
    if (!existing || existing.expiresAt <= now) {
      if (existing) this.map.delete(key);
      else this.evictIfNeeded(now);
      const val = delta;
      this.map.set(key, {
        value: val,
        expiresAt: now + Math.max(100, ttlMs),
      });
      return val;
    }

    const nextVal = Number(existing.value || 0) + delta;
    this.touch(key, {
      value: nextVal,
      expiresAt: existing.expiresAt,
    });
    return nextVal;
  }

  async atomicConsume(req: ConsumeLimitRequest): Promise<RateLimitResult> {
    this.assertAvailable();
    const clock = req.clock ?? this.clock;
    const now = clock();

    if (req.algorithm === 'token_bucket') {
      const existing = this.map.get(req.key);
      const prev =
        existing && existing.expiresAt > now ? (existing.value as TokenBucketState) : null;
      const { nextState, result } = evaluateTokenBucket(prev, {
        capacity: req.burst || req.limit,
        refillPerSec: req.refillPerSec,
        cost: req.cost,
        clock,
      });

      const ttlMs = Math.max(
        60_000,
        Math.ceil(((req.burst || req.limit) / Math.max(0.01, req.refillPerSec)) * 1000) * 2
      );
      if (this.map.has(req.key)) {
        this.map.delete(req.key);
      } else {
        this.evictIfNeeded(now);
      }
      this.map.set(req.key, {
        value: nextState,
        expiresAt: now + ttlMs,
      });
      return { ...result, keyHit: req.key };
    }

    const existing = this.map.get(req.key);
    const prev =
      existing && existing.expiresAt > now ? (existing.value as SlidingWindowState) : null;
    const { nextState, result } = evaluateSlidingWindow(prev, {
      limit: req.limit,
      windowMs: req.windowMs,
      cost: req.cost,
      clock,
    });

    if (this.map.has(req.key)) {
      this.map.delete(req.key);
    } else {
      this.evictIfNeeded(now);
    }
    this.map.set(req.key, {
      value: nextState,
      expiresAt: now + Math.max(req.windowMs, 1000),
    });
    return { ...result, keyHit: req.key };
  }

  getStats(): StoreStats {
    return {
      mode: this.mode,
      trackedKeys: this.map.size,
      maxKeys: this.maxKeys,
      evictions: this.evictionCount,
    };
  }

  destroy(): void {
    if (this.cleanupTimer) {
      clearInterval(this.cleanupTimer);
      this.cleanupTimer = null;
    }
    this.map.clear();
  }
}
