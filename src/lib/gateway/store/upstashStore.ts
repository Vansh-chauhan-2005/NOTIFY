import { evaluateSlidingWindow, type SlidingWindowState } from '../limiters/slidingWindow.js';
import { evaluateTokenBucket, type TokenBucketState } from '../limiters/tokenBucket.js';
import type { RateLimitResult } from '../types.js';
import {
  GatewayStoreUnavailableError,
  type ConsumeLimitRequest,
  type GatewayStoreAdapter,
  type StoreStats,
} from './types.js';

/**
 * Optional Upstash Redis REST adapter (free-tier compatible) for sharing rate-limit
 * counters across multiple Node/Express instances.
 */
export class UpstashRedisGatewayStore implements GatewayStoreAdapter {
  readonly mode = 'upstash-redis' as const;
  private readonly baseUrl: string;
  private readonly token: string;
  private approxKeys = 0;

  constructor(baseUrl: string, token: string) {
    this.baseUrl = baseUrl
      .trim()
      .replace(/^["']+|["']+$/g, '')
      .replace(/\/+$/, '');
    this.token = token.trim().replace(/^["']+|["']+$/g, '');
  }

  private async runCommand<T = unknown>(command: Array<string | number>): Promise<T> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 2500);
    try {
      const res = await fetch(`${this.baseUrl}`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${this.token}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(command),
        signal: controller.signal,
      });

      if (!res.ok) {
        throw new GatewayStoreUnavailableError(`Upstash REST returned HTTP ${res.status}`);
      }

      const json = (await res.json()) as { result?: T; error?: string };
      if (json.error) {
        throw new GatewayStoreUnavailableError(`Upstash Redis error: ${json.error}`);
      }
      return json.result as T;
    } catch (err: any) {
      if (err instanceof GatewayStoreUnavailableError) throw err;
      throw new GatewayStoreUnavailableError(err?.message || 'Upstash REST request failed');
    } finally {
      clearTimeout(timer);
    }
  }

  async get<T = unknown>(key: string): Promise<T | null> {
    const raw = await this.runCommand<string | null>(['GET', `aegis:gw:${key}`]);
    if (raw === null || raw === undefined) return null;
    try {
      return JSON.parse(raw) as T;
    } catch {
      return raw as unknown as T;
    }
  }

  async set<T = unknown>(key: string, value: T, ttlMs: number): Promise<void> {
    const payload = JSON.stringify(value);
    const safeTtl = Math.max(100, Math.floor(ttlMs));
    await this.runCommand(['SET', `aegis:gw:${key}`, payload, 'PX', safeTtl]);
    this.approxKeys += 1;
  }

  async del(key: string): Promise<void> {
    await this.runCommand(['DEL', `aegis:gw:${key}`]);
  }

  async incr(key: string, ttlMs: number, delta = 1): Promise<number> {
    const fullKey = `aegis:gw:${key}`;
    const res = await this.runCommand<number>(['INCRBY', fullKey, delta]);
    if (res === delta) {
      await this.runCommand(['PEXPIRE', fullKey, Math.max(100, Math.floor(ttlMs))]);
      this.approxKeys += 1;
    }
    return Number(res || 0);
  }

  async atomicConsume(req: ConsumeLimitRequest): Promise<RateLimitResult> {
    const clock = req.clock ?? Date.now;
    const prev = await this.get<TokenBucketState | SlidingWindowState>(req.key);

    if (req.algorithm === 'token_bucket') {
      const { nextState, result } = evaluateTokenBucket(prev as TokenBucketState | null, {
        capacity: req.burst || req.limit,
        refillPerSec: req.refillPerSec,
        cost: req.cost,
        clock,
      });
      const ttlMs = Math.max(
        60_000,
        Math.ceil(((req.burst || req.limit) / Math.max(0.01, req.refillPerSec)) * 1000) * 2
      );
      await this.set(req.key, nextState, ttlMs);
      return { ...result, keyHit: req.key };
    }

    const { nextState, result } = evaluateSlidingWindow(prev as SlidingWindowState | null, {
      limit: req.limit,
      windowMs: req.windowMs,
      cost: req.cost,
      clock,
    });
    await this.set(req.key, nextState, Math.max(req.windowMs, 1000));
    return { ...result, keyHit: req.key };
  }

  getStats(): StoreStats {
    return {
      mode: this.mode,
      trackedKeys: this.approxKeys,
      maxKeys: 100_000,
      evictions: 0,
    };
  }
}
