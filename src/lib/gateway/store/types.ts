import type { ClockFn, FailureMode, RateLimitResult } from '../types.js';

export interface StoreStats {
  mode: 'memory' | 'upstash-redis';
  trackedKeys: number;
  maxKeys: number;
  evictions: number;
}

export interface ConsumeLimitRequest {
  key: string;
  algorithm: 'token_bucket' | 'sliding_window';
  limit: number;
  windowMs: number;
  burst: number;
  refillPerSec: number;
  cost: number;
  clock?: ClockFn;
}

export interface GatewayStoreAdapter {
  readonly mode: 'memory' | 'upstash-redis';
  get<T = unknown>(key: string): Promise<T | null>;
  set<T = unknown>(key: string, value: T, ttlMs: number): Promise<void>;
  del(key: string): Promise<void>;
  incr(key: string, ttlMs: number, delta?: number): Promise<number>;
  atomicConsume(req: ConsumeLimitRequest): Promise<RateLimitResult>;
  getStats(): StoreStats;
  cleanupExpired?(): number;
}

export class GatewayStoreUnavailableError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'GatewayStoreUnavailableError';
  }
}

export async function runWithFailureMode<T>(params: {
  failureMode: FailureMode;
  action: () => Promise<T>;
  onStoreError: (err: Error) => void;
  fallbackOpenValue: T;
}): Promise<{ ok: boolean; value?: T; failClosed: boolean; error?: string }> {
  try {
    const value = await params.action();
    return { ok: true, value, failClosed: false };
  } catch (err: any) {
    const errorObj = err instanceof Error ? err : new Error(String(err || 'Limiter store unavailable'));
    params.onStoreError(errorObj);
    if (params.failureMode === 'FAIL_CLOSED') {
      return {
        ok: false,
        failClosed: true,
        error: errorObj.message,
      };
    }
    return {
      ok: true,
      value: params.fallbackOpenValue,
      failClosed: false,
      error: errorObj.message,
    };
  }
}
