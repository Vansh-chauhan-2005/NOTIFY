import { MemoryLruGatewayStore } from './memoryStore.js';
import { UpstashRedisGatewayStore } from './upstashStore.js';
import type { GatewayStoreAdapter } from './types.js';

declare global {
  var __aegisGatewayStoreInstance: GatewayStoreAdapter | undefined;
}

function sanitizeEnvSecret(val?: string): string {
  return String(val || '')
    .trim()
    .replace(/^["']+|["']+$/g, '')
    .trim();
}

export function createGatewayStore(): GatewayStoreAdapter {
  const upstashUrl = sanitizeEnvSecret(process.env.UPSTASH_REDIS_REST_URL);
  const upstashToken = sanitizeEnvSecret(process.env.UPSTASH_REDIS_REST_TOKEN);

  if (upstashUrl && upstashToken) {
    try {
      const parsed = new URL(upstashUrl);
      if (parsed.protocol === 'https:' || parsed.protocol === 'http:') {
        return new UpstashRedisGatewayStore(upstashUrl, upstashToken);
      }
    } catch {
      console.warn('[Gateway] Invalid UPSTASH_REDIS_REST_URL format; falling back to in-memory LRU store.');
    }
  }

  return new MemoryLruGatewayStore({
    maxKeys: 50_000,
    cleanupIntervalMs: 60_000,
  });
}

export function getGatewayStore(): GatewayStoreAdapter {
  if (!global.__aegisGatewayStoreInstance) {
    global.__aegisGatewayStoreInstance = createGatewayStore();
  }
  return global.__aegisGatewayStoreInstance;
}

export { MemoryLruGatewayStore } from './memoryStore.js';
export { UpstashRedisGatewayStore } from './upstashStore.js';
export {
  GatewayStoreUnavailableError,
  runWithFailureMode,
  type ConsumeLimitRequest,
  type GatewayStoreAdapter,
  type StoreStats,
} from './types.js';
