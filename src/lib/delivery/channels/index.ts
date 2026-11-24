import type { DeliveryChannel } from '../stateMachine.js';
import { pushChannelAdapter } from './pushAdapter.js';
import { smsChannelAdapter } from './smsAdapter.js';
import { emailChannelAdapter } from './emailAdapter.js';
import type { ChannelAdapter, ChannelSendResult, DeliveryJobRecord } from './types.js';

export type {
  ChannelAdapter,
  ChannelSendResult,
  DeliveryHistoryEntry,
  DeliveryJobRecord,
  DemoFaultConfig,
} from './types.js';

const inAppChannelAdapter: ChannelAdapter = {
  channel: 'in_app',
  async send(job: DeliveryJobRecord): Promise<ChannelSendResult> {
    return {
      ok: true,
      providerId: `inbox-${job.notificationId}`,
      retryable: false,
      detail: 'Recorded in user in-app inbox',
    };
  },
};

const ADAPTERS: Record<Exclude<DeliveryChannel, 'none'>, ChannelAdapter> = {
  push: pushChannelAdapter,
  sms: smsChannelAdapter,
  email: emailChannelAdapter,
  in_app: inAppChannelAdapter,
};

// Per-user hourly rate limiting per channel to prevent fallback spam
const CHANNEL_HOURLY_LIMITS: Record<Exclude<DeliveryChannel, 'none'>, number> = {
  push: 60,
  sms: 10,
  email: 20,
  in_app: 500,
};

const HOUR_MS = 60 * 60 * 1000;

declare global {
  var __aegisDeliveryUserRateLimits: Map<string, number[]> | undefined;
}

function getRateLimitMap(): Map<string, number[]> {
  if (!global.__aegisDeliveryUserRateLimits) {
    global.__aegisDeliveryUserRateLimits = new Map();
  }
  return global.__aegisDeliveryUserRateLimits;
}

export function checkAndRecordUserChannelLimit(
  userId: string,
  channel: Exclude<DeliveryChannel, 'none'>,
  now: number = Date.now()
): { allowed: boolean; remaining: number; limit: number } {
  const limit = CHANNEL_HOURLY_LIMITS[channel] ?? 30;
  const key = `${userId}:${channel}`;
  const map = getRateLimitMap();
  const cutoff = now - HOUR_MS;
  const timestamps = (map.get(key) || []).filter((ts) => ts > cutoff);

  if (timestamps.length >= limit) {
    map.set(key, timestamps);
    return { allowed: false, remaining: 0, limit };
  }

  timestamps.push(now);
  map.set(key, timestamps);
  return { allowed: true, remaining: Math.max(0, limit - timestamps.length), limit };
}

export function getChannelAdapter(channel: DeliveryChannel): ChannelAdapter | null {
  if (channel === 'none') return null;
  return ADAPTERS[channel] || null;
}
