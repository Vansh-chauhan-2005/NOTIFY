import type { DeliveryChannel } from './stateMachine.js';

export type DeliveryPriority = 'CRITICAL' | 'HIGH' | 'NORMAL' | 'LOW';

export interface DeliveryPolicyConfig {
  priority: DeliveryPriority;
  channels: DeliveryChannel[];
  ackTimeoutMs: number;
  maxRetriesPerChannel: number;
  baseBackoffMs: number;
  jitterRatio: number;
  requiresAck: boolean;
  canBypassQuietHoursIfAllowed: boolean;
  digestOnly: boolean;
  ttlMs: number;
  description: string;
}

export interface DeliveryUserPreferences {
  dndEnabled?: boolean;
  quietHoursStart?: string;
  quietHoursEnd?: string;
  allowCriticalBypassQuietHours?: boolean;
  optOutPush?: boolean;
  optOutSms?: boolean;
  optOutEmail?: boolean;
}

export interface EffectiveDeliveryPlan {
  priority: DeliveryPriority;
  policy: DeliveryPolicyConfig;
  channels: DeliveryChannel[];
  skippedReasons: string[];
  quietHoursActive: boolean;
  quietHoursBypassed: boolean;
  requiresAck: boolean;
  ackTimeoutMs: number;
  maxRetriesPerChannel: number;
}

/**
 * Editable Delivery Policies by Priority.
 * - CRITICAL: push -> sms -> email, 30s ack timeout, 2 retries/channel, 2s/4s backoff + jitter
 * - HIGH: push -> email, 2 min ack timeout, 1 retry/channel
 * - NORMAL: push only, then in-app inbox, no ack required
 * - LOW: in-app inbox only (batched into digest)
 */
export const DELIVERY_POLICIES: Record<DeliveryPriority, DeliveryPolicyConfig> = {
  CRITICAL: {
    priority: 'CRITICAL',
    channels: ['push', 'sms', 'email'],
    ackTimeoutMs: 30_000,
    maxRetriesPerChannel: 2,
    baseBackoffMs: 2_000,
    jitterRatio: 0.25,
    requiresAck: true,
    canBypassQuietHoursIfAllowed: true,
    digestOnly: false,
    ttlMs: 30 * 60_000,
    description: 'Push → SMS → Email · 30s ACK timeout · 2 retries/channel · 2s/4s backoff',
  },
  HIGH: {
    priority: 'HIGH',
    channels: ['push', 'email'],
    ackTimeoutMs: 120_000,
    maxRetriesPerChannel: 1,
    baseBackoffMs: 2_000,
    jitterRatio: 0.25,
    requiresAck: true,
    canBypassQuietHoursIfAllowed: false,
    digestOnly: false,
    ttlMs: 60 * 60_000,
    description: 'Push → Email · 2 min ACK timeout · 1 retry/channel',
  },
  NORMAL: {
    priority: 'NORMAL',
    channels: ['push', 'in_app'],
    ackTimeoutMs: 0,
    maxRetriesPerChannel: 0,
    baseBackoffMs: 2_000,
    jitterRatio: 0.2,
    requiresAck: false,
    canBypassQuietHoursIfAllowed: false,
    digestOnly: false,
    ttlMs: 24 * 60 * 60_000,
    description: 'Push → In-app inbox · No ACK required',
  },
  LOW: {
    priority: 'LOW',
    channels: ['in_app'],
    ackTimeoutMs: 0,
    maxRetriesPerChannel: 0,
    baseBackoffMs: 0,
    jitterRatio: 0,
    requiresAck: false,
    canBypassQuietHoursIfAllowed: false,
    digestOnly: true,
    ttlMs: 7 * 24 * 60 * 60_000,
    description: 'In-app digest only · Quiet delivery',
  },
};

export function normalizePriority(raw?: string | null): DeliveryPriority {
  const upper = String(raw || '').trim().toUpperCase();
  if (upper === 'CRITICAL') return 'CRITICAL';
  if (upper === 'HIGH') return 'HIGH';
  if (upper === 'LOW') return 'LOW';
  // Map MEDIUM or unknown cleanly to NORMAL policy
  return 'NORMAL';
}

export function getPolicyForPriority(rawPriority?: string | null): DeliveryPolicyConfig {
  const normalized = normalizePriority(rawPriority);
  return DELIVERY_POLICIES[normalized];
}

/**
 * Exponential backoff with bounded positive jitter.
 * retryAttemptIndex: 0 -> ~2000ms..2500ms; 1 -> ~4000ms..5000ms.
 */
export function calculateBackoffMs(
  retryAttemptIndex: number,
  baseBackoffMs = 2_000,
  jitterRatio = 0.25,
  rng: () => number = Math.random
): number {
  if (baseBackoffMs <= 0) return 0;
  const safeIdx = Math.max(0, Math.min(8, Math.floor(retryAttemptIndex)));
  const expMs = baseBackoffMs * Math.pow(2, safeIdx);
  const clampedRng = Math.min(1, Math.max(0, rng()));
  const jitterMs = Math.round(expMs * Math.max(0, jitterRatio) * clampedRng);
  return Math.round(expMs + jitterMs);
}

function parseMinutes(hhmm?: string): number | null {
  if (!hhmm || !/^([01]\d|2[0-3]):[0-5]\d$/.test(hhmm)) return null;
  const [hh, mm] = hhmm.split(':').map(Number);
  return hh * 60 + mm;
}

export function isWithinQuietHours(
  prefs?: DeliveryUserPreferences | null,
  now: Date = new Date()
): boolean {
  if (!prefs?.dndEnabled) return false;
  const startMin = parseMinutes(prefs.quietHoursStart);
  const endMin = parseMinutes(prefs.quietHoursEnd);
  if (startMin === null || endMin === null) return false;

  const currentMin = now.getHours() * 60 + now.getMinutes();
  if (startMin === endMin) {
    return true;
  }
  if (startMin < endMin) {
    return currentMin >= startMin && currentMin < endMin;
  }
  // Overnight quiet hours (e.g. 22:00 -> 07:00)
  return currentMin >= startMin || currentMin < endMin;
}

export function resolveEffectiveDeliveryPlan(
  rawPriority?: string | null,
  prefs?: DeliveryUserPreferences | null,
  options?: { now?: Date; demoShortTimeouts?: boolean }
): EffectiveDeliveryPlan {
  const priority = normalizePriority(rawPriority);
  const policy = getPolicyForPriority(priority);
  const skippedReasons: string[] = [];

  const quietHoursActive = isWithinQuietHours(prefs, options?.now);
  const quietHoursBypassed =
    quietHoursActive &&
    policy.canBypassQuietHoursIfAllowed &&
    Boolean(prefs?.allowCriticalBypassQuietHours);

  let channels = [...policy.channels];

  // Respect per-channel opt-outs from Settings
  channels = channels.filter((ch) => {
    if (ch === 'push' && prefs?.optOutPush) {
      skippedReasons.push('Push skipped (opted out in Settings)');
      return false;
    }
    if (ch === 'sms' && prefs?.optOutSms) {
      skippedReasons.push('SMS skipped (opted out in Settings)');
      return false;
    }
    if (ch === 'email' && prefs?.optOutEmail) {
      skippedReasons.push('Email skipped (opted out in Settings)');
      return false;
    }
    return true;
  });

  // Respect quiet hours unless CRITICAL bypass is explicitly allowed by user
  if (quietHoursActive && !quietHoursBypassed) {
    const before = [...channels];
    channels = channels.filter((ch) => ch === 'in_app');
    const suppressed = before.filter((ch) => ch !== 'in_app');
    if (suppressed.length > 0) {
      skippedReasons.push(
        `Quiet hours active (${prefs?.quietHoursStart || '22:00'}–${prefs?.quietHoursEnd || '07:00'}): ${suppressed.join(', ')} suppressed → in-app inbox`
      );
    }
    if (!channels.includes('in_app')) {
      channels.push('in_app');
    }
  } else if (quietHoursBypassed) {
    skippedReasons.push('Quiet hours bypassed (CRITICAL override permitted by user)');
  }

  // Fallback to in_app if all channels were opted out on NORMAL/LOW
  if (channels.length === 0 && !policy.requiresAck) {
    channels = ['in_app'];
    skippedReasons.push('All push channels opted out → queued in-app inbox');
  }

  const ackTimeoutMs =
    options?.demoShortTimeouts && policy.requiresAck
      ? 1_500
      : policy.ackTimeoutMs;

  const isInAppOnly = channels.length === 1 && channels[0] === 'in_app';

  return {
    priority,
    policy,
    channels,
    skippedReasons,
    quietHoursActive,
    quietHoursBypassed,
    requiresAck: isInAppOnly ? false : policy.requiresAck,
    ackTimeoutMs,
    maxRetriesPerChannel: policy.maxRetriesPerChannel,
  };
}

export function formatChannelPlanLabel(channels: DeliveryChannel[]): string {
  const labels: Record<DeliveryChannel, string> = {
    push: 'Push',
    sms: 'SMS',
    email: 'Email',
    in_app: 'In-App Inbox',
    none: 'None',
  };
  if (channels.length === 0) return 'No enabled channels';
  return channels.map((c) => labels[c] || c).join(' → ');
}
