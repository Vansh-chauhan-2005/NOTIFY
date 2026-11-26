import { logSecurityEvent } from '../telemetry/securityLogger.js';

export type BreakerChannel = 'push' | 'whatsapp' | 'sms' | 'email';
export type CircuitState = 'CLOSED' | 'OPEN' | 'HALF_OPEN';

export interface ChannelBreakerStatus {
  channel: BreakerChannel;
  state: CircuitState;
  consecutiveFailures: number;
  openedUntil: number | null;
  lastError?: string;
  lastChangedAt: string;
}

const FAILURE_THRESHOLD = 3;
const OPEN_COOLDOWN_MS = 60_000; // 60 seconds

declare global {
  var __aegisDeliveryBreakersLive: Map<BreakerChannel, ChannelBreakerStatus> | undefined;
  var __aegisDeliveryBreakersSim: Map<BreakerChannel, ChannelBreakerStatus> | undefined;
}

function getBreakerMap(namespace: 'live' | 'sim' = 'live'): Map<BreakerChannel, ChannelBreakerStatus> {
  if (namespace === 'sim') {
    if (!global.__aegisDeliveryBreakersSim) {
      global.__aegisDeliveryBreakersSim = createInitialMap();
    }
    return global.__aegisDeliveryBreakersSim;
  }
  if (!global.__aegisDeliveryBreakersLive) {
    global.__aegisDeliveryBreakersLive = createInitialMap();
  }
  return global.__aegisDeliveryBreakersLive;
}

function createInitialMap(): Map<BreakerChannel, ChannelBreakerStatus> {
  const map = new Map<BreakerChannel, ChannelBreakerStatus>();
  const nowIso = new Date().toISOString();
  for (const ch of ['push', 'whatsapp', 'sms', 'email'] as BreakerChannel[]) {
    map.set(ch, {
      channel: ch,
      state: 'CLOSED',
      consecutiveFailures: 0,
      openedUntil: null,
      lastChangedAt: nowIso,
    });
  }
  return map;
}

export function canAttemptChannel(
  channel: BreakerChannel,
  namespace: 'live' | 'sim' = 'live',
  now: number = Date.now()
): { allowed: boolean; state: CircuitState; remainingMs: number } {
  const map = getBreakerMap(namespace);
  const entry = map.get(channel)!;

  if (entry.state === 'OPEN') {
    if (entry.openedUntil && now < entry.openedUntil) {
      return {
        allowed: false,
        state: 'OPEN',
        remainingMs: entry.openedUntil - now,
      };
    }
    // Cooldown expired -> transition OPEN -> HALF_OPEN to test once
    entry.state = 'HALF_OPEN';
    entry.lastChangedAt = new Date(now).toISOString();
    return { allowed: true, state: 'HALF_OPEN', remainingMs: 0 };
  }

  return { allowed: true, state: entry.state, remainingMs: 0 };
}

export function recordChannelSuccess(
  channel: BreakerChannel,
  namespace: 'live' | 'sim' = 'live',
  now: number = Date.now()
): ChannelBreakerStatus {
  const map = getBreakerMap(namespace);
  const entry = map.get(channel)!;
  entry.state = 'CLOSED';
  entry.consecutiveFailures = 0;
  entry.openedUntil = null;
  entry.lastError = undefined;
  entry.lastChangedAt = new Date(now).toISOString();
  return { ...entry };
}

export function recordChannelFailure(
  channel: BreakerChannel,
  errorReason: string,
  namespace: 'live' | 'sim' = 'live',
  now: number = Date.now()
): { status: ChannelBreakerStatus; trippedOpen: boolean } {
  const map = getBreakerMap(namespace);
  const entry = map.get(channel)!;
  entry.consecutiveFailures += 1;
  entry.lastError = errorReason.slice(0, 160);
  entry.lastChangedAt = new Date(now).toISOString();

  let trippedOpen = false;
  if (entry.state === 'HALF_OPEN' || entry.consecutiveFailures >= FAILURE_THRESHOLD) {
    trippedOpen = entry.state !== 'OPEN';
    entry.state = 'OPEN';
    entry.openedUntil = now + OPEN_COOLDOWN_MS;
    if (trippedOpen) {
      logSecurityEvent({
        eventType: 'CHANNEL_CIRCUIT_OPEN',
        severity: 'warning',
        result: 'blocked',
        details: `Channel circuit breaker OPENED for ${channel} after ${entry.consecutiveFailures} consecutive failure(s) (${namespace} mode).`,
      });
    }
  }

  return { status: { ...entry }, trippedOpen };
}

export function getAllBreakerStatuses(
  namespace: 'live' | 'sim' = 'live',
  now: number = Date.now()
): ChannelBreakerStatus[] {
  const map = getBreakerMap(namespace);
  return (['push', 'whatsapp', 'sms', 'email'] as BreakerChannel[]).map((ch) => {
    const entry = map.get(ch)!;
    if (entry.state === 'OPEN' && entry.openedUntil && now >= entry.openedUntil) {
      entry.state = 'HALF_OPEN';
      entry.lastChangedAt = new Date(now).toISOString();
    }
    return { ...entry };
  });
}

export function resetBreaker(
  channel?: BreakerChannel,
  namespace: 'live' | 'sim' = 'live'
): void {
  const map = getBreakerMap(namespace);
  const targets = channel ? [channel] : (['push', 'whatsapp', 'sms', 'email'] as BreakerChannel[]);
  const nowIso = new Date().toISOString();
  for (const ch of targets) {
    map.set(ch, {
      channel: ch,
      state: 'CLOSED',
      consecutiveFailures: 0,
      openedUntil: null,
      lastChangedAt: nowIso,
    });
  }
}
