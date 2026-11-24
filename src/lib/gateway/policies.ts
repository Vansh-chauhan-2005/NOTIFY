import type { PolicyValidationBounds, RouteGroup, RoutePolicy } from './types.js';

export const POLICY_VALIDATION_BOUNDS: PolicyValidationBounds = {
  minCost: 1,
  maxCost: 50,
  minLimit: 3,
  maxLimit: 2000,
  minWindowMs: 5_000,
  maxWindowMs: 86_400_000,
  minBurst: 1,
  maxBurst: 500,
  minBodyBytes: 1_024,
  maxBodyBytes: 524_288,
  minTimeoutMs: 1_000,
  maxTimeoutMs: 60_000,
};

/**
 * Editable default route policies & cost table.
 * Auth routes default to STRICT + FAIL_CLOSED; static/health fail OPEN.
 */
export const DEFAULT_ROUTE_POLICIES: Record<RouteGroup, RoutePolicy> = {
  auth: {
    group: 'auth',
    description: 'Login, Email/SMS OTP send & verify, delivery ACK links',
    cost: 5,
    algorithm: 'sliding_window',
    limit: 5,
    windowMs: 60_000,
    burst: 5,
    refillPerSec: 0.1,
    maxBodyBytes: 16 * 1024,
    allowedMethods: ['GET', 'POST', 'OPTIONS'],
    allowedContentTypes: ['application/json'],
    failureMode: 'FAIL_CLOSED',
    concurrencyPerUser: 8,
    concurrencyPerRoute: 120,
    requestTimeoutMs: 15_000,
    maxUrlLength: 2048,
    maxJsonDepth: 6,
    maxJsonKeys: 64,
    maxJsonArrayLength: 32,
    shedAtLevel: 'NEVER',
    isCriticalAuthOrAck: true,
    secondaryHourlyLimit: 20,
    secondaryIpHourlyLimit: 10,
  },
  ingest: {
    group: 'ingest',
    description: 'App connection webhooks (/api/v1/ingest/:id) & ingest endpoints',
    cost: 2,
    algorithm: 'sliding_window',
    limit: 60,
    windowMs: 60_000,
    burst: 60,
    refillPerSec: 1,
    maxBodyBytes: 64 * 1024,
    allowedMethods: ['POST', 'OPTIONS'],
    allowedContentTypes: ['application/json'],
    failureMode: 'FAIL_CLOSED',
    concurrencyPerUser: 15,
    concurrencyPerRoute: 150,
    requestTimeoutMs: 12_000,
    maxUrlLength: 2048,
    maxJsonDepth: 10,
    maxJsonKeys: 500,
    maxJsonArrayLength: 200,
    shedAtLevel: 'CRITICAL',
  },
  messaging: {
    group: 'messaging',
    description: 'Notifications, encrypted messaging, delivery jobs, user settings',
    cost: 3,
    algorithm: 'token_bucket',
    limit: 120,
    windowMs: 60_000,
    burst: 30,
    refillPerSec: 2,
    maxBodyBytes: 100 * 1024,
    allowedMethods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
    allowedContentTypes: ['application/json'],
    failureMode: 'FAIL_OPEN',
    concurrencyPerUser: 20,
    concurrencyPerRoute: 200,
    requestTimeoutMs: 15_000,
    maxUrlLength: 2048,
    maxJsonDepth: 10,
    maxJsonKeys: 1000,
    maxJsonArrayLength: 500,
    shedAtLevel: 'NEVER',
  },
  ephemeral: {
    group: 'ephemeral',
    description: 'Ephemeral 300s TTL isolated messages & keys',
    cost: 2,
    algorithm: 'token_bucket',
    limit: 90,
    windowMs: 60_000,
    burst: 25,
    refillPerSec: 1.5,
    maxBodyBytes: 100 * 1024,
    allowedMethods: ['GET', 'POST', 'OPTIONS'],
    allowedContentTypes: ['application/json'],
    failureMode: 'FAIL_OPEN',
    concurrencyPerUser: 12,
    concurrencyPerRoute: 120,
    requestTimeoutMs: 12_000,
    maxUrlLength: 2048,
    maxJsonDepth: 8,
    maxJsonKeys: 300,
    maxJsonArrayLength: 100,
    shedAtLevel: 'CRITICAL',
  },
  provenance: {
    group: 'provenance',
    description: 'Zero-Trust Ed25519 provenance keys, key log, and verification',
    cost: 2,
    algorithm: 'token_bucket',
    limit: 90,
    windowMs: 60_000,
    burst: 25,
    refillPerSec: 1.5,
    maxBodyBytes: 100 * 1024,
    allowedMethods: ['GET', 'POST', 'OPTIONS'],
    allowedContentTypes: ['application/json'],
    failureMode: 'FAIL_OPEN',
    concurrencyPerUser: 12,
    concurrencyPerRoute: 120,
    requestTimeoutMs: 12_000,
    maxUrlLength: 2048,
    maxJsonDepth: 10,
    maxJsonKeys: 400,
    maxJsonArrayLength: 200,
    shedAtLevel: 'CRITICAL',
  },
  dedup: {
    group: 'dedup',
    description: 'Semantic deduplication metadata threads, config, and feedback',
    cost: 1,
    algorithm: 'token_bucket',
    limit: 120,
    windowMs: 60_000,
    burst: 30,
    refillPerSec: 2,
    maxBodyBytes: 64 * 1024,
    allowedMethods: ['GET', 'POST', 'PUT', 'OPTIONS'],
    allowedContentTypes: ['application/json'],
    failureMode: 'FAIL_OPEN',
    concurrencyPerUser: 15,
    concurrencyPerRoute: 150,
    requestTimeoutMs: 12_000,
    maxUrlLength: 2048,
    maxJsonDepth: 10,
    maxJsonKeys: 400,
    maxJsonArrayLength: 200,
    shedAtLevel: 'HIGH',
  },
  priority: {
    group: 'priority',
    description: 'Dynamic sigmoid priority scoring, weights, and user feedback',
    cost: 1,
    algorithm: 'token_bucket',
    limit: 120,
    windowMs: 60_000,
    burst: 30,
    refillPerSec: 2,
    maxBodyBytes: 64 * 1024,
    allowedMethods: ['GET', 'POST', 'PUT', 'OPTIONS'],
    allowedContentTypes: ['application/json'],
    failureMode: 'FAIL_OPEN',
    concurrencyPerUser: 15,
    concurrencyPerRoute: 150,
    requestTimeoutMs: 12_000,
    maxUrlLength: 2048,
    maxJsonDepth: 10,
    maxJsonKeys: 400,
    maxJsonArrayLength: 200,
    shedAtLevel: 'HIGH',
  },
  admin: {
    group: 'admin',
    description: 'Gateway & platform admin control routes',
    cost: 5,
    algorithm: 'token_bucket',
    limit: 60,
    windowMs: 60_000,
    burst: 20,
    refillPerSec: 1,
    maxBodyBytes: 64 * 1024,
    allowedMethods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedContentTypes: ['application/json'],
    failureMode: 'FAIL_OPEN',
    concurrencyPerUser: 10,
    concurrencyPerRoute: 40,
    requestTimeoutMs: 15_000,
    maxUrlLength: 2048,
    maxJsonDepth: 10,
    maxJsonKeys: 300,
    maxJsonArrayLength: 100,
    shedAtLevel: 'NEVER',
  },
  telemetry: {
    group: 'telemetry',
    description: 'Security telemetry events, stats & analytics listings (shed under HIGH load)',
    cost: 10,
    algorithm: 'token_bucket',
    limit: 60,
    windowMs: 60_000,
    burst: 20,
    refillPerSec: 1,
    maxBodyBytes: 64 * 1024,
    allowedMethods: ['GET', 'POST', 'OPTIONS'],
    allowedContentTypes: ['application/json'],
    failureMode: 'FAIL_OPEN',
    concurrencyPerUser: 8,
    concurrencyPerRoute: 40,
    requestTimeoutMs: 12_000,
    maxUrlLength: 2048,
    maxJsonDepth: 8,
    maxJsonKeys: 200,
    maxJsonArrayLength: 100,
    shedAtLevel: 'HIGH',
  },
  simulator: {
    group: 'simulator',
    description: 'Admin-only attack & verification simulators (Demo Mode)',
    cost: 10,
    algorithm: 'sliding_window',
    limit: 20,
    windowMs: 60_000,
    burst: 20,
    refillPerSec: 0.33,
    maxBodyBytes: 32 * 1024,
    allowedMethods: ['POST', 'OPTIONS'],
    allowedContentTypes: ['application/json'],
    failureMode: 'FAIL_OPEN',
    concurrencyPerUser: 3,
    concurrencyPerRoute: 10,
    requestTimeoutMs: 20_000,
    maxUrlLength: 2048,
    maxJsonDepth: 8,
    maxJsonKeys: 200,
    maxJsonArrayLength: 100,
    shedAtLevel: 'HIGH',
  },
  health: {
    group: 'health',
    description: 'Lightweight health & gateway readiness endpoints (generous, fail OPEN)',
    cost: 1,
    algorithm: 'token_bucket',
    limit: 300,
    windowMs: 60_000,
    burst: 60,
    refillPerSec: 5,
    maxBodyBytes: 4 * 1024,
    allowedMethods: ['GET', 'HEAD', 'OPTIONS'],
    allowedContentTypes: ['application/json'],
    failureMode: 'FAIL_OPEN',
    concurrencyPerUser: 30,
    concurrencyPerRoute: 300,
    requestTimeoutMs: 5_000,
    maxUrlLength: 1024,
    maxJsonDepth: 4,
    maxJsonKeys: 32,
    maxJsonArrayLength: 16,
    shedAtLevel: 'NEVER',
    isCriticalAuthOrAck: true,
  },
  static: {
    group: 'static',
    description: 'Static web assets, SPA shell & Vite dev modules (generous, fail OPEN)',
    cost: 1,
    algorithm: 'token_bucket',
    limit: 600,
    windowMs: 60_000,
    burst: 150,
    refillPerSec: 10,
    maxBodyBytes: 32 * 1024,
    allowedMethods: ['GET', 'HEAD', 'OPTIONS'],
    allowedContentTypes: ['application/json', 'text/plain'],
    failureMode: 'FAIL_OPEN',
    concurrencyPerUser: 60,
    concurrencyPerRoute: 500,
    requestTimeoutMs: 15_000,
    maxUrlLength: 4096,
    maxJsonDepth: 6,
    maxJsonKeys: 100,
    maxJsonArrayLength: 100,
    shedAtLevel: 'CRITICAL',
  },
  general: {
    group: 'general',
    description: 'General API endpoints (default 120/min per user, burst 30, 100 KB cap)',
    cost: 1,
    algorithm: 'token_bucket',
    limit: 120,
    windowMs: 60_000,
    burst: 30,
    refillPerSec: 2,
    maxBodyBytes: 100 * 1024,
    allowedMethods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
    allowedContentTypes: ['application/json'],
    failureMode: 'FAIL_OPEN',
    concurrencyPerUser: 20,
    concurrencyPerRoute: 200,
    requestTimeoutMs: 15_000,
    maxUrlLength: 2048,
    maxJsonDepth: 10,
    maxJsonKeys: 1000,
    maxJsonArrayLength: 500,
    shedAtLevel: 'CRITICAL',
  },
};

declare global {
  var __aegisGatewayPolicies: Record<RouteGroup, RoutePolicy> | undefined;
}

function clonePolicies(source: Record<RouteGroup, RoutePolicy>): Record<RouteGroup, RoutePolicy> {
  return JSON.parse(JSON.stringify(source)) as Record<RouteGroup, RoutePolicy>;
}

export function getRoutePolicies(): Record<RouteGroup, RoutePolicy> {
  if (!global.__aegisGatewayPolicies) {
    global.__aegisGatewayPolicies = clonePolicies(DEFAULT_ROUTE_POLICIES);
  }
  return global.__aegisGatewayPolicies;
}

export function getPolicyForGroup(group: RouteGroup): RoutePolicy {
  const policies = getRoutePolicies();
  return policies[group] || policies.general;
}

export interface RouteMatchResult {
  group: RouteGroup;
  costOverride?: number;
  isCriticalAuthOrAck: boolean;
  isSmsSend: boolean;
  isAckLink: boolean;
  isEncryptedSend: boolean;
  connectionId?: string;
}

/**
 * Classifies an incoming HTTP request path into its gateway route group & operation cost.
 */
export function classifyRequestRoute(method: string, rawPath: string): RouteMatchResult {
  const path = (rawPath.split('?')[0] || '/').trim() || '/';
  const lower = path.toLowerCase();
  const upperMethod = method.toUpperCase();

  // Health checks (skip heavy limits, still counted)
  if (lower === '/api/v1/gateway/health' || lower === '/api/v1/analytics/health') {
    return {
      group: 'health',
      costOverride: 1,
      isCriticalAuthOrAck: true,
      isSmsSend: false,
      isAckLink: false,
      isEncryptedSend: false,
    };
  }

  // Admin simulators (high cost, admin-only, shed under HIGH load)
  if (lower.endsWith('/simulate')) {
    return {
      group: 'simulator',
      costOverride: 10,
      isCriticalAuthOrAck: false,
      isSmsSend: false,
      isAckLink: false,
      isEncryptedSend: false,
    };
  }

  // Delivery ACK links & Notification ACK links (never shed before normal traffic)
  if (
    /^\/api\/v1\/delivery\/([^/]+\/)?ack$/.test(lower) ||
    lower.startsWith('/api/v1/notifications/ack/')
  ) {
    return {
      group: 'auth',
      costOverride: 1,
      isCriticalAuthOrAck: true,
      isSmsSend: false,
      isAckLink: true,
      isEncryptedSend: false,
    };
  }

  // Authenticated key backup vault & session audit management (rate-limited at 120/min so normal UX never trips 5/min brute-force lock)
  if (lower.startsWith('/api/v1/auth/keys-backup') || lower.startsWith('/api/v1/auth/sessions')) {
    return {
      group: 'messaging',
      costOverride: 1,
      isCriticalAuthOrAck: false,
      isSmsSend: false,
      isAckLink: false,
      isEncryptedSend: false,
    };
  }

  // Auth routes (Login, Signup, Firebase session, Telemetry, Email OTP, SMS OTP)
  if (lower.startsWith('/auth/') || lower.startsWith('/api/v1/auth/')) {
    const isSmsSend = lower.endsWith('/sms/send');
    const isStatusOrMe = lower.endsWith('/sms/status') || lower.endsWith('/me') || (lower.endsWith('/otp/send') && upperMethod === 'GET');
    return {
      group: 'auth',
      costOverride: isSmsSend ? 20 : isStatusOrMe ? 1 : 5,
      isCriticalAuthOrAck: true,
      isSmsSend,
      isAckLink: false,
      isEncryptedSend: false,
    };
  }

  // Webhook & Connection Ingest
  const connMatch = path.match(/^\/api\/v1\/ingest\/([^/]+)$/);
  if (connMatch || lower === '/api/v1/integrations/webhook' || lower === '/api/v1/notifications/ingest') {
    return {
      group: 'ingest',
      costOverride: 2,
      isCriticalAuthOrAck: false,
      isSmsSend: false,
      isAckLink: false,
      isEncryptedSend: false,
      connectionId: connMatch?.[1],
    };
  }

  // Gateway Admin API
  if (lower.startsWith('/api/v1/gateway/')) {
    return {
      group: 'admin',
      costOverride: lower.endsWith('/stats') ? 10 : 5,
      isCriticalAuthOrAck: false,
      isSmsSend: false,
      isAckLink: false,
      isEncryptedSend: false,
    };
  }

  // Telemetry & Heavy Analytics Stats (low-value under overload -> shed first)
  if (
    lower.startsWith('/api/v1/telemetry/') ||
    lower === '/api/v1/analytics/metrics' ||
    lower.endsWith('/stats')
  ) {
    return {
      group: 'telemetry',
      costOverride: 10,
      isCriticalAuthOrAck: false,
      isSmsSend: false,
      isAckLink: false,
      isEncryptedSend: false,
    };
  }

  if (lower.startsWith('/api/v1/ephemeral')) {
    return {
      group: 'ephemeral',
      costOverride: upperMethod === 'POST' ? 3 : 1,
      isCriticalAuthOrAck: false,
      isSmsSend: false,
      isAckLink: false,
      isEncryptedSend: upperMethod === 'POST',
    };
  }

  if (lower.startsWith('/api/v1/provenance')) {
    return {
      group: 'provenance',
      costOverride: upperMethod === 'POST' ? 2 : 1,
      isCriticalAuthOrAck: false,
      isSmsSend: false,
      isAckLink: false,
      isEncryptedSend: false,
    };
  }

  if (lower.startsWith('/api/v1/dedup')) {
    return {
      group: 'dedup',
      costOverride: 1,
      isCriticalAuthOrAck: false,
      isSmsSend: false,
      isAckLink: false,
      isEncryptedSend: false,
    };
  }

  if (lower.startsWith('/api/v1/priority')) {
    return {
      group: 'priority',
      costOverride: 1,
      isCriticalAuthOrAck: false,
      isSmsSend: false,
      isAckLink: false,
      isEncryptedSend: false,
    };
  }

  if (
    lower.startsWith('/api/v1/notifications') ||
    lower.startsWith('/api/v1/delivery') ||
    lower.startsWith('/api/v1/connections') ||
    lower.startsWith('/api/v1/users')
  ) {
    const isEncryptedSend = upperMethod === 'POST' && (lower.includes('/fallback/') || lower.includes('/delivery/jobs'));
    return {
      group: 'messaging',
      costOverride: isEncryptedSend ? 3 : 1,
      isCriticalAuthOrAck: false,
      isSmsSend: false,
      isAckLink: false,
      isEncryptedSend,
    };
  }

  if (lower.startsWith('/api/')) {
    return {
      group: 'general',
      costOverride: 1,
      isCriticalAuthOrAck: false,
      isSmsSend: false,
      isAckLink: false,
      isEncryptedSend: false,
    };
  }

  // Non-API path: static SPA files / Vite dev modules
  return {
    group: 'static',
    costOverride: 1,
    isCriticalAuthOrAck: false,
    isSmsSend: false,
    isAckLink: false,
    isEncryptedSend: false,
  };
}

export function validateAndUpdateRoutePolicy(
  group: RouteGroup,
  patch: Partial<Pick<RoutePolicy, 'cost' | 'limit' | 'windowMs' | 'burst' | 'refillPerSec' | 'maxBodyBytes' | 'requestTimeoutMs' | 'failureMode'>>
): { ok: boolean; policy?: RoutePolicy; message: string } {
  const policies = getRoutePolicies();
  const current = policies[group];
  if (!current) {
    return { ok: false, message: `Unknown route group: ${group}` };
  }

  const next = { ...current };
  const b = POLICY_VALIDATION_BOUNDS;

  if (patch.cost !== undefined) {
    const val = Math.floor(Number(patch.cost));
    if (!Number.isFinite(val) || val < b.minCost || val > b.maxCost) {
      return { ok: false, message: `Cost must be between ${b.minCost} and ${b.maxCost}.` };
    }
    next.cost = val;
  }

  if (patch.limit !== undefined) {
    const val = Math.floor(Number(patch.limit));
    if (!Number.isFinite(val) || val < b.minLimit || val > b.maxLimit) {
      return { ok: false, message: `Limit must be between ${b.minLimit} and ${b.maxLimit}.` };
    }
    next.limit = val;
  }

  if (patch.windowMs !== undefined) {
    const val = Math.floor(Number(patch.windowMs));
    if (!Number.isFinite(val) || val < b.minWindowMs || val > b.maxWindowMs) {
      return {
        ok: false,
        message: `Window must be between ${b.minWindowMs / 1000}s and ${b.maxWindowMs / 1000}s.`,
      };
    }
    next.windowMs = val;
  }

  if (patch.burst !== undefined) {
    const val = Math.floor(Number(patch.burst));
    if (!Number.isFinite(val) || val < b.minBurst || val > b.maxBurst) {
      return { ok: false, message: `Burst must be between ${b.minBurst} and ${b.maxBurst}.` };
    }
    next.burst = val;
  }

  if (patch.refillPerSec !== undefined) {
    const val = Number(patch.refillPerSec);
    if (!Number.isFinite(val) || val < 0.01 || val > 200) {
      return { ok: false, message: 'Refill rate/sec must be between 0.01 and 200.' };
    }
    next.refillPerSec = Number(val.toFixed(2));
  }

  if (patch.maxBodyBytes !== undefined) {
    const val = Math.floor(Number(patch.maxBodyBytes));
    if (!Number.isFinite(val) || val < b.minBodyBytes || val > b.maxBodyBytes) {
      return {
        ok: false,
        message: `Max body size must be between ${b.minBodyBytes} and ${b.maxBodyBytes} bytes.`,
      };
    }
    next.maxBodyBytes = val;
  }

  if (patch.requestTimeoutMs !== undefined) {
    const val = Math.floor(Number(patch.requestTimeoutMs));
    if (!Number.isFinite(val) || val < b.minTimeoutMs || val > b.maxTimeoutMs) {
      return {
        ok: false,
        message: `Request timeout must be between ${b.minTimeoutMs}ms and ${b.maxTimeoutMs}ms.`,
      };
    }
    next.requestTimeoutMs = val;
  }

  if (patch.failureMode !== undefined) {
    if (patch.failureMode !== 'FAIL_CLOSED' && patch.failureMode !== 'FAIL_OPEN') {
      return { ok: false, message: 'failureMode must be FAIL_CLOSED or FAIL_OPEN.' };
    }
    // Safety guardrail: auth routes must always remain FAIL_CLOSED
    if (group === 'auth' && patch.failureMode !== 'FAIL_CLOSED') {
      return { ok: false, message: 'Auth routes must remain FAIL_CLOSED for security.' };
    }
    next.failureMode = patch.failureMode;
  }

  policies[group] = next;
  return { ok: true, policy: { ...next }, message: `Updated ${group} gateway policy.` };
}

export function resetAllRoutePolicies(): Record<RouteGroup, RoutePolicy> {
  global.__aegisGatewayPolicies = clonePolicies(DEFAULT_ROUTE_POLICIES);
  return getRoutePolicies();
}
