export type ClockFn = () => number;

export type RouteGroup =
  | 'auth'
  | 'ingest'
  | 'messaging'
  | 'ephemeral'
  | 'provenance'
  | 'dedup'
  | 'priority'
  | 'admin'
  | 'telemetry'
  | 'simulator'
  | 'health'
  | 'static'
  | 'general';

export type LoadLevel = 'NORMAL' | 'ELEVATED' | 'HIGH' | 'CRITICAL';

export type FailureMode = 'FAIL_CLOSED' | 'FAIL_OPEN';

export type LimiterAlgorithm = 'token_bucket' | 'sliding_window';

export type ShedThresholdLevel = 'NEVER' | 'HIGH' | 'CRITICAL';

export interface RoutePolicy {
  group: RouteGroup;
  description: string;
  cost: number;
  algorithm: LimiterAlgorithm;
  /** Token bucket capacity or sliding window max requests */
  limit: number;
  /** Window duration in ms (for sliding_window) or reference window (for headers) */
  windowMs: number;
  /** Token bucket burst capacity (defaults to limit) */
  burst: number;
  /** Token bucket steady refill rate per second */
  refillPerSec: number;
  maxBodyBytes: number;
  allowedMethods: string[];
  allowedContentTypes: string[];
  failureMode: FailureMode;
  concurrencyPerUser: number;
  concurrencyPerRoute: number;
  requestTimeoutMs: number;
  maxUrlLength: number;
  maxJsonDepth: number;
  maxJsonKeys: number;
  maxJsonArrayLength: number;
  shedAtLevel: ShedThresholdLevel;
  isCriticalAuthOrAck?: boolean;
  /** Additional hourly cap per account/phone/email for auth routes */
  secondaryHourlyLimit?: number;
  /** Additional hourly cap per IP for SMS/auth routes */
  secondaryIpHourlyLimit?: number;
}

export interface PolicyValidationBounds {
  minCost: number;
  maxCost: number;
  minLimit: number;
  maxLimit: number;
  minWindowMs: number;
  maxWindowMs: number;
  minBurst: number;
  maxBurst: number;
  minBodyBytes: number;
  maxBodyBytes: number;
  minTimeoutMs: number;
  maxTimeoutMs: number;
}

export interface ClientIdentity {
  rawIpNormalized: string;
  ipHash: string;
  shortIpHash: string;
  userId?: string;
  accountKey?: string;
  connectionId?: string;
  routeGroup: RouteGroup;
  keys: {
    mostSpecific: string;
    ipGroup: string;
    ipOnly: string;
    userGroup?: string;
    userOnly?: string;
    connection?: string;
    accountHourly?: string;
  };
  allLimitKeys: string[];
}

export interface RateLimitResult {
  allowed: boolean;
  limit: number;
  remaining: number;
  resetAtMs: number;
  retryAfterSeconds: number;
  keyHit?: string;
}

export type PenaltyStage = 'NONE' | 'WARN' | 'SLOWDOWN' | 'BLOCKED';

export interface StrikeRecord {
  key: string;
  shortKey: string;
  strikes: number;
  lastStrikeAt: number;
  blockLevel: number;
  blockedUntil: number;
  lastUpdatedAt: number;
}

export interface GatewayBlockRecord {
  id: string;
  hashedKey: string;
  shortKey: string;
  scope: 'ip' | 'user' | 'connection' | 'manual';
  reason: string;
  manual: boolean;
  createdByAdminId?: string;
  createdAt: string;
  expiresAt: string;
}

export interface GatewayAllowlistRecord {
  id: string;
  hashedKey: string;
  shortKey: string;
  label: string;
  multiplier: number;
  createdByAdminId: string;
  createdAt: string;
  expiresAt: string;
}

export interface GatewayAuditEntry {
  id: string;
  timestamp: string;
  adminId: string;
  action: 'MANUAL_BLOCK' | 'UNBLOCK' | 'ALLOWLIST_ADD' | 'ALLOWLIST_REMOVE' | 'POLICY_UPDATE' | 'POLICY_RESET';
  targetShortKey: string;
  details: string;
}

export interface GatewayDecision {
  allowed: boolean;
  statusCode: number;
  outcome: 'allowed' | 'throttled' | 'blocked' | 'shed' | 'oversize' | 'malformed' | 'store_error';
  message: string;
  routeGroup: RouteGroup;
  loadLevel: LoadLevel;
  headers: Record<string, string>;
  retryAfterSeconds?: number;
  challengeRequired?: boolean;
  artificialDelayMs?: number;
  penaltyStage?: PenaltyStage;
}

export interface GatewayStatsSnapshot {
  totalRequests: number;
  requestsPerSecond: number;
  outcomes: {
    allowed: number;
    throttled: number;
    blocked: number;
    shed: number;
    oversize: number;
    malformed: number;
    storeError: number;
  };
  byRouteGroup: Record<
    RouteGroup,
    {
      total: number;
      allowed: number;
      throttled: number;
      blocked: number;
      shed: number;
    }
  >;
  byMinute: Array<{
    minute: string;
    label: string;
    total: number;
    allowed: number;
    throttled: number;
    blocked: number;
    shed: number;
  }>;
  loadLevel: LoadLevel;
  inFlightRequests: number;
  eventLoopDelayMs: {
    mean: number;
    p95: number;
    max: number;
  };
  latencyMs: {
    p50: number;
    p95: number;
    sampleCount: number;
  };
  store: {
    mode: 'memory' | 'upstash-redis';
    trackedKeys: number;
    maxKeys: number;
    evictions: number;
  };
  topThrottledKeys: Array<{
    shortKey: string;
    throttledCount: number;
    strikes: number;
    stage: PenaltyStage;
    blockedUntil: string | null;
  }>;
  circuitBreakers: Array<{
    channel: string;
    state: string;
    consecutiveFailures: number;
  }>;
  generatedAt: string;
}

export interface GatewaySimulationScenarioResult {
  code: string;
  title: string;
  expected: string;
  observed: string;
  passed: boolean;
}
