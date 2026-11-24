import { validateCheapRequestHardening } from './hardening.js';
import { buildClientIdentity } from './identity.js';
import { ConcurrencyLimiter } from './limiters/concurrency.js';
import { addRetryJitter } from './limiters/jitter.js';
import {
  getGlobalLoadController,
  LoadLevelController,
  shouldShedRequest,
} from './loadShedder.js';
import { getGatewayMetrics } from './metrics.js';
import { getGlobalPenaltyBox, PenaltyBoxManager } from './penaltyBox.js';
import { classifyRequestRoute, getPolicyForGroup } from './policies.js';
import { getGatewayStore, runWithFailureMode, type GatewayStoreAdapter } from './store/index.js';
import type { ClockFn, GatewayDecision, RoutePolicy } from './types.js';

declare global {
  var __aegisGatewayConcurrencyLimiter: ConcurrencyLimiter | undefined;
}

export function getGlobalConcurrencyLimiter(): ConcurrencyLimiter {
  if (!global.__aegisGatewayConcurrencyLimiter) {
    global.__aegisGatewayConcurrencyLimiter = new ConcurrencyLimiter();
  }
  return global.__aegisGatewayConcurrencyLimiter;
}

export interface EvaluateGatewayInput {
  method: string;
  url: string;
  headers: Record<string, string | string[] | undefined>;
  socketRemoteAddress?: string | null;
  userId?: string;
  isAuthenticated?: boolean;
  accountKey?: string;
  isCriticalPriority?: boolean;
  trustProxyHops?: number;
  ipSalt?: string;
  policyOverride?: RoutePolicy;
  // Injectable dependencies for isolated tests & simulations
  store?: GatewayStoreAdapter;
  penaltyBox?: PenaltyBoxManager;
  loadController?: LoadLevelController;
  concurrencyLimiter?: ConcurrencyLimiter;
  clock?: ClockFn;
  simulatedEventLoopDelayMs?: number;
  recordLiveMetrics?: boolean;
}

export interface EvaluateGatewayResult {
  decision: GatewayDecision;
  releaseConcurrency: () => void;
  policy: RoutePolicy;
  shortIpHash: string;
}

export async function evaluateGatewayRequest(
  input: EvaluateGatewayInput
): Promise<EvaluateGatewayResult> {
  const clock = input.clock ?? Date.now;
  const now = clock();
  const store = input.store ?? getGatewayStore();
  const penaltyBox = input.penaltyBox ?? getGlobalPenaltyBox();
  const loadCtrl = input.loadController ?? getGlobalLoadController();
  const concurrency = input.concurrencyLimiter ?? getGlobalConcurrencyLimiter();
  const metrics = input.recordLiveMetrics === false ? null : getGatewayMetrics();

  const routeMatch = classifyRequestRoute(input.method, input.url);
  const basePolicy = input.policyOverride ?? getPolicyForGroup(routeMatch.group);
  const cost = routeMatch.costOverride ?? basePolicy.cost;

  // 1. Cheap pre-body request hardening (URL length, header sizes, method, content-length, content-type)
  const identity = buildClientIdentity({
    socketRemoteAddress: input.socketRemoteAddress,
    xForwardedFor: input.headers['x-forwarded-for'],
    trustProxyHops: input.trustProxyHops,
    userId: input.userId,
    accountKey: input.accountKey,
    connectionId: routeMatch.connectionId,
    routeGroup: routeMatch.group,
    salt: input.ipSalt,
  });

  const hardening = validateCheapRequestHardening({
    method: input.method,
    url: input.url,
    headers: input.headers,
    policy: basePolicy,
  });

  if (!hardening.ok) {
    const outcome = hardening.outcome === 'oversize' ? 'oversize' : 'malformed';
    metrics?.recordOutcome({
      routeGroup: routeMatch.group,
      outcome,
      shortIpHash: identity.shortIpHash,
      detail: hardening.message || 'Request rejected by ingress hardening.',
      nowMs: now,
    });
    return {
      decision: {
        allowed: false,
        statusCode: hardening.statusCode || 400,
        outcome,
        message: hardening.message || 'Malformed or oversized request.',
        routeGroup: routeMatch.group,
        loadLevel: loadCtrl.getCurrentLevel(),
        headers: hardening.headers || {},
      },
      releaseConcurrency: () => {},
      policy: basePolicy,
      shortIpHash: identity.shortIpHash,
    };
  }

  // CORS preflight OPTIONS passes immediately
  if (input.method.toUpperCase() === 'OPTIONS') {
    return {
      decision: {
        allowed: true,
        statusCode: 204,
        outcome: 'allowed',
        message: 'Preflight allowed.',
        routeGroup: routeMatch.group,
        loadLevel: loadCtrl.getCurrentLevel(),
        headers: {},
      },
      releaseConcurrency: () => {},
      policy: basePolicy,
      shortIpHash: identity.shortIpHash,
    };
  }

  // 2. Health route: counted & logged minimally, exempt from throttling & shedding
  if (routeMatch.group === 'health') {
    metrics?.recordOutcome({
      routeGroup: 'health',
      outcome: 'allowed',
      shortIpHash: identity.shortIpHash,
      detail: 'Health probe counted and allowed.',
      nowMs: now,
    });
    return {
      decision: {
        allowed: true,
        statusCode: 200,
        outcome: 'allowed',
        message: 'Health check allowed.',
        routeGroup: 'health',
        loadLevel: loadCtrl.getCurrentLevel(),
        headers: {
          'RateLimit-Limit': String(basePolicy.limit),
          'RateLimit-Remaining': String(basePolicy.limit),
          'RateLimit-Reset': String(Math.ceil((now + basePolicy.windowMs) / 1000)),
        },
      },
      releaseConcurrency: () => {},
      policy: basePolicy,
      shortIpHash: identity.shortIpHash,
    };
  }

  // 3. Evaluate Server Load Level (hysteresis over event-loop delay & in-flight requests)
  const measuredDelay =
    typeof input.simulatedEventLoopDelayMs === 'number'
      ? input.simulatedEventLoopDelayMs
      : loadCtrl.getEventLoopDelayMs().mean;
  const inFlight = metrics ? metrics.getInFlightCount() : concurrency.getGlobalCount();
  const loadEval = loadCtrl.evaluate({
    eventLoopDelayMs: measuredDelay,
    inFlightRequests: inFlight,
  });

  if (loadEval.changed && metrics) {
    metrics.enqueueTelemetry({
      eventType: 'GATEWAY_LOAD_LEVEL_CHANGED',
      severity: loadEval.current === 'CRITICAL' ? 'critical' : loadEval.current === 'HIGH' ? 'warning' : 'info',
      result: 'success',
      shortIpHash: identity.shortIpHash,
      routeGroup: routeMatch.group,
      detail: `Gateway load level changed ${loadEval.previous} -> ${loadEval.current} (delay=${measuredDelay.toFixed(1)}ms, inFlight=${inFlight}).`,
      nowMs: now,
    });
  }

  // 4. Priority-aware load shedding BEFORE heavy work
  const shedCheck = shouldShedRequest({
    loadLevel: loadEval.current,
    policy: basePolicy,
    isAuthenticated: Boolean(input.isAuthenticated || input.userId),
    isCriticalPriority: Boolean(input.isCriticalPriority),
    isCriticalAuthOrAck: routeMatch.isCriticalAuthOrAck,
  });

  if (shedCheck.shed) {
    const retryAfter = addRetryJitter(shedCheck.retryAfterSeconds || 10);
    metrics?.recordOutcome({
      routeGroup: routeMatch.group,
      outcome: 'shed',
      shortIpHash: identity.shortIpHash,
      detail: shedCheck.reason || `Shed ${routeMatch.group} at load=${loadEval.current}.`,
      nowMs: now,
    });
    return {
      decision: {
        allowed: false,
        statusCode: 503,
        outcome: 'shed',
        message: shedCheck.reason || 'Server busy. Please retry shortly.',
        routeGroup: routeMatch.group,
        loadLevel: loadEval.current,
        retryAfterSeconds: retryAfter,
        headers: {
          'Retry-After': String(retryAfter),
        },
      },
      releaseConcurrency: () => {},
      policy: basePolicy,
      shortIpHash: identity.shortIpHash,
    };
  }

  // 5. Check Manual Blocks, Penalty Box Blocks, and Allowlist
  const penaltyCheck = penaltyBox.checkBlocked(identity.allLimitKeys);
  if (penaltyCheck.blocked) {
    const retryAfter = addRetryJitter(penaltyCheck.retryAfterSeconds || 60);
    const challengeRequired = routeMatch.group === 'auth';
    metrics?.recordOutcome({
      routeGroup: routeMatch.group,
      outcome: 'blocked',
      shortIpHash: identity.shortIpHash,
      detail: `Blocked request from ${identity.shortIpHash} (${penaltyCheck.reason || 'penalty box'}).`,
      nowMs: now,
    });
    return {
      decision: {
        allowed: false,
        statusCode: 429,
        outcome: 'blocked',
        message: penaltyCheck.reason || 'Request temporarily blocked due to repeated rate limit abuse.',
        routeGroup: routeMatch.group,
        loadLevel: loadEval.current,
        retryAfterSeconds: retryAfter,
        challengeRequired,
        penaltyStage: penaltyCheck.stage,
        headers: {
          'Retry-After': String(retryAfter),
          'RateLimit-Limit': String(basePolicy.limit),
          'RateLimit-Remaining': '0',
          'RateLimit-Reset': String(Math.ceil((now + retryAfter * 1000) / 1000)),
        },
      },
      releaseConcurrency: () => {},
      policy: basePolicy,
      shortIpHash: identity.shortIpHash,
    };
  }

  // 6. Concurrency Limiter (per user/IP & per route group)
  const concResult = concurrency.acquire({
    routeGroup: routeMatch.group,
    userOrIpKey: identity.keys.userOnly || identity.keys.ipOnly,
    maxPerUser: basePolicy.concurrencyPerUser,
    maxPerRoute: basePolicy.concurrencyPerRoute,
  });

  if (!concResult.allowed) {
    const retryAfter = addRetryJitter(2);
    metrics?.recordOutcome({
      routeGroup: routeMatch.group,
      outcome: 'throttled',
      shortIpHash: identity.shortIpHash,
      keyHit: identity.keys.mostSpecific,
      detail: concResult.reason || 'Concurrency cap exceeded.',
      nowMs: now,
    });
    return {
      decision: {
        allowed: false,
        statusCode: 429,
        outcome: 'throttled',
        message: concResult.reason || 'Too many concurrent requests.',
        routeGroup: routeMatch.group,
        loadLevel: loadEval.current,
        retryAfterSeconds: retryAfter,
        headers: {
          'Retry-After': String(retryAfter),
          'RateLimit-Limit': String(basePolicy.limit),
          'RateLimit-Remaining': '0',
          'RateLimit-Reset': String(Math.ceil((now + retryAfter * 1000) / 1000)),
        },
      },
      releaseConcurrency: () => {},
      policy: basePolicy,
      shortIpHash: identity.shortIpHash,
    };
  }

  // 7. Compute Effective Multiplier (allowlist bonus vs ELEVATED anonymous tightening)
  const allowlist = penaltyBox.getActiveAllowlist(identity.allLimitKeys);
  const isAuthed = Boolean(input.isAuthenticated || input.userId);
  let ceilingFactor = 1;
  if (allowlist) {
    ceilingFactor = allowlist.multiplier;
  } else if (loadEval.current === 'ELEVATED' && !isAuthed) {
    ceilingFactor = 0.5;
  } else if (isAuthed) {
    ceilingFactor = 1.15;
  }

  // Build hierarchical rate checks: specific key + coarser keys
  interface LimitCheckSpec {
    key: string;
    isIpOnly: boolean;
    algorithm: 'token_bucket' | 'sliding_window';
    limit: number;
    burst: number;
    windowMs: number;
    refillPerSec: number;
    cost: number;
  }

  const checks: LimitCheckSpec[] = [];

  if (routeMatch.group === 'auth' && routeMatch.isSmsSend) {
    // SMS Send: 5 per hour per phone/account & 10 per hour per IP (unit cost 1 per SMS request under policy cost=20 budget or explicit count)
    const smsAccountCap = Math.max(1, Math.round(5 * (allowlist ? allowlist.multiplier : 1)));
    const smsIpCap = Math.max(2, Math.round((basePolicy.secondaryIpHourlyLimit || 10) * (allowlist ? allowlist.multiplier : 1)));
    if (identity.keys.accountHourly) {
      checks.push({
        key: `sms_acct:${identity.keys.accountHourly}`,
        isIpOnly: false,
        algorithm: 'sliding_window',
        limit: smsAccountCap,
        burst: smsAccountCap,
        windowMs: 3_600_000,
        refillPerSec: smsAccountCap / 3600,
        cost: 1,
      });
    }
    checks.push({
      key: `sms_ip:${identity.keys.ipOnly}`,
      isIpOnly: true,
      algorithm: 'sliding_window',
      limit: smsIpCap,
      burst: smsIpCap,
      windowMs: 3_600_000,
      refillPerSec: smsIpCap / 3600,
      cost: 1,
    });
  } else if (routeMatch.group === 'auth' && !routeMatch.isAckLink) {
    // Strict Auth (login / OTP): 5/min per IP+account AND 20/hr per account
    const perMinCap = Math.max(1, Math.round(basePolicy.limit * (allowlist ? allowlist.multiplier : 1)));
    checks.push({
      key: `auth_min:${identity.keys.mostSpecific}`,
      isIpOnly: !identity.keys.accountHourly && !identity.keys.userOnly,
      algorithm: 'sliding_window',
      limit: perMinCap,
      burst: perMinCap,
      windowMs: basePolicy.windowMs,
      refillPerSec: perMinCap / (basePolicy.windowMs / 1000),
      cost: 1,
    });

    const hourlyCap = Math.max(5, Math.round((basePolicy.secondaryHourlyLimit || 20) * (allowlist ? allowlist.multiplier : 1)));
    const acctKey = identity.keys.userOnly || identity.keys.accountHourly;
    if (acctKey) {
      checks.push({
        key: `auth_hr:${acctKey}`,
        isIpOnly: false,
        algorithm: 'sliding_window',
        limit: hourlyCap,
        burst: hourlyCap,
        windowMs: 3_600_000,
        refillPerSec: hourlyCap / 3600,
        cost: 1,
      });
    }

    // Secondary IP hourly ceiling prevents an attacker from rotating fake email accounts from a single IP
    const authIpCap = Math.max(5, Math.round((basePolicy.secondaryIpHourlyLimit || 10) * (allowlist ? allowlist.multiplier : 1)));
    checks.push({
      key: `auth_ip:${identity.keys.ipOnly}`,
      isIpOnly: true,
      algorithm: 'sliding_window',
      limit: authIpCap,
      burst: authIpCap,
      windowMs: 3_600_000,
      refillPerSec: authIpCap / 3600,
      cost: 1,
    });
  } else if (routeMatch.group === 'ingest') {
    // Ingest: 60/min per connection + coarser IP bucket so one abusive IP cannot overwhelm multiple connections
    const connLimit = Math.max(5, Math.round(basePolicy.limit * ceilingFactor));
    if (identity.keys.connection) {
      checks.push({
        key: `ingest_conn:${identity.keys.connection}`,
        isIpOnly: false,
        algorithm: 'sliding_window',
        limit: connLimit,
        burst: connLimit,
        windowMs: basePolicy.windowMs,
        refillPerSec: connLimit / (basePolicy.windowMs / 1000),
        cost: 1,
      });
    }
    const ipIngestLimit = Math.max(connLimit, connLimit * 2);
    checks.push({
      key: `ingest_ip:${identity.keys.ipGroup}`,
      isIpOnly: true,
      algorithm: 'sliding_window',
      limit: ipIngestLimit,
      burst: ipIngestLimit,
      windowMs: basePolicy.windowMs,
      refillPerSec: ipIngestLimit / (basePolicy.windowMs / 1000),
      cost: 1,
    });
  } else {
    // General / Messaging / Ephemeral / Provenance / Dedup / Priority / Telemetry / Admin
    // Enforce most-specific user key AND a generous shared-IP ceiling (4x) so legitimate users behind NAT aren't punished
    const scaledLimit = Math.max(3, Math.round(basePolicy.limit * ceilingFactor));
    const scaledBurst = Math.max(1, Math.round(basePolicy.burst * ceilingFactor));
    const scaledRefill = Number(Math.max(0.05, basePolicy.refillPerSec * ceilingFactor).toFixed(2));
    const costUnits = Math.max(1, cost);

    if (identity.keys.userGroup) {
      checks.push({
        key: `rl:${identity.keys.userGroup}`,
        isIpOnly: false,
        algorithm: basePolicy.algorithm,
        limit: scaledLimit * costUnits,
        burst: scaledBurst * costUnits,
        windowMs: basePolicy.windowMs,
        refillPerSec: scaledRefill * costUnits,
        cost: costUnits,
      });
    }

    const ipSharedMultiplier = identity.keys.userGroup ? 4 : 1;
    checks.push({
      key: `rl:${identity.keys.ipGroup}`,
      isIpOnly: true,
      algorithm: basePolicy.algorithm,
      limit: scaledLimit * costUnits * ipSharedMultiplier,
      burst: scaledBurst * costUnits * ipSharedMultiplier,
      windowMs: basePolicy.windowMs,
      refillPerSec: scaledRefill * costUnits * ipSharedMultiplier,
      cost: costUnits,
    });
  }

  // 8. Execute Store Rate Limit Checks with Failure Mode Policy
  let worstRemaining = Number.POSITIVE_INFINITY;
  let activeLimit = basePolicy.limit;
  let activeResetAtMs = now + basePolicy.windowMs;

  for (const check of checks) {
    const execRes = await runWithFailureMode({
      failureMode: basePolicy.failureMode,
      fallbackOpenValue: {
        allowed: true,
        limit: check.limit,
        remaining: check.limit,
        resetAtMs: now + check.windowMs,
        retryAfterSeconds: 0,
        keyHit: check.key,
      },
      onStoreError: (err) => {
        metrics?.recordOutcome({
          routeGroup: routeMatch.group,
          outcome: 'store_error',
          shortIpHash: identity.shortIpHash,
          detail: `Gateway store failure on ${routeMatch.group} (${basePolicy.failureMode}): ${err.message}`,
          nowMs: now,
        });
      },
      action: () =>
        store.atomicConsume({
          key: check.key,
          algorithm: check.algorithm,
          limit: check.limit,
          windowMs: check.windowMs,
          burst: check.burst,
          refillPerSec: check.refillPerSec,
          cost: check.cost,
          clock,
        }),
    });

    if (execRes.failClosed) {
      concResult.release();
      return {
        decision: {
          allowed: false,
          statusCode: 503,
          outcome: 'store_error',
          message: 'Security rate-limit store temporarily unavailable. Auth routes fail closed for protection.',
          routeGroup: routeMatch.group,
          loadLevel: loadEval.current,
          retryAfterSeconds: 5,
          headers: {
            'Retry-After': '5',
          },
        },
        releaseConcurrency: () => {},
        policy: basePolicy,
        shortIpHash: identity.shortIpHash,
      };
    }

    const r = execRes.value!;
    activeLimit = r.limit;
    worstRemaining = Math.min(worstRemaining, r.remaining);
    activeResetAtMs = Math.max(activeResetAtMs, r.resetAtMs);

    if (!r.allowed) {
      concResult.release();
      // Record strike in penalty box
      const strikeRes = penaltyBox.recordStrike({
        key: check.isIpOnly ? identity.keys.ipOnly : identity.keys.userOnly || check.key,
        isIpOnlyKey: check.isIpOnly,
      });

      if (metrics) {
        metrics.recordOutcome({
          routeGroup: routeMatch.group,
          outcome: 'throttled',
          shortIpHash: identity.shortIpHash,
          keyHit: check.isIpOnly ? identity.keys.ipOnly : identity.keys.userOnly || check.key,
          detail: `Rate limit exceeded on ${routeMatch.group} (${check.key.slice(0, 18)}..., strikes=${strikeRes.record.strikes}, stage=${strikeRes.stage}).`,
          nowMs: now,
        });
        metrics.enqueueTelemetry({
          eventType: 'GATEWAY_STRIKE',
          severity: strikeRes.justBlocked ? 'warning' : 'info',
          result: 'blocked',
          shortIpHash: identity.shortIpHash,
          routeGroup: routeMatch.group,
          detail: `Strike #${strikeRes.record.strikes} assigned (${strikeRes.stage})${
            strikeRes.justBlocked ? `; blocked ${strikeRes.blockDurationSeconds}s` : ''
          }.`,
          nowMs: now,
        });
      }

      const retrySeconds = strikeRes.justBlocked
        ? Math.max(r.retryAfterSeconds, strikeRes.blockDurationSeconds)
        : r.retryAfterSeconds;

      const challengeRequired = routeMatch.group === 'auth' && (strikeRes.justBlocked || strikeRes.record.strikes >= 5);

      return {
        decision: {
          allowed: false,
          statusCode: 429,
          outcome: 'throttled',
          message: strikeRes.justBlocked
            ? `Rate limit exceeded repeatedly. Temporarily blocked for ${strikeRes.blockDurationSeconds}s.`
            : 'Too many requests. Please respect the rate limit and retry shortly.',
          routeGroup: routeMatch.group,
          loadLevel: loadEval.current,
          retryAfterSeconds: retrySeconds,
          challengeRequired,
          penaltyStage: strikeRes.stage,
          headers: {
            'Retry-After': String(retrySeconds),
            'RateLimit-Limit': String(r.limit),
            'RateLimit-Remaining': String(r.remaining),
            'RateLimit-Reset': String(Math.ceil(r.resetAtMs / 1000)),
          },
        },
        releaseConcurrency: () => {},
        policy: basePolicy,
        shortIpHash: identity.shortIpHash,
      };
    }
  }

  // Request allowed!
  if (isAuthed && identity.keys.userOnly && penaltyCheck.stage === 'NONE') {
    penaltyBox.recordGoodBehavior(identity.keys.userOnly);
  }

  metrics?.recordOutcome({
    routeGroup: routeMatch.group,
    outcome: 'allowed',
    shortIpHash: identity.shortIpHash,
    detail: `Allowed ${input.method.toUpperCase()} ${routeMatch.group} (cost=${cost}, remaining=${
      Number.isFinite(worstRemaining) ? worstRemaining : activeLimit
    }).`,
    nowMs: now,
  });

  const finalRemaining = Number.isFinite(worstRemaining) ? worstRemaining : activeLimit;

  return {
    decision: {
      allowed: true,
      statusCode: 200,
      outcome: 'allowed',
      message: 'Allowed',
      routeGroup: routeMatch.group,
      loadLevel: loadEval.current,
      artificialDelayMs: penaltyCheck.artificialDelayMs,
      penaltyStage: penaltyCheck.stage,
      headers: {
        'RateLimit-Limit': String(activeLimit),
        'RateLimit-Remaining': String(Math.max(0, finalRemaining)),
        'RateLimit-Reset': String(Math.ceil(activeResetAtMs / 1000)),
      },
    },
    releaseConcurrency: concResult.release,
    policy: basePolicy,
    shortIpHash: identity.shortIpHash,
  };
}
