import { describe, expect, it } from 'vitest';
import { evaluateGatewayRequest } from '../engine.js';
import {
  inspectRawJsonTextForPollution,
  validateCheapRequestHardening,
  validateParsedJsonSafety,
} from '../hardening.js';
import {
  buildClientIdentity,
  hashIp,
  normalizeIp,
  parseTrustedClientIp,
} from '../identity.js';
import { ConcurrencyLimiter } from '../limiters/concurrency.js';
import { evaluateSlidingWindow, type SlidingWindowState } from '../limiters/slidingWindow.js';
import { evaluateTokenBucket, type TokenBucketState } from '../limiters/tokenBucket.js';
import { LoadLevelController, shouldShedRequest } from '../loadShedder.js';
import { PenaltyBoxManager } from '../penaltyBox.js';
import {
  getPolicyForGroup,
  resetAllRoutePolicies,
  validateAndUpdateRoutePolicy,
} from '../policies.js';
import { runGatewaySimulation } from '../simulator.js';
import { MemoryLruGatewayStore } from '../store/memoryStore.js';

describe('Ingress Gateway & DoS Rate Limiter', () => {
  it('evaluates token bucket burst & steady refill accurately with a virtual clock', () => {
    let now = 1_700_000_000_000;
    const clock = () => now;
    const deterministicRng = () => 0.5;

    let state: TokenBucketState | null = null;
    // Burst = 5, refill = 1 token/sec
    for (let i = 0; i < 5; i++) {
      const step = evaluateTokenBucket(state, {
        capacity: 5,
        refillPerSec: 1,
        cost: 1,
        clock,
        rng: deterministicRng,
      });
      state = step.nextState;
      expect(step.result.allowed).toBe(true);
      expect(step.result.remaining).toBe(4 - i);
    }

    // 6th immediate request fails with retryAfterSeconds >= 1
    const denied = evaluateTokenBucket(state, {
      capacity: 5,
      refillPerSec: 1,
      cost: 1,
      clock,
      rng: deterministicRng,
    });
    state = denied.nextState;
    expect(denied.result.allowed).toBe(false);
    expect(denied.result.retryAfterSeconds).toBeGreaterThanOrEqual(1);

    // Advance virtual clock by 2.5s -> 2.5 tokens refilled -> cost=2 allowed, cost=1 fails
    now += 2500;
    const refilled = evaluateTokenBucket(state, {
      capacity: 5,
      refillPerSec: 1,
      cost: 2,
      clock,
      rng: deterministicRng,
    });
    expect(refilled.result.allowed).toBe(true);
    expect(refilled.result.remaining).toBe(0);
  });

  it('enforces sliding-window strict boundary expiry and cost-weighted limits', () => {
    let now = 1_700_000_000_000;
    const clock = () => now;
    const rng = () => 0.5;

    let state: SlidingWindowState | null = null;

    // Limit = 10 cost units in 10_000ms window
    const s1 = evaluateSlidingWindow(state, { limit: 10, windowMs: 10_000, cost: 5, clock, rng });
    state = s1.nextState;
    expect(s1.result.allowed).toBe(true);
    expect(s1.result.remaining).toBe(5);

    now += 2_000;
    const s2 = evaluateSlidingWindow(state, { limit: 10, windowMs: 10_000, cost: 5, clock, rng });
    state = s2.nextState;
    expect(s2.result.allowed).toBe(true);
    expect(s2.result.remaining).toBe(0);

    // At 9_999ms from first entry, window is still full -> cost=1 rejected
    now += 7_999;
    const rejected = evaluateSlidingWindow(state, { limit: 10, windowMs: 10_000, cost: 1, clock, rng });
    expect(rejected.result.allowed).toBe(false);
    expect(rejected.result.retryAfterSeconds).toBeGreaterThanOrEqual(1);

    // Advance exactly 1ms so first entry (t=0) hits exact boundary ts === now - windowMs -> expires
    now += 1;
    const afterExpiry = evaluateSlidingWindow(state, { limit: 10, windowMs: 10_000, cost: 5, clock, rng });
    expect(afterExpiry.result.allowed).toBe(true);
    expect(afterExpiry.result.remaining).toBe(0);
  });

  it('releases concurrency slots idempotently and never leaks on error paths', () => {
    const conc = new ConcurrencyLimiter();
    const h1 = conc.acquire({
      routeGroup: 'messaging',
      userOrIpKey: 'user:alice',
      maxPerUser: 2,
      maxPerRoute: 10,
    });
    const h2 = conc.acquire({
      routeGroup: 'messaging',
      userOrIpKey: 'user:alice',
      maxPerUser: 2,
      maxPerRoute: 10,
    });
    const h3 = conc.acquire({
      routeGroup: 'messaging',
      userOrIpKey: 'user:alice',
      maxPerUser: 2,
      maxPerRoute: 10,
    });

    expect(h1.allowed).toBe(true);
    expect(h2.allowed).toBe(true);
    expect(h3.allowed).toBe(false);
    expect(conc.getClientCount('user:alice')).toBe(2);

    // Calling release twice on h1 must only decrement once
    try {
      throw new Error('simulated route handler crash');
    } catch {
      h1.release();
      h1.release();
    }

    expect(conc.getClientCount('user:alice')).toBe(1);
    h2.release();
    expect(conc.getClientCount('user:alice')).toBe(0);
    expect(conc.getGlobalCount()).toBe(0);
  });

  it('normalizes IPv4-mapped IPv6, IPv6 /64 subnets, and trusted X-Forwarded-For hops securely', () => {
    expect(normalizeIp('::ffff:198.51.100.42')).toBe('198.51.100.42');
    expect(normalizeIp('2001:0db8:85a3:0001:dead:beef:cafe:0001')).toBe('2001:0db8:85a3:0001::/64');
    expect(normalizeIp('2001:db8:85a3:1:ffff:1234:5678:9abc')).toBe('2001:0db8:85a3:0001::/64');

    // Different host bits in the same IPv6 /64 hash identically
    const hA = hashIp(normalizeIp('2001:db8:1:2::1'), 'unit-test-salt');
    const hB = hashIp(normalizeIp('2001:db8:1:2:dead:beef::99'), 'unit-test-salt');
    expect(hA).toBe(hB);

    // Spoofed leftmost X-Forwarded-For is ignored when trustProxyHops=1
    const spoofedChain = '10.0.0.1, 172.16.0.5, 203.0.113.88';
    expect(
      parseTrustedClientIp({
        socketRemoteAddress: '127.0.0.1',
        xForwardedFor: spoofedChain,
        trustProxyHops: 1,
      })
    ).toBe('203.0.113.88');

    // Two trusted proxies -> second from right
    expect(
      parseTrustedClientIp({
        socketRemoteAddress: '127.0.0.1',
        xForwardedFor: spoofedChain,
        trustProxyHops: 2,
      })
    ).toBe('172.16.0.5');

    // Zero trusted proxies -> ignores X-Forwarded-For completely
    expect(
      parseTrustedClientIp({
        socketRemoteAddress: '198.51.100.9',
        xForwardedFor: spoofedChain,
        trustProxyHops: 0,
      })
    ).toBe('198.51.100.9');

    const ident = buildClientIdentity({
      socketRemoteAddress: '198.51.100.9',
      userId: 'usr_123',
      routeGroup: 'messaging',
      salt: 'unit-test-salt',
    });
    expect(ident.keys.mostSpecific).toBe('user:usr_123:group:messaging');
    expect(ident.shortIpHash).toHaveLength(8);
  });

  it('escalates penalty box strikes cleanly (1m -> 5m -> 30m -> 24h cap) and decays over quiet time', () => {
    let now = 1_700_000_000_000;
    const clock = () => now;
    const pb = new PenaltyBoxManager({ clock });

    const userKey = 'user:abuser_1';
    for (let i = 0; i < 4; i++) {
      const s = pb.recordStrike({ key: userKey });
      expect(s.justBlocked).toBe(false);
    }

    // 5th strike triggers Level 1 block (1m = 60s)
    const b1 = pb.recordStrike({ key: userKey });
    expect(b1.justBlocked).toBe(true);
    expect(b1.blockDurationSeconds).toBe(60);
    expect(pb.checkBlocked([userKey]).blocked).toBe(true);

    // Wait out 1m block -> next strike triggers Level 2 block (5m = 300s)
    now += 61_000;
    const b2 = pb.recordStrike({ key: userKey });
    expect(b2.blockDurationSeconds).toBe(300);

    // Level 3 -> 30m (1800s), Level 4 -> 24h (86400s), Level 5+ stays capped at 24h
    now += 301_000;
    expect(pb.recordStrike({ key: userKey }).blockDurationSeconds).toBe(1800);
    now += 1801_000;
    expect(pb.recordStrike({ key: userKey }).blockDurationSeconds).toBe(86400);
    now += 86401_000;
    expect(pb.recordStrike({ key: userKey }).blockDurationSeconds).toBe(86400);

    // Strikes stay intact while the 24h block is active
    now += 60 * 60 * 1000;
    expect(pb.getStrikeInfo(userKey)?.strikes).toBe(9);

    // Wait out remaining 23h block + 60 minutes quiet -> strikes decay (1 per 10m => 6 decayed, 9 -> 3)
    now += 23 * 60 * 60 * 1000 + 60 * 60 * 1000;
    const afterDecay = pb.getStrikeInfo(userKey);
    expect(afterDecay?.strikes).toBeLessThan(5);
  });

  it('caps MemoryLruGatewayStore with LRU eviction under high cardinality', async () => {
    let now = 1_700_000_000_000;
    const store = new MemoryLruGatewayStore({ maxKeys: 100, clock: () => now });

    for (let i = 0; i < 350; i++) {
      await store.set(`rand:${i}`, { v: i }, 60_000);
    }

    const stats = store.getStats();
    expect(stats.trackedKeys).toBeLessThanOrEqual(100);
    expect(stats.evictions).toBe(250);
    expect(await store.get('rand:0')).toBeNull();
    expect(await store.get('rand:349')).toEqual({ v: 349 });
  });

  it('applies load-level hysteresis and sheds low-value routes before ACK/OTP/CRITICAL messaging', () => {
    const loadCtrl = new LoadLevelController();

    expect(loadCtrl.evaluate({ eventLoopDelayMs: 10, inFlightRequests: 5 }).current).toBe('NORMAL');
    // Crosses elevatedEnterDelayMs (35) -> ELEVATED
    expect(loadCtrl.evaluate({ eventLoopDelayMs: 40, inFlightRequests: 5 }).current).toBe('ELEVATED');
    // Jitters down to 25 (above elevatedExitDelayMs=20) -> stays ELEVATED (no flapping)
    expect(loadCtrl.evaluate({ eventLoopDelayMs: 25, inFlightRequests: 5 }).current).toBe('ELEVATED');
    // Drops below exit (15) -> returns NORMAL
    expect(loadCtrl.evaluate({ eventLoopDelayMs: 15, inFlightRequests: 5 }).current).toBe('NORMAL');

    // Enters HIGH -> telemetry shed, ACK/OTP/messaging preserved
    loadCtrl.evaluate({ eventLoopDelayMs: 95, inFlightRequests: 5 });
    expect(
      shouldShedRequest({
        loadLevel: 'HIGH',
        policy: getPolicyForGroup('telemetry'),
        isAuthenticated: true,
      }).shed
    ).toBe(true);
    expect(
      shouldShedRequest({
        loadLevel: 'HIGH',
        policy: getPolicyForGroup('auth'),
        isAuthenticated: false,
        isCriticalAuthOrAck: true,
      }).shed
    ).toBe(false);

    // Enters CRITICAL -> ACK links & authenticated CRITICAL messaging survive while general/dedup shed
    expect(
      shouldShedRequest({
        loadLevel: 'CRITICAL',
        policy: getPolicyForGroup('messaging'),
        isAuthenticated: true,
        isCriticalPriority: true,
      }).shed
    ).toBe(false);
    expect(
      shouldShedRequest({
        loadLevel: 'CRITICAL',
        policy: getPolicyForGroup('dedup'),
        isAuthenticated: true,
      }).shed
    ).toBe(true);
  });

  it('rejects oversized headers/URLs/bodies, disallowed methods, JSON bombs, and prototype pollution', () => {
    const ingestPolicy = getPolicyForGroup('ingest');

    const badUrl = validateCheapRequestHardening({
      method: 'POST',
      url: '/api/v1/ingest/abc?' + 'x'.repeat(3000),
      headers: { 'content-type': 'application/json' },
      policy: ingestPolicy,
    });
    expect(badUrl.statusCode).toBe(414);

    const badMethod = validateCheapRequestHardening({
      method: 'DELETE',
      url: '/api/v1/ingest/abc',
      headers: {},
      policy: ingestPolicy,
    });
    expect(badMethod.statusCode).toBe(405);

    const badLength = validateCheapRequestHardening({
      method: 'POST',
      url: '/api/v1/ingest/abc',
      headers: { 'content-type': 'application/json', 'content-length': String(128 * 1024) },
      policy: ingestPolicy,
    });
    expect(badLength.statusCode).toBe(413);

    const badContentType = validateCheapRequestHardening({
      method: 'POST',
      url: '/api/v1/ingest/abc',
      headers: { 'content-type': 'text/plain', 'content-length': '20' },
      policy: ingestPolicy,
    });
    expect(badContentType.statusCode).toBe(415);

    const rawProto = inspectRawJsonTextForPollution('{"__proto__":{"polluted":true}}');
    expect(rawProto.statusCode).toBe(400);

    let deep: any = { v: 1 };
    for (let i = 0; i < 12; i++) deep = { nested: deep };
    expect(
      validateParsedJsonSafety(deep, { maxDepth: 10, maxKeys: 100, maxArrayLength: 50 }).statusCode
    ).toBe(400);

    const hugeArr = new Array(60).fill(1);
    expect(
      validateParsedJsonSafety({ items: hugeArr }, { maxDepth: 10, maxKeys: 100, maxArrayLength: 50 }).statusCode
    ).toBe(400);
  });

  it('fails closed on auth routes and fails open on general routes when store is down', async () => {
    const brokenStore = new MemoryLruGatewayStore();
    brokenStore.setSimulatedFailure(true);
    const pb = new PenaltyBoxManager();
    const lc = new LoadLevelController();
    const conc = new ConcurrencyLimiter();

    const authDecision = await evaluateGatewayRequest({
      method: 'POST',
      url: '/api/v1/auth/login',
      headers: { 'content-type': 'application/json' },
      socketRemoteAddress: '198.51.100.12',
      store: brokenStore,
      penaltyBox: pb,
      loadController: lc,
      concurrencyLimiter: conc,
      recordLiveMetrics: false,
    });
    expect(authDecision.decision.allowed).toBe(false);
    expect(authDecision.decision.statusCode).toBe(503);

    const generalDecision = await evaluateGatewayRequest({
      method: 'GET',
      url: '/api/v1/notifications/history',
      headers: {},
      socketRemoteAddress: '198.51.100.12',
      userId: 'usr_1',
      isAuthenticated: true,
      store: brokenStore,
      penaltyBox: pb,
      loadController: lc,
      concurrencyLimiter: conc,
      recordLiveMetrics: false,
    });
    expect(generalDecision.decision.allowed).toBe(true);
    expect(generalDecision.decision.statusCode).toBe(200);
  });

  it('validates route policy bounds and protects auth FAIL_CLOSED guardrail', () => {
    resetAllRoutePolicies();
    const invalidAuthOpen = validateAndUpdateRoutePolicy('auth', { failureMode: 'FAIL_OPEN' });
    expect(invalidAuthOpen.ok).toBe(false);

    const invalidLimit = validateAndUpdateRoutePolicy('general', { limit: 999999 });
    expect(invalidLimit.ok).toBe(false);

    const validUpdate = validateAndUpdateRoutePolicy('general', { limit: 200, cost: 2 });
    expect(validUpdate.ok).toBe(true);
    expect(getPolicyForGroup('general').limit).toBe(200);
    resetAllRoutePolicies();
  });

  it('passes all 14 gateway attack & DoS simulation scenarios (a through n)', async () => {
    const results = await runGatewaySimulation('all');
    expect(results).toHaveLength(14);
    for (const r of results) {
      expect(r.passed, `Scenario ${r.code} failed: ${r.observed}`).toBe(true);
    }
  });
});
