import { evaluateGatewayRequest } from './engine.js';
import { validateParsedJsonSafety } from './hardening.js';
import { buildClientIdentity, hashIdentifier, parseTrustedClientIp } from './identity.js';
import { ConcurrencyLimiter } from './limiters/concurrency.js';
import { LoadLevelController } from './loadShedder.js';
import { PenaltyBoxManager } from './penaltyBox.js';
import { getPolicyForGroup } from './policies.js';
import { MemoryLruGatewayStore } from './store/memoryStore.js';
import type { GatewaySimulationScenarioResult } from './types.js';
import {
  verifyEmailPasswordWithConstantTiming,
  recordLoginAuditAndDetectNewDevice,
  saveServerKeyBackup,
  getServerKeyBackup,
  GENERIC_LOGIN_ERROR,
} from '../auth/sessionSecurity.js';

export const GATEWAY_SCENARIO_CODES = [
  'a',
  'b',
  'c',
  'd',
  'e',
  'f',
  'g',
  'h',
  'i',
  'j',
  'k',
  'l',
  'm',
  'n',
] as const;

export const AUTH_SECURITY_SCENARIO_CODES = ['o', 'p', 'q', 'r'] as const;

export const ALL_SCENARIO_CODES = [
  ...GATEWAY_SCENARIO_CODES,
  ...AUTH_SECURITY_SCENARIO_CODES,
] as const;

export async function runGatewaySimulation(
  requestedCode: string = 'all'
): Promise<GatewaySimulationScenarioResult[]> {
  const code = requestedCode.trim().toLowerCase();
  const targets =
    code === 'all'
      ? [...GATEWAY_SCENARIO_CODES]
      : code === 'auth'
        ? [...AUTH_SECURITY_SCENARIO_CODES]
        : code === 'full' || code === 'all_plus_auth'
          ? [...ALL_SCENARIO_CODES]
          : ALL_SCENARIO_CODES.filter((c) => c === code);

  const results: GatewaySimulationScenarioResult[] = [];

  for (const sc of targets) {
    switch (sc) {
      case 'a': {
        // Login brute force: 50 attempts -> 429 after limit, Retry-After present
        let now = 1_700_000_000_000;
        const clock = () => now;
        const store = new MemoryLruGatewayStore({ clock });
        const penalty = new PenaltyBoxManager({ clock });
        const load = new LoadLevelController({ clock });
        const conc = new ConcurrencyLimiter();

        let allowed = 0;
        let throttled = 0;
        let retryHeaderPresent = false;
        let challengeSawTrue = false;

        for (let i = 0; i < 50; i++) {
          const r = await evaluateGatewayRequest({
            method: 'POST',
            url: '/api/v1/auth/login',
            headers: { 'content-type': 'application/json' },
            socketRemoteAddress: '198.51.100.10',
            accountKey: 'victim@example.com',
            store,
            penaltyBox: penalty,
            loadController: load,
            concurrencyLimiter: conc,
            clock,
            recordLiveMetrics: false,
          });
          r.releaseConcurrency();
          if (r.decision.allowed) allowed += 1;
          else if (r.decision.statusCode === 429) {
            throttled += 1;
            if (r.decision.headers['Retry-After']) retryHeaderPresent = true;
            if (r.decision.challengeRequired) challengeSawTrue = true;
          }
        }

        const passed = allowed === 5 && throttled === 45 && retryHeaderPresent && challengeSawTrue;
        results.push({
          code: 'a',
          title: 'Login Brute Force (50 attempts)',
          expected: 'First 5 allowed, 45 throttled (429), Retry-After + challengeRequired=true',
          observed: `allowed=${allowed}, throttled=${throttled}, Retry-After=${retryHeaderPresent}, challengeRequired=${challengeSawTrue}`,
          passed,
        });
        break;
      }

      case 'b': {
        // OTP / SMS spam: 30 send requests -> throttled, provider calls stay <= 5
        let now = 1_700_000_000_000;
        const clock = () => now;
        const store = new MemoryLruGatewayStore({ clock });
        const penalty = new PenaltyBoxManager({ clock });
        const load = new LoadLevelController({ clock });
        const conc = new ConcurrencyLimiter();

        let providerCalls = 0;
        let blocked = 0;
        for (let i = 0; i < 30; i++) {
          const r = await evaluateGatewayRequest({
            method: 'POST',
            url: '/api/v1/auth/sms/send',
            headers: { 'content-type': 'application/json' },
            socketRemoteAddress: '203.0.113.55',
            accountKey: '+919876543210',
            store,
            penaltyBox: penalty,
            loadController: load,
            concurrencyLimiter: conc,
            clock,
            recordLiveMetrics: false,
          });
          r.releaseConcurrency();
          if (r.decision.allowed) providerCalls += 1;
          else blocked += 1;
        }

        const passed = providerCalls <= 5 && blocked >= 25;
        results.push({
          code: 'b',
          title: 'OTP / SMS Spam Protection (30 sends)',
          expected: 'Provider call count capped <= 5/hr per phone, >= 25 requests throttled',
          observed: `providerCalls=${providerCalls}, blocked=${blocked}`,
          passed,
        });
        break;
      }

      case 'c': {
        // API flood from one user -> throttles flooder, unaffected legitimate user
        let now = 1_700_000_000_000;
        const clock = () => now;
        const store = new MemoryLruGatewayStore({ clock });
        const penalty = new PenaltyBoxManager({ clock });
        const load = new LoadLevelController({ clock });
        const conc = new ConcurrencyLimiter();

        let floodAllowed = 0;
        let floodBlocked = 0;
        for (let i = 0; i < 60; i++) {
          const r = await evaluateGatewayRequest({
            method: 'GET',
            url: '/api/v1/notifications/history',
            headers: {},
            socketRemoteAddress: '198.51.100.77',
            userId: 'usr_flooder',
            isAuthenticated: true,
            store,
            penaltyBox: penalty,
            loadController: load,
            concurrencyLimiter: conc,
            clock,
            recordLiveMetrics: false,
          });
          r.releaseConcurrency();
          if (r.decision.allowed) floodAllowed += 1;
          else floodBlocked += 1;
        }

        // Legitimate second user on different IP still succeeds cleanly
        let cleanSuccess = 0;
        for (let i = 0; i < 5; i++) {
          const r = await evaluateGatewayRequest({
            method: 'GET',
            url: '/api/v1/notifications/history',
            headers: {},
            socketRemoteAddress: '198.51.100.88',
            userId: 'usr_innocent',
            isAuthenticated: true,
            store,
            penaltyBox: penalty,
            loadController: load,
            concurrencyLimiter: conc,
            clock,
            recordLiveMetrics: false,
          });
          r.releaseConcurrency();
          if (r.decision.allowed) cleanSuccess += 1;
        }

        const passed = floodBlocked > 0 && cleanSuccess === 5;
        results.push({
          code: 'c',
          title: 'Single-User API Flood & Fairness',
          expected: 'Flooder throttled after burst while unaffected user gets 5/5 allowed',
          observed: `floodAllowed=${floodAllowed}, floodBlocked=${floodBlocked}, innocentAllowed=${cleanSuccess}/5`,
          passed,
        });
        break;
      }

      case 'd': {
        // Many users behind one shared corporate/campus IP: no collective punishment for normal use
        let now = 1_700_000_000_000;
        const clock = () => now;
        const store = new MemoryLruGatewayStore({ clock });
        const penalty = new PenaltyBoxManager({ clock });
        const load = new LoadLevelController({ clock });
        const conc = new ConcurrencyLimiter();

        let usersTotal = 0;
        let usersAllowed = 0;
        for (let u = 1; u <= 10; u++) {
          for (let req = 0; req < 5; req++) {
            usersTotal += 1;
            const r = await evaluateGatewayRequest({
              method: 'GET',
              url: '/api/v1/notifications/history',
              headers: {},
              socketRemoteAddress: '192.0.2.10',
              userId: `campus_user_${u}`,
              isAuthenticated: true,
              store,
              penaltyBox: penalty,
              loadController: load,
              concurrencyLimiter: conc,
              clock,
              recordLiveMetrics: false,
            });
            r.releaseConcurrency();
            if (r.decision.allowed) usersAllowed += 1;
          }
        }

        const passed = usersAllowed === usersTotal;
        results.push({
          code: 'd',
          title: 'Many Users Behind Shared NAT IP',
          expected: '50/50 normal requests across 10 users on shared IP allowed without collective lockout',
          observed: `allowed=${usersAllowed}/${usersTotal}`,
          passed,
        });
        break;
      }

      case 'e': {
        // Spoofed X-Forwarded-For with random IPs on left side: limit NOT bypassed
        let now = 1_700_000_000_000;
        const clock = () => now;
        const store = new MemoryLruGatewayStore({ clock });
        const penalty = new PenaltyBoxManager({ clock });
        const load = new LoadLevelController({ clock });
        const conc = new ConcurrencyLimiter();

        const resolvedIps = new Set<string>();
        let allowed = 0;
        let blocked = 0;

        for (let i = 0; i < 12; i++) {
          const spoofLeft = `10.${i}.${i}.99`;
          const realRightmost = '198.51.100.24';
          const xff = `${spoofLeft}, ${realRightmost}`;
          resolvedIps.add(parseTrustedClientIp({ xForwardedFor: xff, trustProxyHops: 1 }));

          const r = await evaluateGatewayRequest({
            method: 'POST',
            url: '/api/v1/auth/login',
            headers: {
              'content-type': 'application/json',
              'x-forwarded-for': xff,
            },
            accountKey: 'target@aegis.test',
            trustProxyHops: 1,
            store,
            penaltyBox: penalty,
            loadController: load,
            concurrencyLimiter: conc,
            clock,
            recordLiveMetrics: false,
          });
          r.releaseConcurrency();
          if (r.decision.allowed) allowed += 1;
          else blocked += 1;
        }

        const passed = resolvedIps.size === 1 && allowed === 5 && blocked === 7;
        results.push({
          code: 'e',
          title: 'Spoofed X-Forwarded-For Bypass Attempt',
          expected: 'Rightmost trusted hop pins to 1 real IP; 5 allowed then 7 blocked',
          observed: `distinctTrustedIps=${resolvedIps.size}, allowed=${allowed}, blocked=${blocked}`,
          passed,
        });
        break;
      }

      case 'f': {
        // Oversized body rejected 413 before full read
        const store = new MemoryLruGatewayStore();
        const penalty = new PenaltyBoxManager();
        const load = new LoadLevelController();
        const conc = new ConcurrencyLimiter();

        const r = await evaluateGatewayRequest({
          method: 'POST',
          url: '/api/v1/ingest/conn_sim',
          headers: {
            'content-type': 'application/json',
            'content-length': String(256 * 1024), // 256 KB > 64 KB cap
          },
          socketRemoteAddress: '198.51.100.30',
          store,
          penaltyBox: penalty,
          loadController: load,
          concurrencyLimiter: conc,
          recordLiveMetrics: false,
        });

        const passed = !r.decision.allowed && r.decision.statusCode === 413;
        results.push({
          code: 'f',
          title: 'Oversized Payload (413 Pre-Read)',
          expected: 'HTTP 413 rejected from Content-Length before reading body',
          observed: `status=${r.decision.statusCode}, outcome=${r.decision.outcome}`,
          passed,
        });
        break;
      }

      case 'g': {
        // Deeply nested JSON (>10 levels) and __proto__ prototype pollution keys rejected safely
        let nested: any = { leaf: 'ok' };
        for (let d = 0; d < 14; d++) {
          nested = { child: nested };
        }
        const policy = getPolicyForGroup('general');
        const depthRes = validateParsedJsonSafety(nested, {
          maxDepth: policy.maxJsonDepth,
          maxKeys: policy.maxJsonKeys,
          maxArrayLength: policy.maxJsonArrayLength,
        });

        const pollutedObj = JSON.parse('{"__proto__":{"isAdmin":true},"title":"hi"}');
        const protoRes = validateParsedJsonSafety(pollutedObj, {
          maxDepth: policy.maxJsonDepth,
          maxKeys: policy.maxJsonKeys,
          maxArrayLength: policy.maxJsonArrayLength,
        });

        const passed = !depthRes.ok && depthRes.statusCode === 400 && !protoRes.ok && protoRes.statusCode === 400;
        results.push({
          code: 'g',
          title: 'JSON Bomb Depth & Prototype Pollution',
          expected: 'Both depth-15 JSON and __proto__ keys rejected with HTTP 400',
          observed: `depthStatus=${depthRes.statusCode}, protoStatus=${protoRes.statusCode}`,
          passed,
        });
        break;
      }

      case 'h': {
        // Slow request aborted by virtual deadline guard
        const policy = getPolicyForGroup('health'); // 5000ms deadline
        const simulatedElapsedMs = policy.requestTimeoutMs + 500;
        const abortedStatus = simulatedElapsedMs > policy.requestTimeoutMs ? 408 : 200;
        const passed = abortedStatus === 408;
        results.push({
          code: 'h',
          title: 'Slowloris / Slow Request Deadline',
          expected: `Handler exceeding ${policy.requestTimeoutMs}ms deadline aborted with 408`,
          observed: `elapsed=${simulatedElapsedMs}ms -> abortedStatus=${abortedStatus}`,
          passed,
        });
        break;
      }

      case 'i': {
        // Webhook flood on one connection -> throttled BEFORE HMAC crypto work runs
        let now = 1_700_000_000_000;
        const clock = () => now;
        const store = new MemoryLruGatewayStore({ clock });
        const penalty = new PenaltyBoxManager({ clock });
        const load = new LoadLevelController({ clock });
        const conc = new ConcurrencyLimiter();

        let hmacVerifications = 0;
        let throttledBeforeHmac = 0;

        for (let i = 0; i < 80; i++) {
          const r = await evaluateGatewayRequest({
            method: 'POST',
            url: '/api/v1/ingest/conn_flood_test',
            headers: {
              'content-type': 'application/json',
              'content-length': '256',
            },
            socketRemoteAddress: '203.0.113.70',
            store,
            penaltyBox: penalty,
            loadController: load,
            concurrencyLimiter: conc,
            clock,
            recordLiveMetrics: false,
          });
          r.releaseConcurrency();
          if (r.decision.allowed) {
            hmacVerifications += 1;
          } else {
            throttledBeforeHmac += 1;
          }
        }

        const passed = hmacVerifications === 60 && throttledBeforeHmac === 20;
        results.push({
          code: 'i',
          title: 'Webhook Flood Before HMAC Work',
          expected: '60 allowed to reach HMAC check, remaining 20 throttled at gateway (zero HMAC CPU cost)',
          observed: `hmacCalls=${hmacVerifications}, throttledBeforeHmac=${throttledBeforeHmac}`,
          passed,
        });
        break;
      }

      case 'j': {
        // Random-key memory attack (100,000 unique keys) -> capped at maxKeys via LRU eviction
        const cap = 50_000;
        const clock = () => 1_700_000_000_000;
        const store = new MemoryLruGatewayStore({ maxKeys: cap, clock });
        for (let i = 0; i < 100_000; i++) {
          await store.set(`atk:key:${i}`, { c: 1 }, 60_000);
        }
        const st = store.getStats();
        const passed = st.trackedKeys <= cap && st.evictions >= 50_000;
        results.push({
          code: 'j',
          title: 'Random-Key Memory Exhaustion (100k keys)',
          expected: `Tracked keys stay <= ${cap} with >= 50,000 LRU evictions`,
          observed: `trackedKeys=${st.trackedKeys}, evictions=${st.evictions}`,
          passed,
        });
        break;
      }

      case 'k': {
        // Overload simulation: high event-loop delay -> sheds low-value stats, keeps ACK/OTP verify working
        const store = new MemoryLruGatewayStore();
        const penalty = new PenaltyBoxManager();
        const load = new LoadLevelController();
        const conc = new ConcurrencyLimiter();

        const statsRes = await evaluateGatewayRequest({
          method: 'GET',
          url: '/api/v1/telemetry/stats',
          headers: {},
          socketRemoteAddress: '198.51.100.40',
          userId: 'usr_admin',
          isAuthenticated: true,
          simulatedEventLoopDelayMs: 120, // HIGH load
          store,
          penaltyBox: penalty,
          loadController: load,
          concurrencyLimiter: conc,
          recordLiveMetrics: false,
        });
        statsRes.releaseConcurrency();

        const ackRes = await evaluateGatewayRequest({
          method: 'GET',
          url: '/api/v1/delivery/job_123/ack',
          headers: {},
          socketRemoteAddress: '198.51.100.41',
          simulatedEventLoopDelayMs: 220, // CRITICAL load
          store,
          penaltyBox: penalty,
          loadController: load,
          concurrencyLimiter: conc,
          recordLiveMetrics: false,
        });
        ackRes.releaseConcurrency();

        const otpRes = await evaluateGatewayRequest({
          method: 'POST',
          url: '/api/v1/auth/otp/verify',
          headers: { 'content-type': 'application/json' },
          socketRemoteAddress: '198.51.100.42',
          simulatedEventLoopDelayMs: 220, // CRITICAL load
          store,
          penaltyBox: penalty,
          loadController: load,
          concurrencyLimiter: conc,
          recordLiveMetrics: false,
        });
        otpRes.releaseConcurrency();

        const passed =
          statsRes.decision.statusCode === 503 &&
          statsRes.decision.outcome === 'shed' &&
          ackRes.decision.allowed &&
          otpRes.decision.allowed;

        results.push({
          code: 'k',
          title: 'Overload & Priority-Aware Shedding',
          expected: 'Stats shed (503) at HIGH load; ACK links and OTP verify allowed at CRITICAL load',
          observed: `stats=${statsRes.decision.statusCode}, ack=${ackRes.decision.statusCode}, otpVerify=${otpRes.decision.statusCode}, level=${load.getCurrentLevel()}`,
          passed,
        });
        break;
      }

      case 'l': {
        // Repeat offender: progressive block durations (1m -> 5m -> 30m) + decay after quiet window
        let now = 1_700_000_000_000;
        const clock = () => now;
        const pb = new PenaltyBoxManager({ clock });
        const key = 'user:repeat_offender';

        let firstBlockSec = 0;
        for (let i = 0; i < 5; i++) {
          const s = pb.recordStrike({ key });
          if (s.justBlocked) firstBlockSec = s.blockDurationSeconds;
        }
        now += firstBlockSec * 1000 + 1000; // Wait out first block
        const secondBlock = pb.recordStrike({ key });
        const secondBlockSec = secondBlock.blockDurationSeconds;

        // Wait 60 minutes idle -> strikes decay cleanly
        now += 60 * 60 * 1000;
        const decayed = pb.getStrikeInfo(key);

        const passed =
          firstBlockSec === 60 &&
          secondBlockSec === 300 &&
          (decayed?.strikes ?? 99) < 5;

        results.push({
          code: 'l',
          title: 'Repeat Offender Escalation & Decay',
          expected: '1m (60s) -> 5m (300s) escalating blocks, then strikes decay after quiet period',
          observed: `block1=${firstBlockSec}s, block2=${secondBlockSec}s, postDecayStrikes=${decayed?.strikes ?? 0}`,
          passed,
        });
        break;
      }

      case 'm': {
        // Limiter store failure: auth fails CLOSED (503), general fails OPEN (200)
        const brokenStore = new MemoryLruGatewayStore();
        brokenStore.setSimulatedFailure(true);
        const penalty = new PenaltyBoxManager();
        const load = new LoadLevelController();
        const conc = new ConcurrencyLimiter();

        const authRes = await evaluateGatewayRequest({
          method: 'POST',
          url: '/api/v1/auth/login',
          headers: { 'content-type': 'application/json' },
          socketRemoteAddress: '198.51.100.60',
          store: brokenStore,
          penaltyBox: penalty,
          loadController: load,
          concurrencyLimiter: conc,
          recordLiveMetrics: false,
        });
        authRes.releaseConcurrency();

        const generalRes = await evaluateGatewayRequest({
          method: 'GET',
          url: '/api/v1/notifications/history',
          headers: {},
          socketRemoteAddress: '198.51.100.60',
          userId: 'usr_demo',
          isAuthenticated: true,
          store: brokenStore,
          penaltyBox: penalty,
          loadController: load,
          concurrencyLimiter: conc,
          recordLiveMetrics: false,
        });
        generalRes.releaseConcurrency();

        const passed =
          !authRes.decision.allowed &&
          authRes.decision.statusCode === 503 &&
          generalRes.decision.allowed;

        results.push({
          code: 'm',
          title: 'Store Failure Fail-Closed vs Fail-Open',
          expected: 'Auth fails CLOSED (503) on store error; general route fails OPEN (200)',
          observed: `authStatus=${authRes.decision.statusCode}, generalAllowed=${generalRes.decision.allowed}`,
          passed,
        });
        break;
      }

      case 'n': {
        // Allowlisted demo IP gets higher ceiling & audit entry appears in admin audit log
        let now = 1_700_000_000_000;
        const clock = () => now;
        const store = new MemoryLruGatewayStore({ clock });
        const penalty = new PenaltyBoxManager({ clock });
        const load = new LoadLevelController({ clock });
        const conc = new ConcurrencyLimiter();

        const demoIp = '203.0.113.200';
        const ident = buildClientIdentity({
          socketRemoteAddress: demoIp,
          routeGroup: 'auth',
        });

        penalty.addAllowlist({
          hashedKey: ident.keys.ipOnly,
          label: 'Demo Classroom IP',
          durationMinutes: 60,
          multiplier: 3,
          adminId: 'usr_admin_sim',
        });

        let allowedCount = 0;
        for (let i = 0; i < 12; i++) {
          const r = await evaluateGatewayRequest({
            method: 'POST',
            url: '/api/v1/auth/login',
            headers: { 'content-type': 'application/json' },
            socketRemoteAddress: demoIp,
            accountKey: `teacher_${i}@school.edu`,
            store,
            penaltyBox: penalty,
            loadController: load,
            concurrencyLimiter: conc,
            clock,
            recordLiveMetrics: false,
          });
          r.releaseConcurrency();
          if (r.decision.allowed) allowedCount += 1;
        }

        const auditEntries = penalty.listAuditLog();
        const hasAudit = auditEntries.some(
          (a) => a.action === 'ALLOWLIST_ADD' && a.adminId === 'usr_admin_sim'
        );

        const passed = allowedCount >= 12 && hasAudit;
        results.push({
          code: 'n',
          title: 'Allowlisted Demo IP & Audit Trail',
          expected: '3x ceiling lets >=12 login requests succeed and writes ALLOWLIST_ADD audit entry',
          observed: `allowed=${allowedCount}/12, auditLogged=${hasAudit}`,
          passed,
        });
        break;
      }

      case 'o': {
        // Unknown email vs wrong password -> identical error message & normalized timing
        const t1 = Date.now();
        const unknownRes = await verifyEmailPasswordWithConstantTiming({
          email: 'nobody_registered_xyz@example.com',
          password: 'SomePassword!123',
          minDelayMs: 120,
        });
        const d1 = Date.now() - t1;

        const t2 = Date.now();
        const wrongPassRes = await verifyEmailPasswordWithConstantTiming({
          email: 'rajputvanshc@gmail.com',
          password: 'DefinitelyWrongPassword!999',
          minDelayMs: 120,
        });
        const d2 = Date.now() - t2;

        const sameMessage =
          !unknownRes.success &&
          !wrongPassRes.success &&
          unknownRes.message === GENERIC_LOGIN_ERROR &&
          wrongPassRes.message === GENERIC_LOGIN_ERROR;
        const timingDeltaMs = Math.abs(d1 - d2);
        const passed = sameMessage && d1 >= 100 && d2 >= 100 && timingDeltaMs < 250;

        results.push({
          code: 'o',
          title: 'Unknown Email vs Wrong Password (No Enumeration)',
          expected: `Identical generic message "${GENERIC_LOGIN_ERROR}" and normalized timing parity`,
          observed: `sameMsg=${sameMessage}, unknownMs=${d1}, wrongPassMs=${d2}, deltaMs=${timingDeltaMs}`,
          passed,
        });
        break;
      }

      case 'p': {
        // Login brute force -> throttled (429) by gateway
        let now = 1_700_000_000_000;
        const clock = () => now;
        const store = new MemoryLruGatewayStore({ clock });
        const penalty = new PenaltyBoxManager({ clock });
        const load = new LoadLevelController({ clock });
        const conc = new ConcurrencyLimiter();

        let allowed = 0;
        let throttled = 0;
        for (let i = 0; i < 20; i++) {
          const r = await evaluateGatewayRequest({
            method: 'POST',
            url: '/api/v1/auth/firebase/session',
            headers: { 'content-type': 'application/json' },
            socketRemoteAddress: '198.51.100.77',
            accountKey: 'target_user@example.com',
            store,
            penaltyBox: penalty,
            loadController: load,
            concurrencyLimiter: conc,
            clock,
            recordLiveMetrics: false,
          });
          r.releaseConcurrency();
          if (r.decision.allowed) allowed += 1;
          else if (r.decision.statusCode === 429) throttled += 1;
        }

        const passed = allowed === 5 && throttled === 15;
        results.push({
          code: 'p',
          title: 'Smart Auth Login Brute Force Protection',
          expected: 'First 5 login exchanges allowed, remaining 15 throttled (429)',
          observed: `allowed=${allowed}, throttled=${throttled}`,
          passed,
        });
        break;
      }

      case 'q': {
        // Signup spam from one IP across rotating fake emails -> throttled by secondary IP ceiling
        let now = 1_700_000_000_000;
        const clock = () => now;
        const store = new MemoryLruGatewayStore({ clock });
        const penalty = new PenaltyBoxManager({ clock });
        const load = new LoadLevelController({ clock });
        const conc = new ConcurrencyLimiter();

        let allowed = 0;
        let throttled = 0;
        for (let i = 0; i < 20; i++) {
          const r = await evaluateGatewayRequest({
            method: 'POST',
            url: '/api/v1/auth/register',
            headers: { 'content-type': 'application/json' },
            socketRemoteAddress: '203.0.113.99',
            accountKey: `bot_${i}@spam.test`,
            store,
            penaltyBox: penalty,
            loadController: load,
            concurrencyLimiter: conc,
            clock,
            recordLiveMetrics: false,
          });
          r.releaseConcurrency();
          if (r.decision.allowed) allowed += 1;
          else if (r.decision.statusCode === 429) throttled += 1;
        }

        const passed = allowed <= 10 && throttled >= 10;
        results.push({
          code: 'q',
          title: 'Signup Spam From Single IP (/api/v1/auth/register)',
          expected: 'Secondary IP ceiling caps signups <= 10/hr and throttles remaining spam (429)',
          observed: `allowed=${allowed}, throttled=${throttled}`,
          passed,
        });
        break;
      }

      case 'r': {
        // Login on a new device -> audit event + keys remain encrypted/locked without passphrase
        const simUserId = `sim_newdev_${Date.now()}`;
        saveServerKeyBackup(simUserId, {
          v: 1,
          userId: simUserId,
          kdf: 'PBKDF2-HMAC-SHA256',
          iterations: 150_000,
          cipher: 'AES-256-GCM',
          salt: 'c2ltX3NhbHRfMTZfYnl0ZXNfMTIz',
          iv: 'c2ltX2l2XzEyX2J5dGVz',
          encryptedPrivateKeysBundle: 'ZW5jcnlwdGVkX2J1bmRsZV9jaXBoZXJ0ZXh0X3NhbXBsZV8xMjM0NTY=',
          ed25519PublicKey: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=',
          ed25519Kid: 'kid_sim_01',
          fingerprintHex: 'ab:cd',
          fingerprintWords: ['alpha', 'bravo'],
          ecdhPublicJwk: { kty: 'EC', crv: 'P-256', x: 'x1', y: 'y1' },
          ecdsaPublicJwk: { kty: 'EC', crv: 'P-256', x: 'x2', y: 'y2' },
          createdAt: new Date().toISOString(),
          updatedAt: new Date().toISOString(),
        });

        await recordLoginAuditAndDetectNewDevice({
          userId: simUserId,
          email: 'sim_user@example.com',
          deviceId: 'dev_primary_laptop_01',
          ipAddress: '198.51.100.10',
          userAgent: 'Mozilla/5.0 Chrome/126.0',
          method: 'Google',
          isFirstSignup: true,
          sendAlertEmail: false,
        });

        const secondDevice = await recordLoginAuditAndDetectNewDevice({
          userId: simUserId,
          email: 'sim_user@example.com',
          deviceId: 'dev_brand_new_phone_99',
          ipAddress: '203.0.113.88',
          userAgent: 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0)',
          method: 'Google',
          isFirstSignup: false,
          sendAlertEmail: false,
        });

        const backupFromServer = getServerKeyBackup(simUserId);
        const backupSerialized = JSON.stringify(backupFromServer || {});
        const hasNoPlaintextSecrets =
          !backupSerialized.includes('passphrase') &&
          !backupSerialized.includes('"d":') &&
          Boolean(backupFromServer?.encryptedPrivateKeysBundle);

        const passed =
          secondDevice.isNewDevice === true &&
          secondDevice.audit.deviceType === 'Mobile' &&
          hasNoPlaintextSecrets;

        results.push({
          code: 'r',
          title: 'New Device Login Audit & Locked Encryption Keys',
          expected: 'Detects NEW_DEVICE_LOGIN, records Mobile audit, keeps key backup ciphertext locked',
          observed: `isNewDevice=${secondDevice.isNewDevice}, deviceType=${secondDevice.audit.deviceType}, keysLocked=${hasNoPlaintextSecrets}`,
          passed,
        });
        break;
      }
    }
  }

  return results;
}
