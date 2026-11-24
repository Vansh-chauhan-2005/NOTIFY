import { describe, it, expect, beforeEach } from 'vitest';
import jwt from 'jsonwebtoken';
import { getJwtSecret } from '../../auth/jwtSecret.js';
import { preprocessNotificationText } from '../preprocess.js';
import {
  buildWordShingles,
  computeMinHashSignature,
  cosineSimilarity,
  jaccardSimilarity,
  l2Normalize,
  minHashSimilarity,
  sha256HexSync,
} from '../similarity.js';
import { computeTfIdfPairSimilarity } from '../tfidf.js';
import { evaluateAllMergeGuards, extractEntities } from '../guards.js';
import { InMemoryDedupWindow, type TextEmbedderFn } from '../pipeline.js';
import {
  assertNoPlaintextOrVectors,
  clearDedupStoreForTests,
  getDedupStatsSnapshot,
  getUserDedupSettings,
  recordDedupFeedback,
} from '../store.js';
import { runDedupSimulationSuite } from '../simulator.js';
import { DEFAULT_DEDUP_CONFIG } from '../config.js';
import { GET as getConfigRoute, PUT as putConfigRoute } from '../../../app/api/v1/dedup/config/route.js';
import { POST as postFeedbackRoute } from '../../../app/api/v1/dedup/feedback/route.js';
import { GET as getThreadsRoute, POST as postThreadsRoute } from '../../../app/api/v1/dedup/threads/route.js';
import { POST as postUngroupRoute } from '../../../app/api/v1/dedup/threads/[id]/ungroup/route.js';
import { GET as getStatsRoute } from '../../../app/api/v1/dedup/stats/route.js';
import { POST as postSimulateRoute } from '../../../app/api/v1/dedup/simulate/route.js';

function makeToken(userId: string, role: 'USER' | 'ADMIN' = 'USER'): string {
  return jwt.sign({ userId, role, email: `${userId}@example.com` }, getJwtSecret(), {
    expiresIn: '1h',
  });
}

function makeFixedEmbedder(vecMap: Record<string, number[]>): TextEmbedderFn {
  return async (text: string) => {
    for (const [needle, vec] of Object.entries(vecMap)) {
      if (text.toLowerCase().includes(needle.toLowerCase())) {
        return { embedding: l2Normalize(vec), mode: 'onnx_minilm' };
      }
    }
    const fallback = new Array<number>(384).fill(0);
    for (let i = 0; i < text.length; i++) {
      fallback[(text.charCodeAt(i) * 17 + i) % 384] += 1;
    }
    return { embedding: l2Normalize(fallback), mode: 'onnx_minilm' };
  };
}

describe('Semantic Deduplication Engine — Preprocessing, Math, Guards, Pipeline & API', () => {
  beforeEach(() => {
    clearDedupStoreForTests();
  });

  it('normalizes Unicode NFKC, strips zero-width chars, detects mixed script, and caps tokens', () => {
    const dirty = 'Ｓｅｒｖｅｒ\u200B\u200D down\x00   on  api! [Attachment: crash.log]';
    const res = preprocessNotificationText(dirty);
    expect(res.hadZeroWidthOrControl).toBe(true);
    expect(res.normalizedText).not.toContain('\u200b');
    expect(res.normalizedText).not.toContain('[attachment');
    expect(res.normalizedText).toContain('server down on api');

    const homoglyph = preprocessNotificationText('S\u0435rver down on prod');
    expect(homoglyph.hadMixedScript).toBe(true);

    const hindi = preprocessNotificationText('Production server बंद है');
    expect(hindi.tokens.length).toBeGreaterThanOrEqual(4);

    const longText = Array.from({ length: 400 }, (_, i) => `tok${i}`).join(' ');
    const capped = preprocessNotificationText(longText, 256);
    expect(capped.truncated).toBe(true);
    expect(capped.tokens.length).toBe(256);
  });

  it('computes L2 normalization and cosine similarity within mathematical bounds', () => {
    const unit = l2Normalize([3, 4, 0]);
    const norm = Math.hypot(...unit);
    expect(norm).toBeCloseTo(1, 6);

    expect(cosineSimilarity(unit, unit)).toBeCloseTo(1, 6);
    expect(cosineSimilarity([1, 0, 0], [0, 1, 0])).toBeCloseTo(0, 6);
    expect(cosineSimilarity([], [])).toBe(0);
    expect(cosineSimilarity([0, 0, 0], [1, 0, 0])).toBe(0);
  });

  it('computes deterministic SHA-256, MinHash, Jaccard, and TF-IDF fallback scores', () => {
    expect(sha256HexSync('hello')).toBe(sha256HexSync('hello'));
    expect(sha256HexSync('hello')).not.toBe(sha256HexSync('world'));

    const a = preprocessNotificationText('production database connection pool exhausted').tokens;
    const b = preprocessNotificationText('production database connection pool almost exhausted').tokens;
    const shA = buildWordShingles(a, 2);
    const shB = buildWordShingles(b, 2);
    expect(jaccardSimilarity(shA, shB)).toBeGreaterThan(0.4);
    expect(minHashSimilarity(computeMinHashSignature(shA, 64), computeMinHashSignature(shB, 64))).toBeGreaterThan(0.4);

    const tfidfSame = computeTfIdfPairSimilarity(
      'database connection pool exhausted on primary',
      'primary database connection pool exhausted'
    );
    const tfidfDiff = computeTfIdfPairSimilarity(
      'database connection pool exhausted on primary',
      'weekly cafeteria lunch menu updated'
    );
    expect(tfidfSame).toBeGreaterThan(0.8);
    expect(tfidfDiff).toBeLessThan(0.2);
  });

  it('blocks merges across Rs 500 vs Rs 50,000, different OTPs, negation state flips, CRITICAL alerts, and UNVERIFIED provenance', () => {
    const e1 = extractEntities('Payment debited Rs 500 at Metro Store Ref TXN-1001');
    expect(e1.currenciesAndNumbers.length).toBeGreaterThan(0);
    expect(e1.codesAndIds.length).toBeGreaterThan(0);

    const amountGuard = evaluateAllMergeGuards({
      incoming: {
        notificationId: 'n2',
        userId: 'u1',
        sourceId: 'bank',
        senderId: 'hdfc',
        category: 'finance',
        priority: 'HIGH',
        trust: 'VERIFIED',
      },
      incomingText: 'Payment debited Rs 50,000 at Metro Store',
      candidateThread: {
        threadId: 't1',
        userId: 'u1',
        createdAt: new Date().toISOString(),
        lastMemberAt: new Date().toISOString(),
        memberCount: 1,
        memberIds: ['n1'],
        sourceId: 'bank',
        senderId: 'hdfc',
        category: 'finance',
        topPriority: 'HIGH',
        lowestTrust: 'VERIFIED',
        status: 'ACTIVE',
        stageMatched: 'NONE',
        lastSimilarity: 0,
      },
      candidateLatestText: 'payment debited rs 500 at metro store',
      neverMergeCategories: DEFAULT_DEDUP_CONFIG.neverMergeCategories,
    });
    expect(amountGuard.allowedToMerge).toBe(false);
    expect(amountGuard.blockedByGuard).toBe('ENTITY_CONFLICT');

    const negationGuard = evaluateAllMergeGuards({
      incoming: {
        notificationId: 'n3',
        userId: 'u1',
        sourceId: 'datadog',
        senderId: 'ops',
        category: 'work',
        priority: 'MEDIUM',
        trust: 'VERIFIED',
      },
      incomingText: 'Production API server recovered',
      candidateThread: {
        threadId: 't2',
        userId: 'u1',
        createdAt: new Date().toISOString(),
        lastMemberAt: new Date().toISOString(),
        memberCount: 1,
        memberIds: ['n0'],
        sourceId: 'datadog',
        senderId: 'ops',
        category: 'work',
        topPriority: 'HIGH',
        lowestTrust: 'VERIFIED',
        status: 'ACTIVE',
        stageMatched: 'NONE',
        lastSimilarity: 0,
      },
      candidateLatestText: 'production api server is down',
      neverMergeCategories: DEFAULT_DEDUP_CONFIG.neverMergeCategories,
    });
    expect(negationGuard.allowedToMerge).toBe(false);
    expect(negationGuard.blockedByGuard).toBe('NEGATION_STATE_CONFLICT');
    expect(negationGuard.isResolutionUpdate).toBe(true);
    expect(negationGuard.linkRelatedOnly).toBe(true);

    // Imported opposite_state_pairs from dedupConfig.json (e.g. debited vs credited, cancelled vs confirmed)
    const finOppGuard = evaluateAllMergeGuards({
      incoming: {
        notificationId: 'n4',
        userId: 'u1',
        sourceId: 'bank',
        senderId: 'hdfc',
        category: 'finance',
        priority: 'HIGH',
        trust: 'VERIFIED',
      },
      incomingText: 'Account credited at Metro Store',
      candidateThread: {
        threadId: 't1',
        userId: 'u1',
        createdAt: new Date().toISOString(),
        lastMemberAt: new Date().toISOString(),
        memberCount: 1,
        memberIds: ['n1'],
        sourceId: 'bank',
        senderId: 'hdfc',
        category: 'finance',
        topPriority: 'HIGH',
        lowestTrust: 'VERIFIED',
        status: 'ACTIVE',
        stageMatched: 'NONE',
        lastSimilarity: 0,
      },
      candidateLatestText: 'account debited at metro store',
      neverMergeCategories: DEFAULT_DEDUP_CONFIG.neverMergeCategories,
    });
    expect(finOppGuard.allowedToMerge).toBe(false);
    expect(finOppGuard.blockedByGuard).toBe('NEGATION_STATE_CONFLICT');
  });

  it('groups paraphrases in volatile RAM window, enforces bounded window & per-source cap, escalates priority, and wipes on ungroup/ephemeral/logout', async () => {
    const win = new InMemoryDedupWindow();
    const outVec = Array.from({ length: 384 }, (_, i) => (i === 0 ? 1 : 0));
    const embedder = makeFixedEmbedder({
      'server down': outVec,
      'unreachable': outVec,
      'not responding': outVec,
    });

    const r1 = await win.processNotification({
      incoming: {
        notificationId: 'm1',
        userId: 'u_pipe',
        sourceId: 'datadog',
        senderId: 'bot',
        category: 'work',
        priority: 'MEDIUM',
        trust: 'VERIFIED',
        timestampMs: 1_000_000,
      },
      rawTextInMemory: 'Server down',
      embedder,
    });
    const r2 = await win.processNotification({
      incoming: {
        notificationId: 'm2',
        userId: 'u_pipe',
        sourceId: 'datadog',
        senderId: 'bot',
        category: 'work',
        priority: 'HIGH',
        trust: 'VERIFIED',
        timestampMs: 1_010_000,
      },
      rawTextInMemory: 'Production server unreachable',
      embedder,
    });
    expect(r2.action).toBe('MERGE');
    expect(r2.threadId).toBe(r1.threadId);
    expect(r2.priorityEscalatedInThread).toBe(true);
    expect(r2.shouldSendBrowserNotification).toBe(true);
    expect(r2.threadMetadata.topPriority).toBe('HIGH');

    // Ungroup prevents immediate re-merge & splits cleanly
    const split = win.ungroupThread('u_pipe', r1.threadId);
    expect(split.length).toBe(2);

    // Ephemeral item gets immediately wiped on wipeEphemeralItem
    const eph = await win.processNotification({
      incoming: {
        notificationId: 'eph_1',
        userId: 'u_pipe',
        sourceId: 'vault',
        senderId: 'alice',
        category: 'work',
        priority: 'MEDIUM',
        trust: 'VERIFIED',
        isEphemeral: true,
        timestampMs: 1_020_000,
      },
      rawTextInMemory: 'Temporary incident password reset notice',
      embedder,
    });
    expect(eph.threadMetadata.containsEphemeral).toBe(true);
    expect(win.wipeEphemeralItem('u_pipe', 'eph_1')).toBe(1);
    expect(win.getThreadForNotification('u_pipe', 'eph_1')).toBeNull();

    // Bounded window eviction & clearUser
    for (let i = 0; i < 6; i++) {
      await win.processNotification({
        incoming: {
          notificationId: `cap_${i}`,
          userId: 'u_cap',
          sourceId: 'burst-app',
          senderId: 'sender',
          category: 'work',
          priority: 'LOW',
          trust: 'VERIFIED',
          timestampMs: 2_000_000 + i * 100,
        },
        rawTextInMemory: `Unique unrelated burst notification token_${i}_xyz_${i * 97}`,
        embedder: async () => ({ embedding: null, mode: 'tfidf_lightweight' }),
        options: {
          maxWindowItems: 3,
          maxThreadsPerSourcePerHour: 4,
        },
      });
    }
    expect(win.countActiveItems('u_cap')).toBeLessThanOrEqual(3);
    win.clearUser('u_cap');
    expect(win.countActiveItems('u_cap')).toBe(0);
  });

  it('rejects any plaintext message body or embedding float vectors in metadata firewall', () => {
    expect(assertNoPlaintextOrVectors({ threadId: 'thr_1', memberCount: 2 }).ok).toBe(true);
    expect(assertNoPlaintextOrVectors({ rawText: 'secret alert' }).ok).toBe(false);
    expect(assertNoPlaintextOrVectors({ nested: { plaintext: 'hi' } }).ok).toBe(false);
    expect(assertNoPlaintextOrVectors({ vec: new Array(384).fill(0.05) }).ok).toBe(false);
  });

  it('loads imported dedupConfig.json thresholds (0.98 / 0.50 / 300s) and clamps user adaptation in [0.80, 0.98]', () => {
    expect(DEFAULT_DEDUP_CONFIG.recommendedThreshold).toBe(0.98);
    expect(DEFAULT_DEDUP_CONFIG.mergeThreshold).toBe(0.98);
    expect(DEFAULT_DEDUP_CONFIG.bestF1Threshold).toBe(0.5);
    expect(DEFAULT_DEDUP_CONFIG.dedupWindowSeconds).toBe(300);
    expect(DEFAULT_DEDUP_CONFIG.windowMinutes).toBe(5);
    expect(DEFAULT_DEDUP_CONFIG.guardrails.oppositeStatePairs.length).toBeGreaterThanOrEqual(11);
    expect(DEFAULT_DEDUP_CONFIG.benchmarkComparison.length).toBe(4);
    expect(DEFAULT_DEDUP_CONFIG.thresholdSweep.length).toBe(11);

    const emptyStats = getDedupStatsSnapshot();
    expect(emptyStats.itemsReceived).toBe(0);
    expect(emptyStats.suppressionRatePercent).toBeNull();

    const u = 'u_feedback_clamp';
    for (let i = 0; i < 20; i++) {
      recordDedupFeedback({ userId: u, feedbackKind: 'NOT_DUPLICATE' });
    }
    expect(getUserDedupSettings(u).effectiveMergeThreshold).toBeLessThanOrEqual(0.98);

    for (let i = 0; i < 40; i++) {
      recordDedupFeedback({ userId: u, feedbackKind: 'CONFIRM_MERGE' });
    }
    expect(getUserDedupSettings(u).effectiveMergeThreshold).toBeGreaterThanOrEqual(0.8);
  });

  it('enforces API auth, zero-vector firewall, admin demoMode guard, and full route roundtrip', async () => {
    const userToken = makeToken('user_api_1', 'USER');
    const adminToken = makeToken('admin_api_1', 'ADMIN');

    // Config GET & PUT
    const getCfgRes = await getConfigRoute(
      new Request('http://localhost/api/v1/dedup/config', {
        headers: { Authorization: `Bearer ${userToken}` },
      })
    );
    expect(getCfgRes.status).toBe(200);

    const putCfgRes = await putConfigRoute(
      new Request('http://localhost/api/v1/dedup/config', {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${userToken}`,
        },
        body: JSON.stringify({
          mergeThreshold: 0.9,
          reviewThreshold: 0.79,
          neverMergeCategories: ['finance'],
        }),
      })
    );
    const putJson = await putCfgRes.json();
    expect(putCfgRes.status).toBe(200);
    expect(putJson.data.settings.neverMergeCategories).toContain('security');
    expect(putJson.data.settings.neverMergeCategories).toContain('finance');

    // Threads POST rejects embedding vector
    const rejectedRes = await postThreadsRoute(
      new Request('http://localhost/api/v1/dedup/threads', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${userToken}`,
        },
        body: JSON.stringify({
          action: 'NEW_THREAD',
          embedding: new Array(384).fill(0.1),
          threadMetadata: { threadId: 'thr_bad', memberIds: ['n1'] },
        }),
      })
    );
    expect(rejectedRes.status).toBe(400);

    // Threads POST accepts clean metadata
    const okThreadRes = await postThreadsRoute(
      new Request('http://localhost/api/v1/dedup/threads', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${userToken}`,
        },
        body: JSON.stringify({
          action: 'MERGE',
          stageMatched: 'SEMANTIC_ONNX',
          similarity: 0.92,
          notificationId: 'n2',
          threadMetadata: {
            threadId: 'thr_ok_1',
            memberCount: 2,
            memberIds: ['n1', 'n2'],
            sourceId: 'datadog',
            senderId: 'bot',
            category: 'work',
            topPriority: 'HIGH',
            lowestTrust: 'VERIFIED',
            status: 'ACTIVE',
          },
        }),
      })
    );
    expect(okThreadRes.status).toBe(200);

    const listRes = await getThreadsRoute(
      new Request('http://localhost/api/v1/dedup/threads', {
        headers: { Authorization: `Bearer ${userToken}` },
      })
    );
    const listJson = await listRes.json();
    expect(listJson.data.threads.some((t: any) => t.threadId === 'thr_ok_1')).toBe(true);

    // Feedback & Ungroup
    const fbRes = await postFeedbackRoute(
      new Request('http://localhost/api/v1/dedup/feedback', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${userToken}`,
        },
        body: JSON.stringify({ feedbackKind: 'NOT_DUPLICATE', threadId: 'thr_ok_1' }),
      })
    );
    expect(fbRes.status).toBe(200);

    const ungRes = await postUngroupRoute(
      new Request('http://localhost/api/v1/dedup/threads/thr_ok_1/ungroup', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${userToken}`,
        },
        body: JSON.stringify({}),
      }),
      { params: Promise.resolve({ id: 'thr_ok_1' }) }
    );
    expect(ungRes.status).toBe(200);

    // Admin stats & simulation demoMode guard
    const userStatsRes = await getStatsRoute(
      new Request('http://localhost/api/v1/dedup/stats', {
        headers: { Authorization: `Bearer ${userToken}` },
      })
    );
    expect(userStatsRes.status).toBe(403);

    const adminStatsRes = await getStatsRoute(
      new Request('http://localhost/api/v1/dedup/stats', {
        headers: { Authorization: `Bearer ${adminToken}` },
      })
    );
    expect(adminStatsRes.status).toBe(200);

    const simNoDemo = await postSimulateRoute(
      new Request('http://localhost/api/v1/dedup/simulate', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${adminToken}`,
        },
        body: JSON.stringify({ demoMode: false }),
      })
    );
    expect(simNoDemo.status).toBe(400);
  });

  it('passes all 13 isolated simulator scenarios (a through m)', async () => {
    const scenarios = await runDedupSimulationSuite();
    expect(scenarios.length).toBe(13);
    for (const s of scenarios) {
      expect(s.passed, `Scenario ${s.code} (${s.title}) failed: ${s.observed}`).toBe(true);
    }
  });
});
