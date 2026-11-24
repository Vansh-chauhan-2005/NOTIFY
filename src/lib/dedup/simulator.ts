import { InMemoryDedupWindow, type TextEmbedderFn } from './pipeline.js';
import { cosineSimilarity, l2Normalize } from './similarity.js';
import {
  assertNoPlaintextOrVectors,
  getDedupStatsSnapshot,
  getUserDedupSettings,
  recordDedupFeedback,
  ungroupServerThread,
} from './store.js';
import { createDeliveryJob, getDeliveryJobById } from '../delivery/deliveryStore.js';
import { getSecurityEvents } from '../telemetry/securityLogger.js';
import type { DedupSimulationScenarioResult } from './types.js';

/**
 * Deterministic conceptual embedder used inside simulator scenarios so semantic paraphrases
 * are reliably tested offline without requiring remote Hugging Face network access.
 */
function createSimulatorConceptEmbedder(): TextEmbedderFn {
  const concepts: Array<{ key: string; patterns: RegExp[]; vec: number[] }> = [
    {
      key: 'server_down',
      patterns: [
        /\b(server|api|backend|prod|production)\b/i,
        /\b(down|unreachable|not responding|outage|timeout)\b/i,
      ],
      vec: makeBasisVector(1),
    },
    {
      key: 'recovered_server',
      patterns: [
        /\b(server|api|backend|prod|production)\b/i,
        /\b(recovered|resolved|back up|healthy|restored)\b/i,
      ],
      vec: makeBasisVector(1, 0.96, 2, 0.25),
    },
    {
      key: 'payment_alert',
      patterns: [/\b(payment|debited|rs|inr|transfer|metro)\b/i],
      vec: makeBasisVector(3),
    },
    {
      key: 'otp_alert',
      patterns: [/\b(otp|verification|code|login)\b/i],
      vec: makeBasisVector(4),
    },
    {
      key: 'lunch_menu',
      patterns: [/\b(lunch|menu|cafeteria|weekly|food)\b/i],
      vec: makeBasisVector(5),
    },
  ];

  return async (normalizedText: string) => {
    for (const c of concepts) {
      if (c.patterns.every((re) => re.test(normalizedText))) {
        return { embedding: c.vec, mode: 'mock_embedder' };
      }
    }
    return { embedding: makeHashBasis(normalizedText), mode: 'mock_embedder' };
  };
}

function makeBasisVector(
  dimA: number,
  wA = 1,
  dimB?: number,
  wB = 0
): number[] {
  const v = new Array<number>(384).fill(0);
  v[dimA] = wA;
  if (typeof dimB === 'number') v[dimB] = wB;
  return l2Normalize(v);
}

function makeHashBasis(text: string): number[] {
  const v = new Array<number>(384).fill(0);
  for (let i = 0; i < text.length; i++) {
    v[(text.charCodeAt(i) * 31 + i) % 384] += 1;
  }
  return l2Normalize(v);
}

export async function runDedupSimulationSuite(options: {
  scenario?: string;
} = {}): Promise<DedupSimulationScenarioResult[]> {
  const simUser = `sim_dedup_${Date.now()}`;
  const embedder = createSimulatorConceptEmbedder();
  const target = options.scenario?.toLowerCase();
  const results: DedupSimulationScenarioResult[] = [];
  const shouldRun = (code: string) => !target || target === 'all' || target === code;

  // (a) Exact duplicate -> merged
  if (shouldRun('a')) {
    const win = new InMemoryDedupWindow();
    const d1 = await win.processNotification({
      incoming: {
        notificationId: 'sim_a1',
        userId: simUser,
        sourceId: 'pagerduty',
        senderId: 'ops-bot',
        category: 'work',
        priority: 'HIGH',
        trust: 'VERIFIED',
      },
      rawTextInMemory: 'API gateway returning 502 bad gateway',
      embedder,
    });
    const d2 = await win.processNotification({
      incoming: {
        notificationId: 'sim_a2',
        userId: simUser,
        sourceId: 'pagerduty',
        senderId: 'ops-bot',
        category: 'work',
        priority: 'HIGH',
        trust: 'VERIFIED',
      },
      rawTextInMemory: '  API\u200B  gateway returning 502 bad gateway ',
      embedder,
    });
    results.push({
      code: 'a',
      title: 'Exact Duplicate -> Merged',
      expected: 'MERGE via EXACT (100% similarity)',
      observed: `${d2.action} via ${d2.stageMatched} (${Math.round(d2.similarity * 100)}%, members=${d2.threadMetadata.memberCount})`,
      passed:
        d1.action === 'NEW_THREAD' &&
        d2.action === 'MERGE' &&
        d2.stageMatched === 'EXACT' &&
        d2.threadId === d1.threadId,
      similarity: d2.similarity,
      stage: d2.stageMatched,
    });
  }

  // (b) Semantic paraphrase ("Server down" / "Production server unreachable" / "Prod API not responding") -> merged
  if (shouldRun('b')) {
    const win = new InMemoryDedupWindow();
    const s1 = await win.processNotification({
      incoming: {
        notificationId: 'sim_b1',
        userId: simUser,
        sourceId: 'datadog',
        senderId: 'infra-monitor',
        category: 'work',
        priority: 'HIGH',
        trust: 'VERIFIED',
      },
      rawTextInMemory: 'Server down',
      embedder,
    });
    const s2 = await win.processNotification({
      incoming: {
        notificationId: 'sim_b2',
        userId: simUser,
        sourceId: 'datadog',
        senderId: 'infra-monitor',
        category: 'work',
        priority: 'HIGH',
        trust: 'VERIFIED',
      },
      rawTextInMemory: 'Production server unreachable',
      embedder,
    });
    const s3 = await win.processNotification({
      incoming: {
        notificationId: 'sim_b3',
        userId: simUser,
        sourceId: 'datadog',
        senderId: 'infra-monitor',
        category: 'work',
        priority: 'HIGH',
        trust: 'VERIFIED',
      },
      rawTextInMemory: 'Prod API not responding',
      embedder,
    });
    results.push({
      code: 'b',
      title: 'Semantic Paraphrase ("Server down" / "Production server unreachable" / "Prod API not responding")',
      expected: 'All 3 grouped into 1 thread via semantic embedding',
      observed: `${s2.action}/${s3.action} (members=${s3.threadMetadata.memberCount}, sim=${Math.round(s3.similarity * 100)}%)`,
      passed:
        s2.action === 'MERGE' &&
        s3.action === 'MERGE' &&
        s3.threadMetadata.memberCount === 3 &&
        s2.threadId === s1.threadId &&
        s3.threadId === s1.threadId,
      similarity: s3.similarity,
      stage: s3.stageMatched,
    });
  }

  // (c) Unrelated notifications -> not merged
  if (shouldRun('c')) {
    const win = new InMemoryDedupWindow();
    const u1 = await win.processNotification({
      incoming: {
        notificationId: 'sim_c1',
        userId: simUser,
        sourceId: 'slack',
        senderId: 'ops-bot',
        category: 'work',
        priority: 'MEDIUM',
        trust: 'GATEWAY_ATTESTED',
      },
      rawTextInMemory: 'Production server down on edge node',
      embedder,
    });
    const u2 = await win.processNotification({
      incoming: {
        notificationId: 'sim_c2',
        userId: simUser,
        sourceId: 'slack',
        senderId: 'ops-bot',
        category: 'social',
        priority: 'LOW',
        trust: 'GATEWAY_ATTESTED',
      },
      rawTextInMemory: 'Weekly lunch menu posted for cafeteria',
      embedder,
    });
    results.push({
      code: 'c',
      title: 'Unrelated Notifications -> Separate Threads',
      expected: 'NEW_THREAD with low similarity (<0.78)',
      observed: `${u2.action} (sim=${u2.similarity}, distinct=${u2.threadId !== u1.threadId})`,
      passed: u2.action === 'NEW_THREAD' && u2.threadId !== u1.threadId && u2.similarity < 0.78,
      similarity: u2.similarity,
      stage: u2.stageMatched,
    });
  }

  // (d) Entity difference ("Rs 500" vs "Rs 50,000") -> blocked by ENTITY_CONFLICT guard
  if (shouldRun('d')) {
    const win = new InMemoryDedupWindow();
    const e1 = await win.processNotification({
      incoming: {
        notificationId: 'sim_d1',
        userId: simUser,
        sourceId: 'bank-feed',
        senderId: 'hdfc-webhook',
        category: 'finance',
        priority: 'HIGH',
        trust: 'VERIFIED',
      },
      rawTextInMemory: 'Payment debited Rs 500 at Metro Store',
      embedder,
    });
    const e2 = await win.processNotification({
      incoming: {
        notificationId: 'sim_d2',
        userId: simUser,
        sourceId: 'bank-feed',
        senderId: 'hdfc-webhook',
        category: 'finance',
        priority: 'HIGH',
        trust: 'VERIFIED',
      },
      rawTextInMemory: 'Payment debited Rs 50,000 at Metro Store',
      embedder,
    });
    results.push({
      code: 'd',
      title: 'Entity Difference Guard ("Rs 500" vs "Rs 50,000")',
      expected: 'Blocked by ENTITY_CONFLICT guard -> NEW_THREAD',
      observed: `${e2.action}, blocked=${e2.blockedByGuard}`,
      passed:
        e2.action === 'NEW_THREAD' &&
        e2.threadId !== e1.threadId &&
        e2.blockedByGuard === 'ENTITY_CONFLICT',
      similarity: e2.similarity,
      blockedGuard: e2.blockedByGuard,
    });
  }

  // (e) Different OTP codes -> never merged
  if (shouldRun('e')) {
    const win = new InMemoryDedupWindow();
    const o1 = await win.processNotification({
      incoming: {
        notificationId: 'sim_e1',
        userId: simUser,
        sourceId: 'auth-svc',
        senderId: 'auth-svc',
        category: 'otp',
        priority: 'HIGH',
        trust: 'VERIFIED',
        isOtpOrLoginOrKeyChange: true,
      },
      rawTextInMemory: 'Your login OTP code is 841290',
      embedder,
    });
    const o2 = await win.processNotification({
      incoming: {
        notificationId: 'sim_e2',
        userId: simUser,
        sourceId: 'auth-svc',
        senderId: 'auth-svc',
        category: 'otp',
        priority: 'HIGH',
        trust: 'VERIFIED',
        isOtpOrLoginOrKeyChange: true,
      },
      rawTextInMemory: 'Your login OTP code is 192045',
      embedder,
    });
    results.push({
      code: 'e',
      title: 'Different OTP Codes Guard',
      expected: 'Blocked (never merged/suppressed)',
      observed: `${o2.action}, blocked=${o2.blockedByGuard}`,
      passed: o2.action === 'NEW_THREAD' && o2.threadId !== o1.threadId && Boolean(o2.blockedByGuard),
      blockedGuard: o2.blockedByGuard,
    });
  }

  // (f) Negation / state change ("Server down" vs "Server recovered")
  if (shouldRun('f')) {
    const win = new InMemoryDedupWindow();
    const n1 = await win.processNotification({
      incoming: {
        notificationId: 'sim_f1',
        userId: simUser,
        sourceId: 'datadog',
        senderId: 'infra-monitor',
        category: 'work',
        priority: 'HIGH',
        trust: 'VERIFIED',
      },
      rawTextInMemory: 'Production server is down',
      embedder,
    });
    const n2 = await win.processNotification({
      incoming: {
        notificationId: 'sim_f2',
        userId: simUser,
        sourceId: 'datadog',
        senderId: 'infra-monitor',
        category: 'work',
        priority: 'MEDIUM',
        trust: 'VERIFIED',
      },
      rawTextInMemory: 'Production server recovered cleanly',
      embedder,
    });
    const threadsAfter = win.getThreadMetadataList(simUser);
    const originalThread = threadsAfter.find((t) => t.threadId === n1.threadId);
    results.push({
      code: 'f',
      title: 'Negation / Recovery State Guard ("down" vs "recovered")',
      expected: 'Blocked by NEGATION_STATE_CONFLICT + original thread marked RESOLVED + linked',
      observed: `${n2.action}, blocked=${n2.blockedByGuard}, origStatus=${originalThread?.status}, related=${n2.relatedThreadId}`,
      passed:
        n2.action === 'NEW_THREAD' &&
        n2.blockedByGuard === 'NEGATION_STATE_CONFLICT' &&
        originalThread?.status === 'RESOLVED' &&
        n2.relatedThreadId === n1.threadId,
      blockedGuard: n2.blockedByGuard,
    });
  }

  // (g) CRITICAL / security alerts never suppressed
  if (shouldRun('g')) {
    const win = new InMemoryDedupWindow();
    const c1 = await win.processNotification({
      incoming: {
        notificationId: 'sim_g1',
        userId: simUser,
        sourceId: 'sec-siem',
        senderId: 'siem',
        category: 'security',
        priority: 'CRITICAL',
        trust: 'VERIFIED',
      },
      rawTextInMemory: 'Unauthorized admin login detected on prod',
      embedder,
    });
    const c2 = await win.processNotification({
      incoming: {
        notificationId: 'sim_g2',
        userId: simUser,
        sourceId: 'sec-siem',
        senderId: 'siem',
        category: 'security',
        priority: 'CRITICAL',
        trust: 'VERIFIED',
      },
      rawTextInMemory: 'Unauthorized admin login detected on prod',
      embedder,
    });
    results.push({
      code: 'g',
      title: 'CRITICAL & Security Alerts Never Suppressed',
      expected: 'Blocked by CRITICAL_SECURITY_EXCLUSION -> both remain separate',
      observed: `${c2.action}, blocked=${c2.blockedByGuard}, alert2=${c2.shouldPlayAlert}`,
      passed:
        c2.action === 'NEW_THREAD' &&
        c2.threadId !== c1.threadId &&
        c2.blockedByGuard === 'CRITICAL_SECURITY_EXCLUSION' &&
        c2.shouldPlayAlert,
      blockedGuard: c2.blockedByGuard,
    });
  }

  // (h) Provenance mismatch (VERIFIED vs UNVERIFIED)
  if (shouldRun('h')) {
    const win = new InMemoryDedupWindow();
    const p1 = await win.processNotification({
      incoming: {
        notificationId: 'sim_h1',
        userId: simUser,
        sourceId: 'datadog',
        senderId: 'infra-monitor',
        category: 'work',
        priority: 'HIGH',
        trust: 'VERIFIED',
      },
      rawTextInMemory: 'Production server unreachable',
      embedder,
    });
    const p2 = await win.processNotification({
      incoming: {
        notificationId: 'sim_h2',
        userId: simUser,
        sourceId: 'datadog',
        senderId: 'spoofed-sender',
        category: 'work',
        priority: 'HIGH',
        trust: 'UNVERIFIED',
      },
      rawTextInMemory: 'Production server unreachable',
      embedder,
    });
    results.push({
      code: 'h',
      title: 'Provenance Mismatch Guard (VERIFIED vs UNVERIFIED)',
      expected: 'Blocked by PROVENANCE_TRUST guard',
      observed: `${p2.action}, blocked=${p2.blockedByGuard}`,
      passed:
        p2.action === 'NEW_THREAD' &&
        p2.threadId !== p1.threadId &&
        p2.blockedByGuard === 'PROVENANCE_TRUST',
      blockedGuard: p2.blockedByGuard,
    });
  }

  // (i) Higher-priority member arrives in existing thread -> breaks out / re-escalates
  if (shouldRun('i')) {
    const win = new InMemoryDedupWindow();
    const h1 = await win.processNotification({
      incoming: {
        notificationId: 'sim_i1',
        userId: simUser,
        sourceId: 'datadog',
        senderId: 'infra-monitor',
        category: 'work',
        priority: 'MEDIUM',
        trust: 'VERIFIED',
      },
      rawTextInMemory: 'Production server down on cluster B',
      embedder,
    });
    const h2 = await win.processNotification({
      incoming: {
        notificationId: 'sim_i2',
        userId: simUser,
        sourceId: 'datadog',
        senderId: 'infra-monitor',
        category: 'work',
        priority: 'HIGH',
        trust: 'VERIFIED',
      },
      rawTextInMemory: 'Prod API not responding on cluster B',
      embedder,
    });
    results.push({
      code: 'i',
      title: 'Higher-Priority Escalation Break-Out',
      expected: 'Thread topPriority upgrades MEDIUM -> HIGH and fires escalation notification',
      observed: `action=${h2.action}, topPriority=${h2.threadMetadata.topPriority}, escalated=${h2.priorityEscalatedInThread}`,
      passed:
        h2.action === 'MERGE' &&
        h1.threadMetadata.topPriority === 'MEDIUM' &&
        h2.threadMetadata.topPriority === 'HIGH' &&
        h2.priorityEscalatedInThread &&
        h2.shouldSendBrowserNotification,
    });
  }

  // (j) Fallback delivery deduplication -> suppresses duplicate delivery job + logs history
  if (shouldRun('j')) {
    const { suppressDuplicateDeliveryForThread } = await import('../delivery/deliveryStore.js');
    const created = await createDeliveryJob({
      notificationId: `sim_dlv_${Date.now()}`,
      userId: simUser,
      priority: 'HIGH',
      isDemoJob: true,
    });
    const sup = await suppressDuplicateDeliveryForThread({
      userId: simUser,
      primaryNotificationId: created.job.notificationId,
      duplicateNotificationId: `sim_dlv_dup_${Date.now()}`,
      threadId: `thr_${created.job.notificationId}`,
      similarity: 0.94,
    });
    const reloaded = await getDeliveryJobById(created.job.id);
    const hasHistoryNote = Boolean(
      reloaded?.history.some((h) => h.result.toLowerCase().includes('duplicate suppressed'))
    );
    results.push({
      code: 'j',
      title: 'Fallback Delivery Deduplication',
      expected: 'Suppresses new SMS/Email job and appends "duplicate suppressed" to existing job history',
      observed: `suppressed=${sup.suppressed}, historyRecorded=${hasHistoryNote}`,
      passed: sup.suppressed && hasHistoryNote,
    });
  }

  // (k) Ungroup / Not a duplicate -> splits thread + prevents re-merge + adapts personal threshold
  if (shouldRun('k')) {
    const win = new InMemoryDedupWindow();
    const k1 = await win.processNotification({
      incoming: {
        notificationId: 'sim_k1',
        userId: simUser,
        sourceId: 'datadog',
        senderId: 'infra-monitor',
        category: 'work',
        priority: 'MEDIUM',
        trust: 'VERIFIED',
      },
      rawTextInMemory: 'Server down',
      embedder,
    });
    await win.processNotification({
      incoming: {
        notificationId: 'sim_k2',
        userId: simUser,
        sourceId: 'datadog',
        senderId: 'infra-monitor',
        category: 'work',
        priority: 'MEDIUM',
        trust: 'VERIFIED',
      },
      rawTextInMemory: 'Production server unreachable',
      embedder,
    });
    const split = win.ungroupThread(simUser, k1.threadId);
    const beforeSetting = getUserDedupSettings(simUser);
    const fb = recordDedupFeedback({
      userId: simUser,
      feedbackKind: 'NOT_DUPLICATE',
      threadId: k1.threadId,
    });
    const serverUngroup = ungroupServerThread({
      userId: simUser,
      threadId: k1.threadId,
    });
    results.push({
      code: 'k',
      title: 'Ungroup & Online Threshold Adaptation',
      expected: 'Splits into 2 independent items + blocks immediate re-merge + tightens threshold in [0.80, 0.98]',
      observed: `splitCount=${split.length}, thresh=${beforeSetting.effectiveMergeThreshold}->${fb.settings.effectiveMergeThreshold}`,
      passed:
        split.length === 2 &&
        serverUngroup.ok &&
        fb.settings.effectiveMergeThreshold >= 0.8 &&
        fb.settings.effectiveMergeThreshold <= 0.98 &&
        fb.settings.effectiveMergeThreshold >= beforeSetting.effectiveMergeThreshold,
    });
  }

  // (l) ONNX model unavailable / fallback -> TF-IDF lightweight mode works without crash
  if (shouldRun('l')) {
    const win = new InMemoryDedupWindow();
    const brokenOnnxEmbedder: TextEmbedderFn = async () => ({
      embedding: null,
      mode: 'tfidf_lightweight',
    });
    const l1 = await win.processNotification({
      incoming: {
        notificationId: 'sim_l1',
        userId: simUser,
        sourceId: 'ops',
        senderId: 'ops',
        category: 'work',
        priority: 'MEDIUM',
        trust: 'GATEWAY_ATTESTED',
      },
      rawTextInMemory: 'Database connection pool saturated on primary postgres cluster',
      embedder: brokenOnnxEmbedder,
    });
    const l2 = await win.processNotification({
      incoming: {
        notificationId: 'sim_l2',
        userId: simUser,
        sourceId: 'ops',
        senderId: 'ops',
        category: 'work',
        priority: 'MEDIUM',
        trust: 'GATEWAY_ATTESTED',
      },
      rawTextInMemory: 'Primary postgres cluster database connection pool saturated',
      embedder: brokenOnnxEmbedder,
    });
    results.push({
      code: 'l',
      title: 'ONNX Unavailable -> TF-IDF Lightweight Mode Fallback',
      expected: 'Falls back cleanly to TF-IDF mode without crashing and still groups near-duplicates',
      observed: `mode=${l2.modelMode}, action=${l2.action}, stage=${l2.stageMatched}`,
      passed:
        l1.modelMode === 'tfidf_lightweight' &&
        l2.modelMode === 'tfidf_lightweight' &&
        l2.action === 'MERGE',
      similarity: l2.similarity,
      stage: l2.stageMatched,
    });
  }

  // (m) Zero plaintext & zero embedding vectors in Firestore/store/telemetry payloads
  if (shouldRun('m')) {
    const sentinelSecret = 'SUPER_SECRET_PLAINTEXT_SENTINEL_9911';
    const win = new InMemoryDedupWindow();
    const res = await win.processNotification({
      incoming: {
        notificationId: 'sim_m1',
        userId: simUser,
        sourceId: 'slack',
        senderId: 'ops',
        category: 'work',
        priority: 'HIGH',
        trust: 'VERIFIED',
      },
      rawTextInMemory: `Alert containing ${sentinelSecret}`,
      embedder,
    });
    const firewallOnMetadata = assertNoPlaintextOrVectors(res.threadMetadata);
    const firewallRejectedVector = assertNoPlaintextOrVectors({
      embedding: new Array(384).fill(0.1),
    });
    const statsJson = JSON.stringify(getDedupStatsSnapshot());
    const eventsJson = JSON.stringify(getSecurityEvents({ limit: 50 }).events);
    const leaked =
      statsJson.includes(sentinelSecret) ||
      eventsJson.includes(sentinelSecret) ||
      JSON.stringify(res.threadMetadata).includes(sentinelSecret);

    // Explicitly validate unit similarity bounds too
    const vecIdentical = cosineSimilarity(l2Normalize([1, 2, 3]), l2Normalize([1, 2, 3]));
    const vecOrthogonal = cosineSimilarity([1, 0, 0], [0, 1, 0]);

    results.push({
      code: 'm',
      title: 'Zero Plaintext & Zero Vector Privacy Guarantee',
      expected: 'Metadata passes firewall; raw vector rejected; zero plaintext leak in stats/logs',
      observed: `metaClean=${firewallOnMetadata.ok}, vectorBlocked=${!firewallRejectedVector.ok}, leaked=${leaked}, simId=${vecIdentical}`,
      passed:
        firewallOnMetadata.ok &&
        !firewallRejectedVector.ok &&
        !leaked &&
        Math.abs(vecIdentical - 1) < 1e-4 &&
        Math.abs(vecOrthogonal) < 1e-4,
    });
  }

  return results;
}
