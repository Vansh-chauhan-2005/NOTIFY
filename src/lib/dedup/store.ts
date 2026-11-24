import fs from 'fs';
import os from 'os';
import path from 'path';
import {
  DEFAULT_DEDUP_CONFIG,
  clampMergeThreshold,
  clampNumber,
  clampReviewThreshold,
  clampUserPersonalThreshold,
  sanitizeNeverMergeCategories,
} from './config.js';
import { logSecurityEvent } from '../telemetry/securityLogger.js';
import type {
  DedupDecisionAction,
  DedupFeedbackKind,
  DedupStage,
  DedupStatsSnapshot,
  DedupThreadMetadata,
  GuardName,
  UserDedupSettings,
} from './types.js';

const FORBIDDEN_PRIVACY_KEYS = new Set([
  'text',
  'rawtext',
  'raw_text',
  'plaintext',
  'message',
  'body',
  'content',
  'title',
  'subject',
  'decrypted',
  'embedding',
  'embeddings',
  'vector',
  'vectors',
  'minhash',
  'shingles',
  'tokens',
]);

interface DedupPersistedStore {
  userSettings: Record<string, UserDedupSettings>;
  threads: Record<string, DedupThreadMetadata>;
  counters: {
    itemsReceived: number;
    itemsGrouped: number;
    suggestionsCount: number;
    ungroupCount: number;
    notDuplicateFeedbackCount: number;
    confirmedMergeCount: number;
    perSourceCapHits: number;
    guardsBlockedByType: Record<GuardName, number>;
    stageCounts: Record<DedupStage, number>;
    similarityHistogram: number[]; // 10 bins [0..0.1) ... [0.9..1.0]
  };
  recentEvents: Array<{
    timestampMs: number;
    grouped: boolean;
    threadId: string;
  }>;
}

declare global {
  var __aegisDedupStoreData: DedupPersistedStore | undefined;
}

function getDedupStorePath(): string {
  if (process.env.VITEST === 'true' || process.env.NODE_ENV === 'test') {
    return path.join(os.tmpdir(), `.aegis-dedup-metadata.vitest.${process.pid}.json`);
  }
  return path.resolve(process.cwd(), '.aegis-dedup-metadata.json');
}

function createEmptyStore(): DedupPersistedStore {
  return {
    userSettings: {},
    threads: {},
    counters: {
      itemsReceived: 0,
      itemsGrouped: 0,
      suggestionsCount: 0,
      ungroupCount: 0,
      notDuplicateFeedbackCount: 0,
      confirmedMergeCount: 0,
      perSourceCapHits: 0,
      guardsBlockedByType: {
        CRITICAL_SECURITY_EXCLUSION: 0,
        ENTITY_CONFLICT: 0,
        NEGATION_STATE_CONFLICT: 0,
        PROVENANCE_TRUST: 0,
        PER_SOURCE_CAP: 0,
      },
      stageCounts: {
        EXACT: 0,
        MINHASH: 0,
        SEMANTIC_ONNX: 0,
        TFIDF_FALLBACK: 0,
        NONE: 0,
      },
      similarityHistogram: Array(10).fill(0),
    },
    recentEvents: [],
  };
}

function loadStore(): DedupPersistedStore {
  if (global.__aegisDedupStoreData) {
    return global.__aegisDedupStoreData;
  }
  const filePath = getDedupStorePath();
  let data = createEmptyStore();
  try {
    if (fs.existsSync(filePath)) {
      const raw = fs.readFileSync(filePath, 'utf8');
      const parsed = JSON.parse(raw);
      if (parsed && typeof parsed === 'object') {
        const empty = createEmptyStore();
        data = {
          userSettings: parsed.userSettings && typeof parsed.userSettings === 'object' ? parsed.userSettings : {},
          threads: parsed.threads && typeof parsed.threads === 'object' ? parsed.threads : {},
          counters: {
            ...empty.counters,
            ...(parsed.counters || {}),
            guardsBlockedByType: {
              ...empty.counters.guardsBlockedByType,
              ...(parsed.counters?.guardsBlockedByType || {}),
            },
            stageCounts: {
              ...empty.counters.stageCounts,
              ...(parsed.counters?.stageCounts || {}),
            },
            similarityHistogram:
              Array.isArray(parsed.counters?.similarityHistogram) &&
              parsed.counters.similarityHistogram.length === 10
                ? parsed.counters.similarityHistogram
                : Array(10).fill(0),
          },
          recentEvents: Array.isArray(parsed.recentEvents) ? parsed.recentEvents.slice(-400) : [],
        };
      }
    }
  } catch {
    data = createEmptyStore();
  }
  global.__aegisDedupStoreData = data;
  return data;
}

function persistStore(data: DedupPersistedStore): void {
  try {
    const tmp = `${getDedupStorePath()}.tmp`;
    fs.writeFileSync(tmp, JSON.stringify(data, null, 2), 'utf8');
    fs.renameSync(tmp, getDedupStorePath());
  } catch {
    // Non-fatal in read-only runtimes
  }
}

export function clearDedupStoreForTests(): void {
  global.__aegisDedupStoreData = createEmptyStore();
  try {
    const fp = getDedupStorePath();
    if (fs.existsSync(fp)) fs.unlinkSync(fp);
  } catch {
    // ignore
  }
}

/**
 * Strict Zero-Text / Zero-Vector Firewall:
 * Recursively verifies incoming server payloads never contain plaintext or float embedding vectors.
 */
export function assertNoPlaintextOrVectors(payload: unknown): { ok: boolean; reason?: string } {
  const stack: Array<{ val: unknown; path: string }> = [{ val: payload, path: 'root' }];
  let depth = 0;

  while (stack.length > 0 && depth < 500) {
    depth += 1;
    const { val, path: curPath } = stack.pop()!;
    if (!val || typeof val !== 'object') continue;

    if (Array.isArray(val)) {
      if (val.length > 32 && val.every((x) => typeof x === 'number')) {
        return {
          ok: false,
          reason: `Privacy violation at ${curPath}: numeric embedding vectors must never leave device RAM.`,
        };
      }
      for (let i = 0; i < Math.min(val.length, 64); i++) {
        stack.push({ val: val[i], path: `${curPath}[${i}]` });
      }
      continue;
    }

    for (const [key, child] of Object.entries(val as Record<string, unknown>)) {
      const lower = key.trim().toLowerCase();
      if (FORBIDDEN_PRIVACY_KEYS.has(lower)) {
        return {
          ok: false,
          reason: `Privacy violation: forbidden field "${key}" rejected by zero-text/zero-vector dedup firewall.`,
        };
      }
      if (child && typeof child === 'object') {
        stack.push({ val: child, path: `${curPath}.${key}` });
      }
    }
  }

  return { ok: true };
}

export function getUserDedupSettings(userId: string): UserDedupSettings {
  const cleanId = String(userId || 'anonymous').trim().slice(0, 128) || 'anonymous';
  const store = loadStore();
  if (!store.userSettings[cleanId]) {
    const baseMerge = DEFAULT_DEDUP_CONFIG.mergeThreshold;
    store.userSettings[cleanId] = {
      userId: cleanId,
      dedupEnabled: true,
      mergeThreshold: baseMerge,
      reviewThreshold: DEFAULT_DEDUP_CONFIG.reviewThreshold,
      personalThresholdOffset: 0,
      effectiveMergeThreshold: clampUserPersonalThreshold(baseMerge),
      windowMinutes: DEFAULT_DEDUP_CONFIG.windowMinutes,
      neverMergeCategories: [...DEFAULT_DEDUP_CONFIG.neverMergeCategories],
      feedbackCount: 0,
      updatedAt: new Date().toISOString(),
    };
    persistStore(store);
  }
  return structuredClone(store.userSettings[cleanId]);
}

export function updateUserDedupSettings(
  userId: string,
  patch: {
    dedupEnabled?: boolean;
    mergeThreshold?: number;
    reviewThreshold?: number;
    windowMinutes?: number;
    neverMergeCategories?: string[];
  }
): UserDedupSettings {
  const store = loadStore();
  const current = getUserDedupSettings(userId);
  const cleanId = current.userId;

  const mergeThreshold =
    typeof patch.mergeThreshold === 'number'
      ? clampMergeThreshold(patch.mergeThreshold)
      : current.mergeThreshold;
  const reviewThreshold =
    typeof patch.reviewThreshold === 'number'
      ? clampReviewThreshold(patch.reviewThreshold, mergeThreshold)
      : clampReviewThreshold(current.reviewThreshold, mergeThreshold);
  const windowMinutes =
    typeof patch.windowMinutes === 'number'
      ? Math.round(clampNumber(patch.windowMinutes, 5, 180))
      : current.windowMinutes;

  const updated: UserDedupSettings = {
    ...current,
    dedupEnabled: typeof patch.dedupEnabled === 'boolean' ? patch.dedupEnabled : current.dedupEnabled,
    mergeThreshold,
    reviewThreshold,
    effectiveMergeThreshold: clampUserPersonalThreshold(
      mergeThreshold + current.personalThresholdOffset
    ),
    windowMinutes,
    neverMergeCategories: patch.neverMergeCategories
      ? sanitizeNeverMergeCategories(patch.neverMergeCategories)
      : current.neverMergeCategories,
    updatedAt: new Date().toISOString(),
  };

  store.userSettings[cleanId] = updated;
  persistStore(store);
  return structuredClone(updated);
}

export function recordDedupDecisionMetadata(params: {
  userId: string;
  action: DedupDecisionAction;
  stageMatched: DedupStage;
  similarity: number;
  blockedByGuard: GuardName | null;
  threadMetadata: DedupThreadMetadata;
  perSourceCapHit?: boolean;
  isDemo?: boolean;
  ipAddress?: string;
  userAgent?: string;
}): DedupThreadMetadata {
  const store = loadStore();
  const nowMs = Date.now();

  // Strictly whitelist ONLY non-sensitive metadata fields
  const cleanMeta: DedupThreadMetadata = {
    threadId: String(params.threadMetadata.threadId).replace(/[^a-zA-Z0-9_-]/g, '_').slice(0, 128),
    userId: String(params.userId).slice(0, 128),
    createdAt: String(params.threadMetadata.createdAt || new Date(nowMs).toISOString()),
    lastMemberAt: String(params.threadMetadata.lastMemberAt || new Date(nowMs).toISOString()),
    memberCount: Math.max(1, Math.floor(Number(params.threadMetadata.memberCount) || 1)),
    memberIds: Array.isArray(params.threadMetadata.memberIds)
      ? params.threadMetadata.memberIds.map((id) => String(id).slice(0, 128)).slice(-50)
      : [],
    sourceId: String(params.threadMetadata.sourceId || 'direct').slice(0, 64),
    senderId: String(params.threadMetadata.senderId || 'unknown').slice(0, 128),
    category: String(params.threadMetadata.category || 'work').slice(0, 32),
    topPriority: params.threadMetadata.topPriority,
    lowestTrust: params.threadMetadata.lowestTrust,
    status: params.threadMetadata.status,
    stageMatched: params.stageMatched,
    lastSimilarity: Number(clampNumber(params.similarity, 0, 1).toFixed(4)),
    memberSimilarities: params.threadMetadata.memberSimilarities || {},
    relatedThreadIds: Array.isArray(params.threadMetadata.relatedThreadIds)
      ? params.threadMetadata.relatedThreadIds.slice(0, 10)
      : [],
    containsEphemeral: Boolean(params.threadMetadata.containsEphemeral),
    ephemeralMemberIds: Array.isArray(params.threadMetadata.ephemeralMemberIds)
      ? params.threadMetadata.ephemeralMemberIds.slice(0, 50)
      : [],
    ...(params.isDemo ? { isDemo: true } : {}),
  };

  store.threads[cleanMeta.threadId] = cleanMeta;

  // Prune stored thread map to max 300 recent threads
  const keys = Object.keys(store.threads);
  if (keys.length > 300) {
    keys
      .sort(
        (a, b) =>
          Date.parse(store.threads[a].lastMemberAt) - Date.parse(store.threads[b].lastMemberAt)
      )
      .slice(0, keys.length - 300)
      .forEach((oldKey) => {
        delete store.threads[oldKey];
      });
  }

  if (!params.isDemo) {
    store.counters.itemsReceived += 1;
    if (params.action === 'MERGE') {
      store.counters.itemsGrouped += 1;
    } else if (params.action === 'SUGGEST') {
      store.counters.suggestionsCount += 1;
    }

    store.counters.stageCounts[params.stageMatched] =
      (store.counters.stageCounts[params.stageMatched] || 0) + 1;

    if (params.blockedByGuard) {
      store.counters.guardsBlockedByType[params.blockedByGuard] =
        (store.counters.guardsBlockedByType[params.blockedByGuard] || 0) + 1;
    }
    if (params.perSourceCapHit) {
      store.counters.perSourceCapHits += 1;
      store.counters.guardsBlockedByType.PER_SOURCE_CAP =
        (store.counters.guardsBlockedByType.PER_SOURCE_CAP || 0) + 1;
    }

    const bin = Math.min(9, Math.max(0, Math.floor(cleanMeta.lastSimilarity * 10)));
    store.counters.similarityHistogram[bin] += 1;

    store.recentEvents.push({
      timestampMs: nowMs,
      grouped: params.action === 'MERGE',
      threadId: cleanMeta.threadId,
    });
    if (store.recentEvents.length > 400) {
      store.recentEvents = store.recentEvents.slice(-400);
    }
  }

  persistStore(store);

  if (params.action === 'MERGE') {
    logSecurityEvent({
      eventType: 'DEDUP_MERGED',
      severity: 'info',
      result: 'success',
      userId: params.userId,
      ipAddress: params.ipAddress,
      userAgent: params.userAgent,
      details: `Merged into thread ${cleanMeta.threadId} via ${params.stageMatched} (sim=${cleanMeta.lastSimilarity}, members=${cleanMeta.memberCount}).`,
    });
  } else if (params.action === 'SUGGEST') {
    logSecurityEvent({
      eventType: 'DEDUP_SUGGESTED',
      severity: 'info',
      result: 'success',
      userId: params.userId,
      ipAddress: params.ipAddress,
      userAgent: params.userAgent,
      details: `Suggested thread relation for ${cleanMeta.threadId} (sim=${cleanMeta.lastSimilarity}).`,
    });
  } else if (params.blockedByGuard) {
    logSecurityEvent({
      eventType: 'DEDUP_GUARD_BLOCKED',
      severity: 'info',
      result: 'blocked',
      userId: params.userId,
      ipAddress: params.ipAddress,
      userAgent: params.userAgent,
      details: `Safety guard ${params.blockedByGuard} prevented merge for ${cleanMeta.threadId}.`,
    });
  }

  if (params.perSourceCapHit) {
    logSecurityEvent({
      eventType: 'DEDUP_THREAD_CAP_HIT',
      severity: 'warning',
      result: 'blocked',
      userId: params.userId,
      ipAddress: params.ipAddress,
      userAgent: params.userAgent,
      details: `Per-source thread cap triggered for source ${cleanMeta.sourceId}.`,
    });
  }

  return structuredClone(cleanMeta);
}

export function recordDedupFeedback(params: {
  userId: string;
  feedbackKind: DedupFeedbackKind;
  threadId?: string;
  notificationId?: string;
  ipAddress?: string;
  userAgent?: string;
}): { settings: UserDedupSettings } {
  const store = loadStore();
  const settings = getUserDedupSettings(params.userId);
  const delta =
    params.feedbackKind === 'CONFIRM_MERGE' ? -0.008 : 0.015;

  const nextEffective = clampUserPersonalThreshold(
    settings.effectiveMergeThreshold + delta
  );
  const nextOffset = Number((nextEffective - settings.mergeThreshold).toFixed(4));

  const updated: UserDedupSettings = {
    ...settings,
    personalThresholdOffset: nextOffset,
    effectiveMergeThreshold: nextEffective,
    feedbackCount: settings.feedbackCount + 1,
    updatedAt: new Date().toISOString(),
  };

  store.userSettings[settings.userId] = updated;
  if (params.feedbackKind === 'NOT_DUPLICATE') {
    store.counters.notDuplicateFeedbackCount += 1;
  } else if (params.feedbackKind === 'CONFIRM_MERGE') {
    store.counters.confirmedMergeCount += 1;
  }
  persistStore(store);

  logSecurityEvent({
    eventType: 'DEDUP_FEEDBACK',
    severity: 'info',
    result: 'success',
    userId: params.userId,
    ipAddress: params.ipAddress,
    userAgent: params.userAgent,
    details: `Dedup feedback ${params.feedbackKind} recorded (threshold -> ${updated.effectiveMergeThreshold}).`,
  });

  return { settings: structuredClone(updated) };
}

export function ungroupServerThread(params: {
  userId: string;
  threadId: string;
  isAdmin?: boolean;
  ipAddress?: string;
  userAgent?: string;
}): { ok: boolean; message: string; splitThreads: DedupThreadMetadata[]; settings: UserDedupSettings } {
  const store = loadStore();
  const existing = store.threads[params.threadId];
  const settings = getUserDedupSettings(params.userId);

  if (!existing) {
    // Still honor client-only RAM thread ungroup cleanly & adjust threshold
    store.counters.ungroupCount += 1;
    persistStore(store);
    const fb = recordDedupFeedback({
      userId: params.userId,
      feedbackKind: 'UNGROUP',
      threadId: params.threadId,
      ipAddress: params.ipAddress,
      userAgent: params.userAgent,
    });
    logSecurityEvent({
      eventType: 'DEDUP_UNGROUPED',
      severity: 'info',
      result: 'success',
      userId: params.userId,
      ipAddress: params.ipAddress,
      userAgent: params.userAgent,
      details: `Thread ${params.threadId} ungrouped by user.`,
    });
    return {
      ok: true,
      message: 'Thread ungrouped and personal merge threshold tightened.',
      splitThreads: [],
      settings: fb.settings,
    };
  }

  if (!params.isAdmin && existing.userId !== params.userId) {
    return {
      ok: false,
      message: 'Forbidden: cannot ungroup another user thread.',
      splitThreads: [],
      settings,
    };
  }

  const splitThreads: DedupThreadMetadata[] = [];
  const members = existing.memberIds.length > 0 ? existing.memberIds : [existing.threadId];
  delete store.threads[params.threadId];

  for (let i = 0; i < members.length; i++) {
    const mid = members[i];
    const newId = i === 0 ? params.threadId : `thr_${mid}`;
    const rec: DedupThreadMetadata = {
      ...existing,
      threadId: newId,
      memberCount: 1,
      memberIds: [mid],
      lastSimilarity: 1,
      memberSimilarities: { [mid]: 1 },
    };
    store.threads[newId] = rec;
    splitThreads.push(structuredClone(rec));
  }

  store.counters.ungroupCount += 1;
  persistStore(store);

  const fb = recordDedupFeedback({
    userId: params.userId,
    feedbackKind: 'UNGROUP',
    threadId: params.threadId,
    ipAddress: params.ipAddress,
    userAgent: params.userAgent,
  });

  logSecurityEvent({
    eventType: 'DEDUP_UNGROUPED',
    severity: 'info',
    result: 'success',
    userId: params.userId,
    ipAddress: params.ipAddress,
    userAgent: params.userAgent,
    details: `Thread ${params.threadId} split into ${splitThreads.length} independent notifications.`,
  });

  return {
    ok: true,
    message: `Thread ungrouped into ${splitThreads.length} items.`,
    splitThreads,
    settings: fb.settings,
  };
}

export function wipeEphemeralDedupMetadata(userId?: string, ephemeralId?: string): number {
  const store = loadStore();
  let modified = 0;
  for (const [tid, thread] of Object.entries(store.threads)) {
    if (userId && thread.userId !== userId) continue;
    if (!thread.containsEphemeral && !(thread.ephemeralMemberIds && thread.ephemeralMemberIds.length > 0)) {
      continue;
    }

    if (ephemeralId) {
      const before = thread.memberIds.length;
      thread.memberIds = thread.memberIds.filter((id) => id !== ephemeralId);
      thread.ephemeralMemberIds = (thread.ephemeralMemberIds || []).filter((id) => id !== ephemeralId);
      if (thread.memberSimilarities && thread.memberSimilarities[ephemeralId] !== undefined) {
        delete thread.memberSimilarities[ephemeralId];
      }
      if (thread.memberIds.length === 0) {
        delete store.threads[tid];
        modified += 1;
      } else if (thread.memberIds.length !== before) {
        thread.memberCount = thread.memberIds.length;
        thread.containsEphemeral = thread.ephemeralMemberIds.length > 0;
        modified += 1;
      }
    } else {
      const ephSet = new Set(thread.ephemeralMemberIds || []);
      thread.memberIds = thread.memberIds.filter((id) => !ephSet.has(id));
      thread.ephemeralMemberIds = [];
      thread.containsEphemeral = false;
      if (thread.memberIds.length === 0) {
        delete store.threads[tid];
      } else {
        thread.memberCount = thread.memberIds.length;
      }
      modified += 1;
    }
  }
  if (modified > 0) {
    persistStore(store);
  }
  return modified;
}

export function listDedupThreads(options: {
  userId?: string;
  isAdmin?: boolean;
  includeDemo?: boolean;
  limit?: number;
}): DedupThreadMetadata[] {
  const store = loadStore();
  let list = Object.values(store.threads);
  if (!options.isAdmin && options.userId) {
    list = list.filter((t) => t.userId === options.userId);
  }
  if (!options.includeDemo) {
    list = list.filter((t) => !t.isDemo);
  }
  list.sort((a, b) => Date.parse(b.lastMemberAt) - Date.parse(a.lastMemberAt));
  return list.slice(0, options.limit || 100).map((t) => structuredClone(t));
}

export function getDedupStatsSnapshot(): DedupStatsSnapshot {
  const store = loadStore();
  const threads = Object.values(store.threads).filter((t) => !t.isDemo);
  const { itemsReceived, itemsGrouped } = store.counters;

  // Honest metric: return null when zero items processed (UI shows "No data yet", never fake 100%)
  const suppressionRatePercent =
    itemsReceived > 0 ? Number(((itemsGrouped / itemsReceived) * 100).toFixed(1)) : null;

  const histogramLabels = [
    '0.0-0.1',
    '0.1-0.2',
    '0.2-0.3',
    '0.3-0.4',
    '0.4-0.5',
    '0.5-0.6',
    '0.6-0.7',
    '0.7-0.8',
    '0.8-0.9',
    '0.9-1.0',
  ];

  // Build rolling 10-minute bucket series
  const now = Date.now();
  const bucketMs = 60_000;
  const currentFloor = Math.floor(now / bucketMs) * bucketMs;
  const buckets: Array<{
    ts: number;
    label: string;
    total: number;
    grouped: number;
    threadSet: Set<string>;
  }> = [];

  for (let i = 9; i >= 0; i--) {
    const ts = currentFloor - i * bucketMs;
    const d = new Date(ts);
    const hh = String(d.getHours()).padStart(2, '0');
    const mm = String(d.getMinutes()).padStart(2, '0');
    buckets.push({ ts, label: `${hh}:${mm}`, total: 0, grouped: 0, threadSet: new Set() });
  }

  for (const ev of store.recentEvents) {
    const floor = Math.floor(ev.timestampMs / bucketMs) * bucketMs;
    const b = buckets.find((x) => x.ts === floor);
    if (b) {
      b.total += 1;
      if (ev.grouped) b.grouped += 1;
      b.threadSet.add(ev.threadId);
    }
  }

  return {
    itemsReceived,
    itemsGrouped,
    suggestionsCount: store.counters.suggestionsCount,
    distinctThreadsCount: threads.length,
    suppressionRatePercent,
    activeThreadsCount: threads.filter((t) => t.status === 'ACTIVE').length,
    resolvedThreadsCount: threads.filter((t) => t.status === 'RESOLVED').length,
    ungroupCount: store.counters.ungroupCount,
    notDuplicateFeedbackCount: store.counters.notDuplicateFeedbackCount,
    confirmedMergeCount: store.counters.confirmedMergeCount,
    perSourceCapHits: store.counters.perSourceCapHits,
    guardsBlockedByType: { ...store.counters.guardsBlockedByType },
    stageCounts: { ...store.counters.stageCounts },
    similarityHistogram: histogramLabels.map((bucket, idx) => ({
      bucket,
      count: store.counters.similarityHistogram[idx] || 0,
    })),
    timeSeries: buckets.map((b) => ({
      label: b.label,
      total: b.total,
      grouped: b.grouped,
      uniqueThreads: b.threadSet.size,
    })),
    activeConfig: {
      mergeThreshold: DEFAULT_DEDUP_CONFIG.mergeThreshold,
      reviewThreshold: DEFAULT_DEDUP_CONFIG.reviewThreshold,
      windowMinutes: DEFAULT_DEDUP_CONFIG.windowMinutes,
      maxThreadsPerSourcePerHour: DEFAULT_DEDUP_CONFIG.maxThreadsPerSourcePerHour,
      neverMergeCategories: [...DEFAULT_DEDUP_CONFIG.neverMergeCategories],
    },
    generatedAt: new Date(now).toISOString(),
  };
}
