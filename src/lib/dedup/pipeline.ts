import { DEFAULT_DEDUP_CONFIG, clampMergeThreshold, clampReviewThreshold } from './config.js';
import {
  checkCriticalSecurityGuard,
  evaluateAllMergeGuards,
  minProvenanceTrust,
} from './guards.js';
import { preprocessNotificationText } from './preprocess.js';
import {
  buildWordShingles,
  computeMinHashSignature,
  cosineSimilarity,
  jaccardSimilarity,
  l2Normalize,
  minHashSimilarity,
  sha256HexSync,
} from './similarity.js';
import { buildTfIdfSparseVector, sparseCosineSimilarity } from './tfidf.js';
import type {
  DedupDecisionResult,
  DedupIncomingMetadataInput,
  DedupStage,
  DedupThreadMetadata,
  GuardCheckDetail,
} from './types.js';

export type TextEmbedderFn = (normalizedText: string) => Promise<{
  embedding: number[] | null;
  mode: 'onnx_minilm' | 'tfidf_lightweight' | 'mock_embedder';
}>;

interface RamThreadMember {
  notificationId: string;
  timestampMs: number;
  exactHash: string;
  shingles: string[];
  minHash: number[];
  embedding: number[] | null;
  tfidfVec: Record<string, number>;
  normalizedText: string;
  isEphemeral: boolean;
  ephemeralExpiresAtMs?: number;
}

interface RamThreadState {
  metadata: DedupThreadMetadata;
  latestMember: RamThreadMember;
  members: RamThreadMember[];
}

export interface PipelineRuntimeOptions {
  mergeThreshold?: number;
  reviewThreshold?: number;
  windowMinutes?: number;
  maxWindowItems?: number;
  maxThreadsPerSourcePerHour?: number;
  neverMergeCategories?: string[];
  dedupEnabled?: boolean;
}

const PRIORITY_RANK: Record<'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL', number> = {
  LOW: 0,
  MEDIUM: 1,
  HIGH: 2,
  CRITICAL: 3,
};

/**
 * Ephemeral, bounded RAM-only vector & thread sliding window per user.
 * Zero persistence: vectors and normalized text never touch Firestore, localStorage, or server logs.
 */
export class InMemoryDedupWindow {
  private readonly threadsByUser = new Map<string, Map<string, RamThreadState>>();
  private readonly itemToThreadByUser = new Map<string, Map<string, string>>();
  private readonly ungroupedPairsByUser = new Map<string, Set<string>>();
  private readonly sourceThreadTimesByUser = new Map<string, Map<string, number[]>>();

  private getUserThreads(userId: string): Map<string, RamThreadState> {
    let map = this.threadsByUser.get(userId);
    if (!map) {
      map = new Map();
      this.threadsByUser.set(userId, map);
    }
    return map;
  }

  private getItemIndex(userId: string): Map<string, string> {
    let idx = this.itemToThreadByUser.get(userId);
    if (!idx) {
      idx = new Map();
      this.itemToThreadByUser.set(userId, idx);
    }
    return idx;
  }

  private getUngroupedSet(userId: string): Set<string> {
    let set = this.ungroupedPairsByUser.get(userId);
    if (!set) {
      set = new Set();
      this.ungroupedPairsByUser.set(userId, set);
    }
    return set;
  }

  public pruneWindow(
    userId: string,
    nowMs: number,
    windowMs: number,
    maxItems: number
  ): void {
    const threads = this.getUserThreads(userId);
    const idx = this.getItemIndex(userId);

    for (const [tid, state] of threads.entries()) {
      // Remove expired ephemeral members first
      state.members = state.members.filter((m) => {
        if (m.isEphemeral && m.ephemeralExpiresAtMs && nowMs >= m.ephemeralExpiresAtMs) {
          idx.delete(m.notificationId);
          return false;
        }
        return true;
      });

      if (state.members.length === 0) {
        threads.delete(tid);
        continue;
      }

      state.latestMember = state.members[state.members.length - 1];
      state.metadata.memberIds = state.members.map((m) => m.notificationId);
      state.metadata.memberCount = state.members.length;
      state.metadata.ephemeralMemberIds = state.members
        .filter((m) => m.isEphemeral)
        .map((m) => m.notificationId);
      state.metadata.containsEphemeral = state.metadata.ephemeralMemberIds.length > 0;

      const lastMs = Date.parse(state.metadata.lastMemberAt);
      if (Number.isFinite(lastMs) && nowMs - lastMs > windowMs) {
        for (const m of state.members) {
          idx.delete(m.notificationId);
        }
        threads.delete(tid);
      }
    }

    // Bounded window item count eviction (oldest lastMemberAt evicted first)
    let totalItems = 0;
    for (const state of threads.values()) {
      totalItems += state.members.length;
    }

    if (totalItems > maxItems) {
      const sorted = Array.from(threads.entries()).sort(
        (a, b) => Date.parse(a[1].metadata.lastMemberAt) - Date.parse(b[1].metadata.lastMemberAt)
      );
      for (const [tid, state] of sorted) {
        if (totalItems <= maxItems) break;
        for (const m of state.members) {
          idx.delete(m.notificationId);
        }
        totalItems -= state.members.length;
        threads.delete(tid);
      }
    }
  }

  public countActiveItems(userId: string): number {
    const threads = this.threadsByUser.get(userId);
    if (!threads) return 0;
    let total = 0;
    for (const state of threads.values()) total += state.members.length;
    return total;
  }

  public getThreadMetadataList(userId: string): DedupThreadMetadata[] {
    const threads = this.threadsByUser.get(userId);
    if (!threads) return [];
    return Array.from(threads.values())
      .map((t) => structuredClone(t.metadata))
      .sort((a, b) => Date.parse(b.lastMemberAt) - Date.parse(a.lastMemberAt));
  }

  public getThreadForNotification(userId: string, notificationId: string): string | null {
    return this.getItemIndex(userId).get(notificationId) || null;
  }

  public markNotDuplicatePair(userId: string, idA: string, idB: string): void {
    const pairKey = idA < idB ? `${idA}::${idB}` : `${idB}::${idA}`;
    this.getUngroupedSet(userId).add(pairKey);
  }

  public isPairMarkedNotDuplicate(userId: string, idA: string, idB: string): boolean {
    const pairKey = idA < idB ? `${idA}::${idB}` : `${idB}::${idA}`;
    return this.getUngroupedSet(userId).has(pairKey);
  }

  /**
   * Immediately purges ephemeral vectors and removes ephemeral items from RAM threads on burn/expiry.
   */
  public wipeEphemeralItem(userId: string, notificationId?: string): number {
    const threads = this.threadsByUser.get(userId);
    if (!threads) return 0;
    const idx = this.getItemIndex(userId);
    let removed = 0;

    for (const [tid, state] of threads.entries()) {
      const before = state.members.length;
      state.members = state.members.filter((m) => {
        const shouldDrop = notificationId ? m.notificationId === notificationId : m.isEphemeral;
        if (shouldDrop) {
          // Overwrite embedding array in RAM before dropping reference
          if (m.embedding) {
            m.embedding.fill(0);
          }
          m.normalizedText = '';
          idx.delete(m.notificationId);
          removed += 1;
          return false;
        }
        return true;
      });
      if (state.members.length === 0) {
        threads.delete(tid);
      } else if (state.members.length !== before) {
        state.latestMember = state.members[state.members.length - 1];
        state.metadata.memberIds = state.members.map((m) => m.notificationId);
        state.metadata.memberCount = state.members.length;
        state.metadata.ephemeralMemberIds = state.members
          .filter((m) => m.isEphemeral)
          .map((m) => m.notificationId);
        state.metadata.containsEphemeral = state.metadata.ephemeralMemberIds.length > 0;
      }
    }
    return removed;
  }

  public clearUser(userId: string): void {
    const threads = this.threadsByUser.get(userId);
    if (threads) {
      for (const state of threads.values()) {
        for (const m of state.members) {
          if (m.embedding) m.embedding.fill(0);
          m.normalizedText = '';
        }
      }
      threads.clear();
    }
    this.itemToThreadByUser.delete(userId);
    this.ungroupedPairsByUser.delete(userId);
    this.sourceThreadTimesByUser.delete(userId);
  }

  private checkAndRecordSourceThreadCap(
    userId: string,
    sourceId: string,
    nowMs: number,
    maxPerHour: number
  ): { allowed: boolean; currentHourlyCount: number } {
    let bySource = this.sourceThreadTimesByUser.get(userId);
    if (!bySource) {
      bySource = new Map();
      this.sourceThreadTimesByUser.set(userId, bySource);
    }
    const oneHourAgo = nowMs - 60 * 60 * 1000;
    const key = sourceId.trim().toLowerCase() || 'unknown';
    const recent = (bySource.get(key) || []).filter((ts) => ts >= oneHourAgo);
    if (recent.length >= maxPerHour) {
      bySource.set(key, recent);
      return { allowed: false, currentHourlyCount: recent.length };
    }
    recent.push(nowMs);
    bySource.set(key, recent);
    return { allowed: true, currentHourlyCount: recent.length };
  }

  public ungroupThread(userId: string, threadId: string): DedupThreadMetadata[] {
    const threads = this.threadsByUser.get(userId);
    if (!threads) return [];
    const target = threads.get(threadId);
    if (!target || target.members.length <= 1) return [];

    const idx = this.getItemIndex(userId);
    const createdThreads: DedupThreadMetadata[] = [];
    const originalMembers = [...target.members];

    // Prevent immediate re-merge among ungrouped siblings
    for (let i = 0; i < originalMembers.length; i++) {
      for (let j = i + 1; j < originalMembers.length; j++) {
        this.markNotDuplicatePair(
          userId,
          originalMembers[i].notificationId,
          originalMembers[j].notificationId
        );
      }
    }

    threads.delete(threadId);

    for (let i = 0; i < originalMembers.length; i++) {
      const m = originalMembers[i];
      const newTid = i === 0 ? threadId : `thr_${m.notificationId}`;
      const tsIso = new Date(m.timestampMs).toISOString();
      const singleMeta: DedupThreadMetadata = {
        ...structuredClone(target.metadata),
        threadId: newTid,
        createdAt: tsIso,
        lastMemberAt: tsIso,
        memberCount: 1,
        memberIds: [m.notificationId],
        lastSimilarity: 1,
        memberSimilarities: { [m.notificationId]: 1 },
        containsEphemeral: m.isEphemeral,
        ephemeralMemberIds: m.isEphemeral ? [m.notificationId] : [],
      };
      threads.set(newTid, {
        metadata: singleMeta,
        latestMember: m,
        members: [m],
      });
      idx.set(m.notificationId, newTid);
      createdThreads.push(structuredClone(singleMeta));
    }

    return createdThreads;
  }

  public mergeTwoThreads(
    userId: string,
    targetThreadId: string,
    sourceThreadId: string,
    similarityScore = 0.84
  ): DedupThreadMetadata | null {
    if (targetThreadId === sourceThreadId) return null;
    const threads = this.threadsByUser.get(userId);
    if (!threads) return null;
    const target = threads.get(targetThreadId);
    const source = threads.get(sourceThreadId);
    if (!target || !source) return null;

    const idx = this.getItemIndex(userId);
    for (const m of source.members) {
      target.members.push(m);
      idx.set(m.notificationId, targetThreadId);
      target.metadata.memberIds.push(m.notificationId);
      target.metadata.memberSimilarities = {
        ...(target.metadata.memberSimilarities || {}),
        [m.notificationId]: Number(similarityScore.toFixed(4)),
      };
    }
    target.members.sort((a, b) => a.timestampMs - b.timestampMs);
    target.latestMember = target.members[target.members.length - 1];
    target.metadata.memberCount = target.members.length;
    target.metadata.lastMemberAt = new Date(target.latestMember.timestampMs).toISOString();
    target.metadata.lastSimilarity = Number(similarityScore.toFixed(4));
    target.metadata.lowestTrust = minProvenanceTrust(
      target.metadata.lowestTrust,
      source.metadata.lowestTrust
    );
    if (
      PRIORITY_RANK[source.metadata.topPriority] > PRIORITY_RANK[target.metadata.topPriority]
    ) {
      target.metadata.topPriority = source.metadata.topPriority;
    }
    target.metadata.ephemeralMemberIds = target.members
      .filter((m) => m.isEphemeral)
      .map((m) => m.notificationId);
    target.metadata.containsEphemeral = target.metadata.ephemeralMemberIds.length > 0;

    threads.delete(sourceThreadId);
    return structuredClone(target.metadata);
  }

  public async processNotification(params: {
    incoming: DedupIncomingMetadataInput;
    rawTextInMemory: string;
    embedder: TextEmbedderFn;
    options?: PipelineRuntimeOptions;
  }): Promise<DedupDecisionResult> {
    const cfg = DEFAULT_DEDUP_CONFIG;
    const nowMs = params.incoming.timestampMs ?? Date.now();
    const windowMs = (params.options?.windowMinutes ?? cfg.windowMinutes) * 60 * 1000;
    const maxItems = params.options?.maxWindowItems ?? cfg.maxWindowItems;
    const maxThreadsPerHour =
      params.options?.maxThreadsPerSourcePerHour ?? cfg.maxThreadsPerSourcePerHour;
    const neverMergeCategories =
      params.options?.neverMergeCategories ?? cfg.neverMergeCategories;
    const dedupEnabled = params.options?.dedupEnabled ?? true;

    this.pruneWindow(params.incoming.userId, nowMs, windowMs, maxItems);

    const prep = preprocessNotificationText(params.rawTextInMemory, cfg.maxTokens);
    const exactHash = sha256HexSync(
      `${prep.normalizedText}|${params.incoming.senderId.toLowerCase()}|${params.incoming.sourceId.toLowerCase()}`
    );
    const shingles = buildWordShingles(prep.tokens, cfg.minHashShingleSize);
    const minHash = computeMinHashSignature(shingles, cfg.minHashPermutations);

    const threads = this.getUserThreads(params.incoming.userId);
    const corpusTexts: string[] = [];
    for (const st of threads.values()) {
      corpusTexts.push(st.latestMember.normalizedText);
    }

    const tfidfVec = buildTfIdfSparseVector(prep.normalizedText, corpusTexts);
    const embedRes = await params.embedder(prep.normalizedText);
    const embedding = embedRes.embedding ? l2Normalize(embedRes.embedding) : null;
    const modelMode = embedding ? embedRes.mode : 'tfidf_lightweight';

    const baseMergeThreshold = clampMergeThreshold(
      modelMode === 'tfidf_lightweight'
        ? params.options?.mergeThreshold ?? cfg.tfidfFallbackMergeThreshold
        : params.options?.mergeThreshold ?? cfg.mergeThreshold
    );
    const baseReviewThreshold = clampReviewThreshold(
      modelMode === 'tfidf_lightweight'
        ? params.options?.reviewThreshold ?? cfg.tfidfFallbackReviewThreshold
        : params.options?.reviewThreshold ?? cfg.reviewThreshold,
      baseMergeThreshold
    );

    const member: RamThreadMember = {
      notificationId: params.incoming.notificationId,
      timestampMs: nowMs,
      exactHash,
      shingles,
      minHash,
      embedding,
      tfidfVec,
      normalizedText: prep.normalizedText,
      isEphemeral: Boolean(params.incoming.isEphemeral),
      ephemeralExpiresAtMs: params.incoming.ephemeralExpiresAtMs,
    };

    const idx = this.getItemIndex(params.incoming.userId);

    const createNewThread = (paramsNew: {
      stageMatched: DedupStage;
      similarity: number;
      guards: GuardCheckDetail[];
      blockedByGuard: GuardCheckDetail['guard'] | null;
      relatedThreadId: string | null;
      action: 'NEW_THREAD' | 'SUGGEST';
      whySummary: string;
    }): DedupDecisionResult => {
      const capCheck = this.checkAndRecordSourceThreadCap(
        params.incoming.userId,
        params.incoming.sourceId,
        nowMs,
        maxThreadsPerHour
      );
      const guards = [...paramsNew.guards];
      if (!capCheck.allowed) {
        guards.push({
          guard: 'PER_SOURCE_CAP',
          passed: false,
          severity: 'warn',
          reason: `Source "${params.incoming.sourceId}" hit max ${maxThreadsPerHour} threads/hour cap (${capCheck.currentHourlyCount}).`,
        });
      } else {
        guards.push({
          guard: 'PER_SOURCE_CAP',
          passed: true,
          reason: `Source thread creation within hourly cap (${capCheck.currentHourlyCount}/${maxThreadsPerHour}).`,
        });
      }

      const tid = `thr_${params.incoming.notificationId}`;
      const tsIso = new Date(nowMs).toISOString();
      const meta: DedupThreadMetadata = {
        threadId: tid,
        userId: params.incoming.userId,
        createdAt: tsIso,
        lastMemberAt: tsIso,
        memberCount: 1,
        memberIds: [params.incoming.notificationId],
        sourceId: params.incoming.sourceId,
        senderId: params.incoming.senderId,
        category: params.incoming.category,
        topPriority: params.incoming.priority,
        lowestTrust: params.incoming.trust,
        status: 'ACTIVE',
        stageMatched: paramsNew.stageMatched,
        lastSimilarity: Number(paramsNew.similarity.toFixed(4)),
        memberSimilarities: { [params.incoming.notificationId]: 1 },
        relatedThreadIds: paramsNew.relatedThreadId ? [paramsNew.relatedThreadId] : [],
        containsEphemeral: Boolean(params.incoming.isEphemeral),
        ephemeralMemberIds: params.incoming.isEphemeral ? [params.incoming.notificationId] : [],
      };

      threads.set(tid, {
        metadata: meta,
        latestMember: member,
        members: [member],
      });
      idx.set(params.incoming.notificationId, tid);
      this.pruneWindow(params.incoming.userId, nowMs, windowMs, maxItems);

      return {
        action: paramsNew.action,
        threadId: tid,
        stageMatched: paramsNew.stageMatched,
        similarity: Number(paramsNew.similarity.toFixed(4)),
        thresholdUsed: baseMergeThreshold,
        reviewThresholdUsed: baseReviewThreshold,
        modelMode,
        guards,
        blockedByGuard: paramsNew.blockedByGuard,
        relatedThreadId: paramsNew.relatedThreadId,
        shouldPlayAlert:
          params.incoming.priority === 'CRITICAL' || params.incoming.priority === 'HIGH',
        shouldSendBrowserNotification: true,
        priorityEscalatedInThread: false,
        repetitionCountInWindow: 1,
        threadMetadata: structuredClone(meta),
        whySummary: paramsNew.whySummary,
      };
    };

    if (!dedupEnabled || threads.size === 0) {
      const selfCrit = checkCriticalSecurityGuard(
        params.incoming,
        params.rawTextInMemory,
        neverMergeCategories
      );
      return createNewThread({
        stageMatched: 'NONE',
        similarity: 0,
        guards: [selfCrit],
        blockedByGuard: !selfCrit.passed ? selfCrit.guard : null,
        relatedThreadId: null,
        action: 'NEW_THREAD',
        whySummary: !dedupEnabled
          ? 'Deduplication is disabled in user settings.'
          : `First notification in active ${params.options?.windowMinutes ?? cfg.windowMinutes}-minute (${(params.options?.windowMinutes ?? cfg.windowMinutes) * 60}s) window.`,
      });
    }

    // Score against every active thread in RAM sliding window
    let bestCandidate: {
      state: RamThreadState;
      stage: DedupStage;
      similarity: number;
    } | null = null;

    for (const state of threads.values()) {
      if (state.metadata.status === 'MUTED') continue;
      if (
        this.isPairMarkedNotDuplicate(
          params.incoming.userId,
          params.incoming.notificationId,
          state.latestMember.notificationId
        )
      ) {
        continue;
      }

      // Stage 1: Exact normalized SHA-256 + sender + source
      if (state.latestMember.exactHash === exactHash) {
        bestCandidate = { state, stage: 'EXACT', similarity: 1.0 };
        break;
      }

      // Stage 2: MinHash + Jaccard near-duplicate
      const mhSim = minHashSimilarity(minHash, state.latestMember.minHash);
      if (mhSim >= cfg.minHashThreshold) {
        const jSim = jaccardSimilarity(shingles, state.latestMember.shingles);
        if (jSim >= 0.55) {
          const score = Math.max(jSim, mhSim * 0.96);
          if (!bestCandidate || score > bestCandidate.similarity) {
            bestCandidate = {
              state,
              stage: 'MINHASH',
              similarity: Math.min(0.99, score),
            };
          }
          continue;
        }
      }

      // Stage 3: Semantic ONNX embedding cosine OR pure TS TF-IDF cosine fallback
      let semSim = 0;
      let semStage: DedupStage = 'TFIDF_FALLBACK';
      if (embedding && state.latestMember.embedding) {
        semSim = cosineSimilarity(embedding, state.latestMember.embedding);
        semStage = 'SEMANTIC_ONNX';
      } else {
        semSim = sparseCosineSimilarity(tfidfVec, state.latestMember.tfidfVec);
        semStage = 'TFIDF_FALLBACK';
      }

      if (!bestCandidate || semSim > bestCandidate.similarity) {
        bestCandidate = {
          state,
          stage: semStage,
          similarity: Math.max(0, Math.min(1, semSim)),
        };
      }
    }

    if (!bestCandidate) {
      return createNewThread({
        stageMatched: 'NONE',
        similarity: 0,
        guards: [],
        blockedByGuard: null,
        relatedThreadId: null,
        action: 'NEW_THREAD',
        whySummary: 'No active candidate threads in sliding window.',
      });
    }

    const candidateState = bestCandidate.state;
    const guardOutcome = evaluateAllMergeGuards({
      incoming: params.incoming,
      incomingText: params.rawTextInMemory,
      candidateThread: candidateState.metadata,
      candidateLatestText: candidateState.latestMember.normalizedText,
      neverMergeCategories,
    });

    if (guardOutcome.isResolutionUpdate) {
      candidateState.metadata.status = 'RESOLVED';
    }

    // If similarity is high OR guard blocked merge -> handle guard outcome honestly
    if (!guardOutcome.allowedToMerge) {
      const canLink =
        guardOutcome.linkRelatedOnly && bestCandidate.similarity >= baseReviewThreshold;
      return createNewThread({
        stageMatched: bestCandidate.stage,
        similarity: bestCandidate.similarity,
        guards: guardOutcome.guards,
        blockedByGuard: guardOutcome.blockedByGuard,
        relatedThreadId: canLink ? candidateState.metadata.threadId : null,
        action: 'NEW_THREAD',
        whySummary: `Merge blocked by ${guardOutcome.blockedByGuard}${canLink ? ' (linked as Related without suppressing)' : ''}.`,
      });
    }

    if (bestCandidate.similarity >= baseMergeThreshold) {
      // MERGE into existing thread!
      const prevTopPriority = candidateState.metadata.topPriority;
      const priorityEscalated =
        PRIORITY_RANK[params.incoming.priority] > PRIORITY_RANK[prevTopPriority];

      candidateState.members.push(member);
      candidateState.latestMember = member;
      candidateState.metadata.memberCount = candidateState.members.length;
      candidateState.metadata.memberIds.push(params.incoming.notificationId);
      candidateState.metadata.lastMemberAt = new Date(nowMs).toISOString();
      candidateState.metadata.lastSimilarity = Number(bestCandidate.similarity.toFixed(4));
      candidateState.metadata.stageMatched = bestCandidate.stage;
      candidateState.metadata.lowestTrust = guardOutcome.lowestTrust;
      candidateState.metadata.memberSimilarities = {
        ...(candidateState.metadata.memberSimilarities || {}),
        [params.incoming.notificationId]: Number(bestCandidate.similarity.toFixed(4)),
      };
      if (priorityEscalated) {
        candidateState.metadata.topPriority = params.incoming.priority;
      }
      if (params.incoming.isEphemeral) {
        candidateState.metadata.containsEphemeral = true;
        candidateState.metadata.ephemeralMemberIds = [
          ...(candidateState.metadata.ephemeralMemberIds || []),
          params.incoming.notificationId,
        ];
      }
      idx.set(params.incoming.notificationId, candidateState.metadata.threadId);

      return {
        action: 'MERGE',
        threadId: candidateState.metadata.threadId,
        stageMatched: bestCandidate.stage,
        similarity: Number(bestCandidate.similarity.toFixed(4)),
        thresholdUsed: baseMergeThreshold,
        reviewThresholdUsed: baseReviewThreshold,
        modelMode,
        guards: guardOutcome.guards,
        blockedByGuard: null,
        relatedThreadId: null,
        shouldPlayAlert: priorityEscalated && params.incoming.priority === 'CRITICAL',
        shouldSendBrowserNotification: priorityEscalated,
        priorityEscalatedInThread: priorityEscalated,
        repetitionCountInWindow: candidateState.metadata.memberCount,
        threadMetadata: structuredClone(candidateState.metadata),
        whySummary: `Grouped via ${bestCandidate.stage} (${Math.round(bestCandidate.similarity * 100)}% >= ${Math.round(baseMergeThreshold * 100)}%); all safety guards passed.`,
      };
    }

    if (bestCandidate.similarity >= baseReviewThreshold) {
      return createNewThread({
        stageMatched: bestCandidate.stage,
        similarity: bestCandidate.similarity,
        guards: guardOutcome.guards,
        blockedByGuard: null,
        relatedThreadId: candidateState.metadata.threadId,
        action: 'SUGGEST',
        whySummary: `Possibly related (${Math.round(bestCandidate.similarity * 100)}% between ${Math.round(baseReviewThreshold * 100)}% and ${Math.round(baseMergeThreshold * 100)}%). Kept separate with Merge suggestion.`,
      });
    }

    return createNewThread({
      stageMatched: bestCandidate.stage,
      similarity: bestCandidate.similarity,
      guards: guardOutcome.guards,
      blockedByGuard: null,
      relatedThreadId: null,
      action: 'NEW_THREAD',
      whySummary: `Distinct topic (${Math.round(bestCandidate.similarity * 100)}% < ${Math.round(baseReviewThreshold * 100)}% review threshold).`,
    });
  }
}

export const globalClientDedupWindow = new InMemoryDedupWindow();
