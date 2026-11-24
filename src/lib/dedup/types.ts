export type DedupStage =
  | 'EXACT'
  | 'MINHASH'
  | 'SEMANTIC_ONNX'
  | 'TFIDF_FALLBACK'
  | 'NONE';

export type DedupDecisionAction = 'MERGE' | 'SUGGEST' | 'NEW_THREAD';

export type DedupThreadStatus = 'ACTIVE' | 'RESOLVED' | 'MUTED';

export type DedupProvenanceTrust = 'VERIFIED' | 'GATEWAY_ATTESTED' | 'UNVERIFIED';

export type GuardName =
  | 'CRITICAL_SECURITY_EXCLUSION'
  | 'ENTITY_CONFLICT'
  | 'NEGATION_STATE_CONFLICT'
  | 'PROVENANCE_TRUST'
  | 'PER_SOURCE_CAP';

export interface GuardCheckDetail {
  guard: GuardName;
  passed: boolean;
  reason: string;
  severity?: 'block' | 'link_only' | 'warn';
}

export interface ExtractedEntities {
  currenciesAndNumbers: string[];
  codesAndIds: string[];
  urlsAndDomains: string[];
  emails: string[];
  phones: string[];
  datesAndTimes: string[];
}

export interface DedupPreprocessResult {
  normalizedText: string;
  tokens: string[];
  truncated: boolean;
  hadZeroWidthOrControl: boolean;
  hadMixedScript: boolean;
}

export interface DedupEvalThresholdMetric {
  threshold: number;
  precision: number;
  recall: number;
  f1: number;
  accuracy: number;
  confusionMatrix: number[][];
}

export interface DedupGuardrailsConfig {
  blockIfNumbersDiffer: boolean;
  numberRegex: string;
  blockIfOppositeStates: boolean;
  oppositeStatePairs: Array<[string, string]>;
}

export interface DedupBenchmarkRow {
  Method: string;
  Threshold: number;
  Precision: number;
  Recall: number;
  F1: number;
  'PR-AUC': number;
  'Tricky FP Rate': number;
}

export interface DedupThresholdSweepRow {
  threshold: number;
  precision: number;
  recall: number;
  f1: number;
  f05: number;
  tricky_fp_rate: number;
}

export interface DedupConfig {
  version: string;
  generatedAt: string;
  modelId: string;
  embeddingModel: string;
  similarityMetric: string;
  quantized: boolean;
  embeddingDim: number;
  maxTokens: number;
  recommendedThreshold: number;
  bestF1Threshold: number;
  highPrecisionThreshold: number;
  dedupWindowSeconds: number;
  mergeThreshold: number;
  reviewThreshold: number;
  userThresholdMin: number;
  userThresholdMax: number;
  windowMinutes: number;
  maxWindowItems: number;
  maxThreadsPerSourcePerHour: number;
  minHashPermutations: number;
  minHashShingleSize: number;
  minHashThreshold: number;
  tfidfFallbackMergeThreshold: number;
  tfidfFallbackReviewThreshold: number;
  neverMergeCategories: string[];
  guardrails: DedupGuardrailsConfig;
  benchmarkComparison: DedupBenchmarkRow[];
  thresholdSweep: DedupThresholdSweepRow[];
  evaluation: {
    source: string;
    evaluator: string;
    pairCount: number;
    positivePairs: number;
    negativePairs: number;
    rocAuc: number;
    atRecommendedThreshold: DedupEvalThresholdMetric;
    bestF1Threshold: DedupEvalThresholdMetric;
    prCurve: Array<{
      threshold: number;
      precision: number;
      recall: number;
      f1: number;
      f05?: number;
      trickyFpRate?: number;
    }>;
    methodComparison: Array<
      DedupEvalThresholdMetric & {
        method: string;
        rocAuc: number;
        trickyFpRate?: number;
      }
    >;
  };
  modelCard: {
    modelName: string;
    embeddingDimensions: number;
    maxSequenceTokens: number;
    approxDownloadMb: number;
    intendedUse: string;
    outOfScopeAndHonesty: string[];
  };
}

export interface UserDedupSettings {
  userId: string;
  dedupEnabled: boolean;
  mergeThreshold: number;
  reviewThreshold: number;
  personalThresholdOffset: number;
  effectiveMergeThreshold: number;
  windowMinutes: number;
  neverMergeCategories: string[];
  feedbackCount: number;
  updatedAt: string;
}

/**
 * Metadata-only thread representation allowed in Firestore, API payloads, and server telemetry.
 * STRICT PRIVACY: NEVER includes plaintext message text or embedding float vectors.
 */
export interface DedupThreadMetadata {
  threadId: string;
  userId: string;
  createdAt: string;
  lastMemberAt: string;
  memberCount: number;
  memberIds: string[];
  sourceId: string;
  senderId: string;
  category: string;
  topPriority: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  lowestTrust: DedupProvenanceTrust;
  status: DedupThreadStatus;
  stageMatched: DedupStage;
  lastSimilarity: number;
  memberSimilarities?: Record<string, number>;
  relatedThreadIds?: string[];
  containsEphemeral?: boolean;
  ephemeralMemberIds?: string[];
  isDemo?: boolean;
}

export interface DedupIncomingMetadataInput {
  notificationId: string;
  userId: string;
  sourceId: string;
  senderId: string;
  category: string;
  priority: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  trust: DedupProvenanceTrust;
  timestampMs?: number;
  isEphemeral?: boolean;
  ephemeralExpiresAtMs?: number;
  isOtpOrLoginOrKeyChange?: boolean;
  isPriorityFloorAlert?: boolean;
  provenanceFailed?: boolean;
}

export interface DedupDecisionResult {
  action: DedupDecisionAction;
  threadId: string;
  stageMatched: DedupStage;
  similarity: number;
  thresholdUsed: number;
  reviewThresholdUsed: number;
  modelMode: 'onnx_minilm' | 'tfidf_lightweight' | 'mock_embedder';
  guards: GuardCheckDetail[];
  blockedByGuard: GuardName | null;
  relatedThreadId: string | null;
  shouldPlayAlert: boolean;
  shouldSendBrowserNotification: boolean;
  priorityEscalatedInThread: boolean;
  repetitionCountInWindow: number;
  threadMetadata: DedupThreadMetadata;
  whySummary: string;
}

export type DedupFeedbackKind = 'NOT_DUPLICATE' | 'UNGROUP' | 'CONFIRM_MERGE';

export interface DedupStatsSnapshot {
  itemsReceived: number;
  itemsGrouped: number;
  suggestionsCount: number;
  distinctThreadsCount: number;
  suppressionRatePercent: number | null;
  activeThreadsCount: number;
  resolvedThreadsCount: number;
  ungroupCount: number;
  notDuplicateFeedbackCount: number;
  confirmedMergeCount: number;
  perSourceCapHits: number;
  guardsBlockedByType: Record<GuardName, number>;
  stageCounts: Record<DedupStage, number>;
  similarityHistogram: Array<{
    bucket: string;
    count: number;
  }>;
  timeSeries: Array<{
    label: string;
    total: number;
    grouped: number;
    uniqueThreads: number;
  }>;
  activeConfig: {
    mergeThreshold: number;
    reviewThreshold: number;
    windowMinutes: number;
    maxThreadsPerSourcePerHour: number;
    neverMergeCategories: string[];
  };
  generatedAt: string;
}

export interface DedupSimulationScenarioResult {
  code: string;
  title: string;
  passed: boolean;
  expected: string;
  observed: string;
  similarity?: number;
  stage?: DedupStage;
  blockedGuard?: GuardName | null;
}

export interface EmbedderBenchmarkResult {
  mode: 'onnx_minilm' | 'tfidf_lightweight';
  backend: 'wasm' | 'webgpu' | 'cpu_ts';
  modelLoadMs: number;
  samplesTested: number;
  avgEmbedMs: number;
  throughputPerSec: number;
  estimatedRamMb: number;
  cachedInBrowser: boolean;
}
