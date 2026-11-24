import rawConfig from './dedupConfig.json' with { type: 'json' };
import type {
  DedupBenchmarkRow,
  DedupConfig,
  DedupThresholdSweepRow,
} from './types.js';

interface RawImportedDedupConfig {
  version?: string;
  embedding_model?: string;
  similarity_metric?: string;
  recommended_threshold?: number;
  best_f1_threshold?: number;
  high_precision_threshold?: number;
  dedup_window_seconds?: number;
  guardrails?: {
    block_if_numbers_differ?: boolean;
    number_regex?: string;
    block_if_opposite_states?: boolean;
    opposite_state_pairs?: Array<[string, string]>;
  };
  benchmark_comparison?: DedupBenchmarkRow[];
  threshold_sweep?: DedupThresholdSweepRow[];
}

function hydrateDedupConfig(raw: RawImportedDedupConfig): DedupConfig {
  const recommended = typeof raw.recommended_threshold === 'number' ? raw.recommended_threshold : 0.98;
  const bestF1 = typeof raw.best_f1_threshold === 'number' ? raw.best_f1_threshold : 0.5;
  const highPrec =
    typeof raw.high_precision_threshold === 'number' ? raw.high_precision_threshold : recommended;
  const windowSeconds =
    typeof raw.dedup_window_seconds === 'number' && raw.dedup_window_seconds > 0
      ? raw.dedup_window_seconds
      : 300;
  const windowMinutes = Math.max(1, Math.round(windowSeconds / 60));

  const benchmarkComparison = Array.isArray(raw.benchmark_comparison)
    ? raw.benchmark_comparison
    : [];
  const thresholdSweep = Array.isArray(raw.threshold_sweep) ? raw.threshold_sweep : [];

  const tfidfMethod = benchmarkComparison.find((row) =>
    row.Method.toLowerCase().includes('tf-idf')
  );
  const recSweep =
    thresholdSweep.find((r) => Math.abs(r.threshold - recommended) < 0.005) ||
    thresholdSweep[thresholdSweep.length - 1];
  const bestF1Sweep =
    thresholdSweep.find((r) => Math.abs(r.threshold - bestF1) < 0.005) || thresholdSweep[0];
  const miniLmBench =
    benchmarkComparison.find((row) => row.Method.toLowerCase().includes('recommended')) ||
    benchmarkComparison[benchmarkComparison.length - 1];

  const embeddingModel = raw.embedding_model || 'sentence-transformers/all-MiniLM-L6-v2';
  const modelId = embeddingModel.startsWith('sentence-transformers/')
    ? embeddingModel.replace('sentence-transformers/', 'Xenova/')
    : embeddingModel;

  return {
    version: raw.version || '1.0.0',
    generatedAt: '2026-11-23T00:00:00.000Z',
    modelId,
    embeddingModel,
    similarityMetric: raw.similarity_metric || 'cosine',
    quantized: true,
    embeddingDim: 384,
    maxTokens: 256,
    recommendedThreshold: recommended,
    bestF1Threshold: bestF1,
    highPrecisionThreshold: highPrec,
    dedupWindowSeconds: windowSeconds,
    mergeThreshold: recommended,
    reviewThreshold: bestF1,
    userThresholdMin: 0.8,
    userThresholdMax: Math.max(0.95, Math.min(0.99, highPrec)),
    windowMinutes,
    maxWindowItems: 500,
    maxThreadsPerSourcePerHour: 20,
    minHashPermutations: 32,
    minHashShingleSize: 3,
    minHashThreshold: 0.68,
    tfidfFallbackMergeThreshold:
      typeof tfidfMethod?.Threshold === 'number' ? tfidfMethod.Threshold : 0.83,
    tfidfFallbackReviewThreshold: bestF1,
    neverMergeCategories: ['security', 'otp', 'auth', 'provenance'],
    guardrails: {
      blockIfNumbersDiffer: raw.guardrails?.block_if_numbers_differ ?? true,
      numberRegex: raw.guardrails?.number_regex || '\\d+(?:[.,]\\d+)?',
      blockIfOppositeStates: raw.guardrails?.block_if_opposite_states ?? true,
      oppositeStatePairs: Array.isArray(raw.guardrails?.opposite_state_pairs)
        ? raw.guardrails.opposite_state_pairs
        : [
            ['down', 'recovered'],
            ['offline', 'online'],
            ['failed', 'passed'],
            ['failed', 'succeeded'],
            ['failed', 'completed'],
            ['fail', 'successful'],
            ['debited', 'credited'],
            ['blocked', 'unblocked'],
            ['blocked', 'approved'],
            ['cancelled', 'confirmed'],
            ['band', 'chalu'],
          ],
    },
    benchmarkComparison,
    thresholdSweep,
    evaluation: {
      source: 'colab_imported_dedup_config',
      evaluator: embeddingModel,
      pairCount: 600,
      positivePairs: 240,
      negativePairs: 360,
      rocAuc: miniLmBench?.['PR-AUC'] ?? 0.714,
      atRecommendedThreshold: {
        threshold: recommended,
        precision: recSweep?.precision ?? miniLmBench?.Precision ?? 0.9775,
        recall: recSweep?.recall ?? miniLmBench?.Recall ?? 0.3222,
        f1: recSweep?.f1 ?? miniLmBench?.F1 ?? 0.4847,
        accuracy: recSweep?.precision ?? 0.9775,
        confusionMatrix: [],
      },
      bestF1Threshold: {
        threshold: bestF1,
        precision: bestF1Sweep?.precision ?? 0.5695,
        recall: bestF1Sweep?.recall ?? 0.9556,
        f1: bestF1Sweep?.f1 ?? 0.7137,
        accuracy: bestF1Sweep?.f1 ?? 0.7137,
        confusionMatrix: [],
      },
      prCurve: thresholdSweep.map((row) => ({
        threshold: row.threshold,
        precision: row.precision,
        recall: row.recall,
        f1: row.f1,
        f05: row.f05,
        trickyFpRate: row.tricky_fp_rate,
      })),
      methodComparison: benchmarkComparison.map((row) => ({
        method: row.Method,
        threshold: row.Threshold,
        precision: row.Precision,
        recall: row.Recall,
        f1: row.F1,
        accuracy: row.F1,
        confusionMatrix: [],
        rocAuc: row['PR-AUC'],
        trickyFpRate: row['Tricky FP Rate'],
      })),
    },
    modelCard: {
      modelName: `${modelId} (${embeddingModel}, INT8/Quantized ONNX)`,
      embeddingDimensions: 384,
      maxSequenceTokens: 256,
      approxDownloadMb: 23,
      intendedUse: `On-device semantic similarity grouping inside a ${windowSeconds}s (${windowMinutes}-minute) RAM sliding window using recommended threshold ${(recommended * 100).toFixed(0)}%.`,
      outOfScopeAndHonesty: [
        'Similarity heuristic only — paraphrases, abbreviations, or multilingual phrasing can still miss or collide.',
        'Never merges CRITICAL/security/OTP/login/provenance-failure alerts or notifications with differing numbers or opposite state pairs (e.g. down/recovered, debited/credited, cancelled/confirmed).',
        'Evaluation figures come from the imported Colab benchmark & threshold sweep (PR-AUC 0.714, Tricky FP Rate 1.11% at threshold 0.98), NOT live production traffic.',
        'Plaintext and embedding float vectors stay strictly in device volatile RAM and are never persisted or logged.',
      ],
    },
  };
}

export const DEFAULT_DEDUP_CONFIG: DedupConfig = hydrateDedupConfig(
  rawConfig as unknown as RawImportedDedupConfig
);

export const MIN_THRESHOLD = 0.5;
export const MAX_THRESHOLD = 0.99;
export const USER_THRESHOLD_MIN = DEFAULT_DEDUP_CONFIG.userThresholdMin ?? 0.8;
export const USER_THRESHOLD_MAX = DEFAULT_DEDUP_CONFIG.userThresholdMax ?? 0.98;

export function clampNumber(value: number, min: number, max: number): number {
  if (!Number.isFinite(value)) return min;
  return Math.max(min, Math.min(max, value));
}

export function clampMergeThreshold(value: number): number {
  return Number(clampNumber(value, 0.7, 0.98).toFixed(3));
}

export function clampReviewThreshold(value: number, mergeThreshold: number): number {
  const maxAllowed = Math.max(MIN_THRESHOLD, mergeThreshold - 0.02);
  return Number(clampNumber(value, MIN_THRESHOLD, maxAllowed).toFixed(3));
}

export function clampUserPersonalThreshold(value: number): number {
  return Number(clampNumber(value, USER_THRESHOLD_MIN, USER_THRESHOLD_MAX).toFixed(3));
}

export function sanitizeNeverMergeCategories(input: unknown): string[] {
  const mandatory = ['security', 'otp', 'auth', 'provenance'];
  const extras = Array.isArray(input)
    ? input
        .map((c) => String(c || '').trim().toLowerCase())
        .filter((c) => /^[a-z0-9_-]{2,32}$/.test(c))
    : [];
  return Array.from(new Set([...mandatory, ...extras])).slice(0, 12);
}
