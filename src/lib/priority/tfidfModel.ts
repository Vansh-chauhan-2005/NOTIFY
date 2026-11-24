import rawTfidfArtifact from './tfidfDefaultWeights.json';
import type { PriorityCategory } from './types.js';

export type TfidfPriorityClass = 'Critical' | 'High' | 'Low' | 'Normal';

export interface TfidfDefaultWeightsArtifact {
  version: string;
  model_type: string;
  input_format: string;
  classes: TfidfPriorityClass[];
  categories: PriorityCategory[];
  tfidf_config: {
    lowercase: boolean;
    ngram_range: [number, number];
    sublinear_tf: boolean;
    norm: 'l2' | 'l1' | null;
    token_pattern: string;
  };
  vocabulary_idf: Record<string, number>;
  intercepts: Record<TfidfPriorityClass, number>;
  weights: Record<TfidfPriorityClass, Record<string, number>>;
  evaluation_metrics: {
    test_accuracy: number;
    test_f1_macro: number;
    test_roc_auc_ovr_macro: number;
    cv5_f1_macro_mean: number;
  };
}

export interface TfidfModelSummary {
  loaded: boolean;
  sourceArtifact: string;
  version: string;
  modelType: string;
  inputFormat: string;
  classes: TfidfPriorityClass[];
  categories: PriorityCategory[];
  vocabularySize: number;
  ngramRange: [number, number];
  sublinearTf: boolean;
  norm: string;
  intercepts: Record<TfidfPriorityClass, number>;
  evaluationMetrics: {
    test_accuracy: number;
    test_f1_macro: number;
    test_roc_auc_ovr_macro: number;
    cv5_f1_macro_mean: number;
  };
}

export interface TfidfClassificationResult {
  predictedClass: TfidfPriorityClass;
  probabilities: Record<TfidfPriorityClass, number>;
  logits: Record<TfidfPriorityClass, number>;
  tfidfImportanceScore: number;
  matchedTermsCount: number;
  categoryUsed: PriorityCategory;
  topTerms: Array<{ term: string; classWeight: number; tfidf: number; contribution: number }>;
}

const ARTIFACT = rawTfidfArtifact as unknown as TfidfDefaultWeightsArtifact;

const VOCAB_IDF = ARTIFACT?.vocabulary_idf || {};
const INTERCEPTS = ARTIFACT?.intercepts || {
  Critical: 0,
  High: 0,
  Low: 0,
  Normal: 0,
};
const CLASS_WEIGHTS = ARTIFACT?.weights || {
  Critical: {},
  High: {},
  Low: {},
  Normal: {},
};
const CLASSES: TfidfPriorityClass[] = Array.isArray(ARTIFACT?.classes) && ARTIFACT.classes.length > 0
  ? ARTIFACT.classes
  : ['Critical', 'High', 'Low', 'Normal'];

export const TFIDF_DEFAULT_MODEL_SUMMARY: TfidfModelSummary = {
  loaded: Object.keys(VOCAB_IDF).length > 0 && CLASSES.every((c) => Boolean(CLASS_WEIGHTS[c])),
  sourceArtifact: '/public/assets/aistudio/defaultWeights_390b2f53.json',
  version: ARTIFACT?.version || '1.0.0',
  modelType: ARTIFACT?.model_type || 'tfidf_logistic_regression_multiclass',
  inputFormat: ARTIFACT?.input_format || 'cat_{category} {text}',
  classes: CLASSES,
  categories: ARTIFACT?.categories || ['security', 'finance', 'work', 'social', 'promo'],
  vocabularySize: Object.keys(VOCAB_IDF).length,
  ngramRange: ARTIFACT?.tfidf_config?.ngram_range || [1, 2],
  sublinearTf: Boolean(ARTIFACT?.tfidf_config?.sublinear_tf ?? true),
  norm: ARTIFACT?.tfidf_config?.norm || 'l2',
  intercepts: {
    Critical: Number(INTERCEPTS.Critical ?? 0),
    High: Number(INTERCEPTS.High ?? 0),
    Low: Number(INTERCEPTS.Low ?? 0),
    Normal: Number(INTERCEPTS.Normal ?? 0),
  },
  evaluationMetrics: {
    test_accuracy: Number(ARTIFACT?.evaluation_metrics?.test_accuracy ?? 0),
    test_f1_macro: Number(ARTIFACT?.evaluation_metrics?.test_f1_macro ?? 0),
    test_roc_auc_ovr_macro: Number(ARTIFACT?.evaluation_metrics?.test_roc_auc_ovr_macro ?? 0),
    cv5_f1_macro_mean: Number(ARTIFACT?.evaluation_metrics?.cv5_f1_macro_mean ?? 0),
  },
};

export function getTfidfDefaultWeightsArtifact(): TfidfDefaultWeightsArtifact {
  return ARTIFACT;
}

/**
 * Tokenizes input matching scikit-learn `token_pattern="(?u)\\b\\w\\w+\\b"` with `lowercase=true`.
 */
function tokenizeForTfidf(text: string): string[] {
  const prepared = ARTIFACT?.tfidf_config?.lowercase === false ? text : text.toLowerCase();
  return prepared.match(/[\p{L}\p{N}_]{2,}/gu) || [];
}

/**
 * Builds normalized TF-IDF feature map over the loaded vocabulary_idf (`ngram_range: [1, 2]`,
 * `sublinear_tf: true`, `norm: "l2"`). Never retains plaintext strings after returning numeric weights.
 */
function vectorizeTextWithArtifact(formattedInput: string): Map<string, number> {
  const unigrams = tokenizeForTfidf(formattedInput);
  const minN = ARTIFACT?.tfidf_config?.ngram_range?.[0] ?? 1;
  const maxN = ARTIFACT?.tfidf_config?.ngram_range?.[1] ?? 2;

  const tfCounts = new Map<string, number>();
  for (let n = minN; n <= maxN; n++) {
    for (let i = 0; i + n <= unigrams.length; i++) {
      const term = n === 1 ? unigrams[i] : unigrams.slice(i, i + n).join(' ');
      if (Object.prototype.hasOwnProperty.call(VOCAB_IDF, term)) {
        tfCounts.set(term, (tfCounts.get(term) || 0) + 1);
      }
    }
  }

  const rawVec = new Map<string, number>();
  let sqNorm = 0;
  for (const [term, tf] of tfCounts.entries()) {
    const idf = VOCAB_IDF[term];
    if (typeof idf !== 'number' || !Number.isFinite(idf)) continue;
    const tfWeight = ARTIFACT?.tfidf_config?.sublinear_tf !== false ? 1 + Math.log(tf) : tf;
    const val = tfWeight * idf;
    rawVec.set(term, val);
    sqNorm += val * val;
  }

  if (sqNorm > 0 && ARTIFACT?.tfidf_config?.norm !== null) {
    const norm = Math.sqrt(sqNorm);
    for (const [term, val] of rawVec.entries()) {
      rawVec.set(term, val / norm);
    }
  }

  return rawVec;
}

/**
 * Classifies in-memory text using the imported Colab multiclass TF-IDF + Logistic Regression
 * `defaultWeights.json` model (`input_format: "cat_{category} {text}"`).
 */
export function classifyTextWithDefaultWeights(
  ephemeralText: string,
  category: PriorityCategory = 'work'
): TfidfClassificationResult {
  const safeCategory: PriorityCategory = TFIDF_DEFAULT_MODEL_SUMMARY.categories.includes(category)
    ? category
    : 'work';
  const formatted = `cat_${safeCategory} ${String(ephemeralText || '')}`;
  const vec = vectorizeTextWithArtifact(formatted);

  const logits: Record<TfidfPriorityClass, number> = {
    Critical: Number(INTERCEPTS.Critical ?? 0),
    High: Number(INTERCEPTS.High ?? 0),
    Low: Number(INTERCEPTS.Low ?? 0),
    Normal: Number(INTERCEPTS.Normal ?? 0),
  };

  for (const cls of CLASSES) {
    const clsWeights = CLASS_WEIGHTS[cls] || {};
    let z = Number(INTERCEPTS[cls] ?? 0);
    for (const [term, x] of vec.entries()) {
      const w = clsWeights[term];
      if (typeof w === 'number' && Number.isFinite(w)) {
        z += w * x;
      }
    }
    logits[cls] = z;
  }

  const maxLogit = Math.max(...CLASSES.map((c) => logits[c]));
  const exps: Record<TfidfPriorityClass, number> = {
    Critical: Math.exp(logits.Critical - maxLogit),
    High: Math.exp(logits.High - maxLogit),
    Low: Math.exp(logits.Low - maxLogit),
    Normal: Math.exp(logits.Normal - maxLogit),
  };
  const expSum = exps.Critical + exps.High + exps.Low + exps.Normal || 1;

  const probabilities: Record<TfidfPriorityClass, number> = {
    Critical: Number((exps.Critical / expSum).toFixed(4)),
    High: Number((exps.High / expSum).toFixed(4)),
    Low: Number((exps.Low / expSum).toFixed(4)),
    Normal: Number((exps.Normal / expSum).toFixed(4)),
  };

  let predictedClass: TfidfPriorityClass = 'Normal';
  let bestProb = -1;
  for (const cls of CLASSES) {
    if (probabilities[cls] > bestProb) {
      bestProb = probabilities[cls];
      predictedClass = cls;
    }
  }

  const rawImportance =
    probabilities.Critical * 0.99 +
    probabilities.High * 0.74 +
    probabilities.Normal * 0.38 +
    probabilities.Low * 0.1;
  const tfidfImportanceScore = Number(Math.max(0.05, Math.min(0.99, rawImportance)).toFixed(4));

  const predWeights = CLASS_WEIGHTS[predictedClass] || {};
  const topTerms = Array.from(vec.entries())
    .map(([term, tfidf]) => {
      const w = Number(predWeights[term] ?? 0);
      return {
        term,
        classWeight: Number(w.toFixed(4)),
        tfidf: Number(tfidf.toFixed(4)),
        contribution: Number((w * tfidf).toFixed(4)),
      };
    })
    .sort((a, b) => Math.abs(b.contribution) - Math.abs(a.contribution))
    .slice(0, 8);

  return {
    predictedClass,
    probabilities,
    logits: {
      Critical: Number(logits.Critical.toFixed(4)),
      High: Number(logits.High.toFixed(4)),
      Low: Number(logits.Low.toFixed(4)),
      Normal: Number(logits.Normal.toFixed(4)),
    },
    tfidfImportanceScore,
    matchedTermsCount: vec.size,
    categoryUsed: safeCategory,
    topTerms,
  };
}
