import {
  assertFiniteFeatures,
  clamp,
  computeAgeFactor,
  computeRepetitionFeature,
} from './math.js';
import { classifyTextWithDefaultWeights } from './tfidfModel.js';
import {
  PRIORITY_FEATURE_NAMES,
  type FeatureVector,
  type PriorityCategory,
  type PriorityFeatureName,
  type QuietHoursConfig,
} from './types.js';

const URGENCY_TERMS: Array<{ term: string; weight: number }> = [
  { term: 'critical', weight: 0.25 },
  { term: 'urgent', weight: 0.22 },
  { term: 'breach', weight: 0.28 },
  { term: 'unauthorized', weight: 0.28 },
  { term: 'compromised', weight: 0.28 },
  { term: 'otp', weight: 0.24 },
  { term: 'verification code', weight: 0.22 },
  { term: '2fa', weight: 0.22 },
  { term: 'new device', weight: 0.22 },
  { term: 'revoked', weight: 0.24 },
  { term: 'key mismatch', weight: 0.28 },
  { term: 'outage', weight: 0.24 },
  { term: 'down', weight: 0.16 },
  { term: 'incident', weight: 0.22 },
  { term: 'wire', weight: 0.2 },
  { term: 'transfer', weight: 0.16 },
  { term: 'fraud', weight: 0.26 },
  { term: 'failed', weight: 0.14 },
  { term: 'immediately', weight: 0.18 },
  { term: 'action required', weight: 0.2 },
];

const CATEGORY_PATTERNS: Record<PriorityCategory, RegExp> = {
  security: /\b(otp|2fa|mfa|login|sign[- ]?in|new device|password|revoked|ed25519|key|breach|security|unauthorized|intrusion|lockout|quarantine)\b/i,
  finance: /\b(bank|wire|invoice|payment|charge|card|transaction|payout|fraud|refund|settlement|debited|credited|upi)\b/i,
  work: /\b(deploy|prod|production|incident|outage|pager|ticket|jira|pr|merge|build|server|alert|db|latency)\b/i,
  promo: /\b(sale|discount|promo|promotion|newsletter|deal|offer|coupon|unsubscribe|webinar|flash deal|limited time|cashback)\b/i,
  social: /\b(liked|commented|mentioned|replied|dm|chat|friend|follow|invited|party)\b/i,
};

const FORBIDDEN_TEXT_KEYS = new Set([
  'message',
  'text',
  'plaintext',
  'body',
  'content',
  'title',
  'subject',
  'decrypted',
  'rawtext',
  'raw_text',
  'ciphertext',
]);

/**
 * Computes numeric in-memory importance score [0, 1] using the imported Colab TF-IDF +
 * Multiclass Logistic Regression `defaultWeights.json` blended with explicit urgency signals.
 * Never stores or logs raw text.
 */
export function computeTextImportanceScore(
  ephemeralText: string,
  extraUrgentKeywords: string[] = []
): {
  textScore: number;
  keywordUrgency: number;
  detectedCategory: PriorityCategory;
  tfidfPredictedClass?: 'Critical' | 'High' | 'Low' | 'Normal';
} {
  const lower = String(ephemeralText || '').toLowerCase();
  if (!lower.trim()) {
    return { textScore: 0.25, keywordUrgency: 0, detectedCategory: 'work' };
  }

  let signalSum = 0.15;
  let kwMatches = 0;

  for (const { term, weight } of URGENCY_TERMS) {
    if (lower.includes(term)) {
      signalSum += weight;
      kwMatches += 1;
    }
  }

  for (const custom of extraUrgentKeywords) {
    const clean = String(custom || '').trim().toLowerCase();
    if (clean.length >= 2 && lower.includes(clean)) {
      signalSum += 0.22;
      kwMatches += 1;
    }
  }

  // Punctuation / emphasis nudge (very small so promo spam doesn't abuse !!!)
  const exclCount = (lower.match(/!/g) || []).length;
  if (exclCount > 0) {
    signalSum += Math.min(0.08, exclCount * 0.02);
  }

  let detectedCategory: PriorityCategory = 'work';
  if (CATEGORY_PATTERNS.security.test(lower)) {
    detectedCategory = 'security';
  } else if (CATEGORY_PATTERNS.finance.test(lower)) {
    detectedCategory = 'finance';
  } else if (CATEGORY_PATTERNS.promo.test(lower)) {
    detectedCategory = 'promo';
  } else if (CATEGORY_PATTERNS.work.test(lower)) {
    detectedCategory = 'work';
  } else if (CATEGORY_PATTERNS.social.test(lower)) {
    detectedCategory = 'social';
  }

  const tfidfRes = classifyTextWithDefaultWeights(lower, detectedCategory);
  const heuristicScore = clamp(signalSum, 0.05, 0.99);
  const blendedScore =
    tfidfRes.matchedTermsCount > 0
      ? tfidfRes.tfidfImportanceScore * 0.65 + heuristicScore * 0.35
      : heuristicScore;

  const textScore = Number(clamp(blendedScore, 0.05, 0.99).toFixed(4));
  const keywordUrgency = Number(clamp(kwMatches / 3, 0, 1).toFixed(4));
  return {
    textScore,
    keywordUrgency,
    detectedCategory,
    tfidfPredictedClass: tfidfRes.predictedClass,
  };
}

export function normalizeClaimedPriority(claimed?: string | number | null): number {
  if (typeof claimed === 'number' && Number.isFinite(claimed)) {
    return clamp(claimed, 0, 1);
  }
  const upper = String(claimed || 'NORMAL').trim().toUpperCase();
  if (upper === 'CRITICAL' || upper === 'HIGHEST') return 1.0;
  if (upper === 'HIGH') return 0.75;
  if (upper === 'NORMAL' || upper === 'MEDIUM') return 0.45;
  if (upper === 'LOW') return 0.2;
  return 0.45;
}

export function computeUserContextFactor(
  quietHours?: QuietHoursConfig,
  nowDate: Date = new Date()
): number {
  if (!quietHours) return 0.7;
  if (quietHours.dndActive) return 0.2;
  if (!quietHours.enabled) return 0.75;

  const hour = nowDate.getUTCHours();
  const { startHourUtc, endHourUtc } = quietHours;
  const inQuiet =
    startHourUtc <= endHourUtc
      ? hour >= startHourUtc && hour < endHourUtc
      : hour >= startHourUtc || hour < endHourUtc;

  return inQuiet ? 0.25 : 0.78;
}

/**
 * Extracts normalized [0, 1] feature vector purely in-memory.
 * Plaintext input string is discarded on return and never stored.
 */
export function extractFeaturesFromContent(params: {
  plaintextInMemory?: string;
  precomputedTextScore?: number;
  category?: PriorityCategory;
  source?: string;
  provenanceTrustScore?: number;
  sourceReliability?: number;
  elapsedSeconds?: number;
  isAcked?: boolean;
  repeatCount?: number;
  userAffinity?: number;
  senderClaimedPriority?: string | number;
  urgentKeywords?: string[];
  quietHours?: QuietHoursConfig;
}): FeatureVector {
  const textAnalysis =
    typeof params.plaintextInMemory === 'string' && params.plaintextInMemory.trim().length > 0
      ? computeTextImportanceScore(params.plaintextInMemory, params.urgentKeywords || [])
      : null;

  const textScore = clamp(
    typeof params.precomputedTextScore === 'number'
      ? params.precomputedTextScore
      : textAnalysis?.textScore ?? 0.45,
    0,
    1
  );

  const keywordUrgency = clamp(textAnalysis?.keywordUrgency ?? 0, 0, 1);
  const category: PriorityCategory = params.category ?? textAnalysis?.detectedCategory ?? 'work';

  const senderTrust = clamp(params.provenanceTrustScore ?? 0.5, 0, 1);
  const sourceReliability = clamp(params.sourceReliability ?? 0.75, 0, 1);
  const ageFactor = computeAgeFactor(params.elapsedSeconds ?? 0, Boolean(params.isAcked));
  const userContext = computeUserContextFactor(params.quietHours);
  const repetition = computeRepetitionFeature(params.repeatCount ?? 1);
  const userAffinity = clamp(params.userAffinity ?? 0.6, 0, 1);
  const senderClaimedPriority = normalizeClaimedPriority(params.senderClaimedPriority);

  return assertFiniteFeatures({
    textScore,
    keywordUrgency,
    senderTrust,
    sourceReliability,
    category_security: category === 'security' ? 1 : 0,
    category_finance: category === 'finance' ? 1 : 0,
    category_work: category === 'work' ? 1 : 0,
    category_social: category === 'social' ? 1 : 0,
    category_promo: category === 'promo' ? 1 : 0,
    ageFactor,
    userContext,
    repetition,
    userAffinity,
    senderClaimedPriority,
  });
}

/**
 * Privacy-enforcing validator for POST /api/v1/priority/score:
 * Rejects any payload containing raw message/text fields or non-numeric features.
 */
export function validateNumericOnlyScoreInput(body: unknown): {
  ok: true;
  features: FeatureVector;
} | {
  ok: false;
  message: string;
} {
  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    return { ok: false, message: 'Request body must be a JSON object.' };
  }

  const record = body as Record<string, unknown>;
  for (const key of Object.keys(record)) {
    if (FORBIDDEN_TEXT_KEYS.has(key.toLowerCase())) {
      return {
        ok: false,
        message: `Privacy violation rejected: /api/v1/priority/score accepts numeric features only and never accepts "${key}".`,
      };
    }
  }

  const candidate =
    record.features && typeof record.features === 'object' && !Array.isArray(record.features)
      ? (record.features as Record<string, unknown>)
      : record;

  for (const key of Object.keys(candidate)) {
    if (FORBIDDEN_TEXT_KEYS.has(key.toLowerCase())) {
      return {
        ok: false,
        message: `Privacy violation rejected: raw text key "${key}" is forbidden inside feature payload.`,
      };
    }
  }

  const assembled: Partial<FeatureVector> = {};
  for (const name of PRIORITY_FEATURE_NAMES) {
    const val = candidate[name];
    if (typeof val !== 'number' || !Number.isFinite(val)) {
      return {
        ok: false,
        message: `Feature "${name}" must be a finite numeric value in [0, 1].`,
      };
    }
    if (val < 0 || val > 1) {
      return {
        ok: false,
        message: `Feature "${name}" (${val}) must be normalized within [0, 1].`,
      };
    }
    assembled[name as PriorityFeatureName] = val;
  }

  return { ok: true, features: assertFiniteFeatures(assembled) };
}
