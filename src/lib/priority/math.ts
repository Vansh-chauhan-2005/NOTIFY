import defaultWeightsArtifact from './defaultWeights.json';
import { TFIDF_DEFAULT_MODEL_SUMMARY } from './tfidfModel.js';
import {
  PRIORITY_FEATURE_NAMES,
  type AppliedHardRule,
  type DefaultWeightsArtifact,
  type FeatureContribution,
  type FeatureVector,
  type HardRuleContext,
  type LegacyNotificationPriority,
  type PriorityFeatureName,
  type PriorityThresholds,
  type SigmoidPriorityLabel,
  type WeightVector,
} from './types.js';
import { applyHardSafetyRules } from './rules.js';

export const DEFAULT_PRIORITY_ARTIFACT = defaultWeightsArtifact as DefaultWeightsArtifact;
export { TFIDF_DEFAULT_MODEL_SUMMARY };

export const FEATURE_DISPLAY_LABELS: Record<PriorityFeatureName, string> = {
  textScore: 'In-memory text signal',
  keywordUrgency: 'Urgent keyword match',
  senderTrust: 'Ed25519 provenance trust',
  sourceReliability: 'Source reliability',
  category_security: 'Security category',
  category_finance: 'Finance category',
  category_work: 'Work / incident category',
  category_social: 'Social category',
  category_promo: 'Promo category',
  ageFactor: 'Unacked age escalation',
  userContext: 'User focus / quiet hours',
  repetition: 'Burst repetition factor',
  userAffinity: 'User source affinity',
  senderClaimedPriority: 'Sender claimed priority (weak)',
};

export const DEFAULT_THRESHOLDS: PriorityThresholds = {
  critical: DEFAULT_PRIORITY_ARTIFACT.thresholds.critical,
  high: DEFAULT_PRIORITY_ARTIFACT.thresholds.high,
  normal: DEFAULT_PRIORITY_ARTIFACT.thresholds.normal,
  hysteresis: DEFAULT_PRIORITY_ARTIFACT.thresholds.hysteresis,
};

export const DEFAULT_WEIGHTS: WeightVector = { ...DEFAULT_PRIORITY_ARTIFACT.weights };
export const DEFAULT_BIAS: number = DEFAULT_PRIORITY_ARTIFACT.bias;

export function clamp(val: number, min: number, max: number): number {
  if (!Number.isFinite(val)) return min;
  return Math.max(min, Math.min(max, val));
}

/**
 * Numerically stable logistic sigmoid function:
 *   sigma(z) = 1 / (1 + exp(-z)) for z >= 0
 *   sigma(z) = exp(z) / (1 + exp(z)) for z < 0
 * Never overflows to Infinity or NaN even at z = +/-1000.
 */
export function sigmoid(z: number): number {
  if (!Number.isFinite(z)) {
    throw new Error(`Invalid logit z=${String(z)}: must be finite.`);
  }
  if (z >= 0) {
    return 1 / (1 + Math.exp(-z));
  }
  const ez = Math.exp(z);
  return ez / (1 + ez);
}

/**
 * Inverse sigmoid (log-odds), safely bounded inside (1e-6, 1 - 1e-6).
 */
export function logit(p: number): number {
  if (!Number.isFinite(p)) {
    throw new Error(`Invalid probability p=${String(p)}: must be finite.`);
  }
  const clipped = clamp(p, 1e-6, 1 - 1e-6);
  return Math.log(clipped / (1 - clipped));
}

/**
 * Validates that every feature value is finite and within [0, 1].
 */
export function assertFiniteFeatures(features: Partial<FeatureVector>): FeatureVector {
  const out = {} as FeatureVector;
  for (const name of PRIORITY_FEATURE_NAMES) {
    const val = features[name];
    if (typeof val !== 'number' || !Number.isFinite(val)) {
      throw new Error(`Feature "${name}" must be a finite number (received ${String(val)}).`);
    }
    if (val < 0 || val > 1) {
      throw new Error(`Feature "${name}" must be normalized within [0, 1] (received ${val}).`);
    }
    out[name] = val;
  }
  return out;
}

/**
 * Computes age escalation factor in [0, 1]:
 *   ageFactor = 0 when already acknowledged
 *   ageFactor = 1 - exp(-elapsedSeconds / tau) when unacknowledged (tau = 120s default)
 */
export function computeAgeFactor(
  elapsedSeconds: number,
  isAcked = false,
  tauSeconds = DEFAULT_PRIORITY_ARTIFACT.hyperparams.ageTauSeconds
): number {
  if (isAcked) return 0;
  if (!Number.isFinite(elapsedSeconds) || elapsedSeconds <= 0) return 0;
  const tau = Math.max(1, tauSeconds);
  return clamp(1 - Math.exp(-elapsedSeconds / tau), 0, 1);
}

/**
 * Computes staleness decay factor for LOW / stale unacknowledged notifications.
 * Only applies gentle decay after notification exceeds halfLife without urgency.
 */
export function computeDecayPenalty(
  elapsedSeconds: number,
  baseLabel: SigmoidPriorityLabel,
  isAcked = false,
  halfLifeSeconds = DEFAULT_PRIORITY_ARTIFACT.hyperparams.decayHalfLifeSeconds
): number {
  if (isAcked) return 0;
  if (!Number.isFinite(elapsedSeconds) || elapsedSeconds <= 0) return 0;
  if (baseLabel !== 'LOW') return 0;
  const halfLife = Math.max(60, halfLifeSeconds);
  // Decay factor up to 0.12 reduction for stale LOW items
  const ratio = 1 - Math.pow(0.5, elapsedSeconds / halfLife);
  return clamp(0.12 * ratio, 0, 0.12);
}

/**
 * Models burst repetition: rises cleanly for 2-4 repeats, then plateaus/damps past 5
 * so spam bursts don't indefinitely amplify priority (anti-fatigue damping).
 */
export function computeRepetitionFeature(repeatCount: number): number {
  if (!Number.isFinite(repeatCount) || repeatCount <= 1) return 0;
  if (repeatCount <= 4) {
    return clamp((repeatCount - 1) * 0.28, 0, 0.85);
  }
  // Fatigue damping beyond 4 repeats within window
  const excess = repeatCount - 4;
  return clamp(0.85 * Math.exp(-0.22 * excess), 0.15, 0.85);
}

export function normalizePriorityThresholds(
  input?: Partial<PriorityThresholds>
): PriorityThresholds {
  const hysteresis = clamp(input?.hysteresis ?? DEFAULT_THRESHOLDS.hysteresis, 0.01, 0.12);
  const normal = clamp(input?.normal ?? DEFAULT_THRESHOLDS.normal, 0.1, 0.55);
  const high = clamp(input?.high ?? DEFAULT_THRESHOLDS.high, normal + 0.05, 0.82);
  const critical = clamp(input?.critical ?? DEFAULT_THRESHOLDS.critical, high + 0.05, 0.98);
  return { critical, high, normal, hysteresis };
}

/**
 * Maps score p in [0, 1] to priority label using thresholds + hysteresis band.
 * Hysteresis prevents rapid label flickering when p hovers around a boundary.
 */
export function mapScoreToLabelWithHysteresis(
  p: number,
  thresholds: PriorityThresholds = DEFAULT_THRESHOLDS,
  previousLabel?: SigmoidPriorityLabel
): SigmoidPriorityLabel {
  const t = normalizePriorityThresholds(thresholds);
  const h = t.hysteresis;

  if (!previousLabel) {
    if (p >= t.critical) return 'CRITICAL';
    if (p >= t.high) return 'HIGH';
    if (p >= t.normal) return 'NORMAL';
    return 'LOW';
  }

  // With hysteresis: hold current band until p crosses boundary +/- h/2
  const halfH = h / 2;
  if (previousLabel === 'CRITICAL') {
    if (p >= t.critical - halfH) return 'CRITICAL';
    if (p >= t.high) return 'HIGH';
    if (p >= t.normal) return 'NORMAL';
    return 'LOW';
  }
  if (previousLabel === 'HIGH') {
    if (p >= t.critical + halfH) return 'CRITICAL';
    if (p >= t.high - halfH) return 'HIGH';
    if (p >= t.normal) return 'NORMAL';
    return 'LOW';
  }
  if (previousLabel === 'NORMAL') {
    if (p >= t.critical) return 'CRITICAL';
    if (p >= t.high + halfH) return 'HIGH';
    if (p >= t.normal - halfH) return 'NORMAL';
    return 'LOW';
  }
  // previousLabel === 'LOW'
  if (p >= t.critical) return 'CRITICAL';
  if (p >= t.high) return 'HIGH';
  if (p >= t.normal + halfH) return 'NORMAL';
  return 'LOW';
}

export function computeLogitAndContributions(
  features: FeatureVector,
  weights: WeightVector,
  bias: number
): { z: number; contributions: FeatureContribution[] } {
  const validated = assertFiniteFeatures(features);
  if (!Number.isFinite(bias)) {
    throw new Error(`Bias must be a finite number (received ${String(bias)}).`);
  }
  let z = bias;
  const contributions: FeatureContribution[] = [];

  for (const name of PRIORITY_FEATURE_NAMES) {
    const w = weights[name];
    if (typeof w !== 'number' || !Number.isFinite(w)) {
      throw new Error(`Weight for "${name}" must be finite (received ${String(w)}).`);
    }
    const x = validated[name];
    const contrib = w * x;
    z += contrib;
    contributions.push({
      feature: name,
      label: FEATURE_DISPLAY_LABELS[name],
      value: Number(x.toFixed(4)),
      weight: Number(w.toFixed(4)),
      contribution: Number(contrib.toFixed(4)),
    });
  }

  contributions.sort((a, b) => Math.abs(b.contribution) - Math.abs(a.contribution));
  return { z, contributions };
}

export interface ScoreNotificationParams {
  features: FeatureVector;
  weights?: WeightVector;
  bias?: number;
  thresholds?: Partial<PriorityThresholds>;
  previousLabel?: SigmoidPriorityLabel;
  elapsedSeconds?: number;
  isAcked?: boolean;
  activeMode?: 'PERSONALIZED' | 'GLOBAL_DEFAULT';
  ruleContext?: HardRuleContext;
}

/**
 * Full transparent logistic regression scoring with:
 * 1) Base score pBase at ageFactor=0
 * 2) Dynamic time escalation (capped at +0.25 above pBase and 0.99 ceiling, stops when acked)
 * 3) Staleness decay for LOW items
 * 4) Threshold mapping with hysteresis
 * 5) Deterministic hard safety rules
 */
export function scoreNotification(params: ScoreNotificationParams) {
  const weights = params.weights ?? DEFAULT_WEIGHTS;
  const bias = params.bias ?? DEFAULT_BIAS;
  const thresholds = normalizePriorityThresholds(params.thresholds);

  const ageFactor =
    typeof params.elapsedSeconds === 'number'
      ? computeAgeFactor(params.elapsedSeconds, Boolean(params.isAcked))
      : params.isAcked
        ? 0
        : params.features.ageFactor;

  const featuresWithAge: FeatureVector = assertFiniteFeatures({
    ...params.features,
    ageFactor,
  });

  // Compute baseline (ageFactor = 0) so we can strictly enforce +0.25 escalation cap
  const baseFeatures: FeatureVector = { ...featuresWithAge, ageFactor: 0 };
  const baseRes = computeLogitAndContributions(baseFeatures, weights, bias);
  const pBase = sigmoid(baseRes.z);
  const baseLabel = mapScoreToLabelWithHysteresis(pBase, thresholds);

  const liveRes = computeLogitAndContributions(featuresWithAge, weights, bias);
  const rawP = sigmoid(liveRes.z);

  const maxAllowedBoost = DEFAULT_PRIORITY_ARTIFACT.hyperparams.ageMaxBoost; // 0.25
  const ceiling = DEFAULT_PRIORITY_ARTIFACT.hyperparams.ageMaxCeiling; // 0.99
  const maxAllowedP = Math.min(ceiling, pBase + maxAllowedBoost);

  let effectiveP = rawP;
  let escalationCapped = false;
  if (!params.isAcked && effectiveP > maxAllowedP && rawP > pBase) {
    effectiveP = maxAllowedP;
    escalationCapped = true;
  }

  const decayApplied =
    typeof params.elapsedSeconds === 'number'
      ? computeDecayPenalty(params.elapsedSeconds, baseLabel, Boolean(params.isAcked))
      : 0;
  if (decayApplied > 0 && ageFactor <= 0.15) {
    effectiveP = clamp(effectiveP - decayApplied, 0.001, 0.999);
  }

  const ageBoostApplied = Math.max(0, Number((effectiveP - pBase).toFixed(4)));
  const modelLabel = mapScoreToLabelWithHysteresis(
    effectiveP,
    thresholds,
    params.previousLabel
  );

  // Build rule context automatically if omitted, while preserving explicit overrides
  const inferredContext: HardRuleContext = {
    isSecurityAlert: featuresWithAge.category_security >= 0.5,
    isPromo: featuresWithAge.category_promo >= 0.5,
    senderTrust: featuresWithAge.senderTrust,
    isProvenanceVerified: featuresWithAge.senderTrust >= 0.65,
    ...params.ruleContext,
  };

  const ruleOutcome = applyHardSafetyRules({
    modelLabel,
    p: effectiveP,
    features: featuresWithAge,
    context: inferredContext,
  });

  const appliedRules: AppliedHardRule[] = ruleOutcome.appliedRules;

  return {
    p: Number(effectiveP.toFixed(4)),
    pBase: Number(pBase.toFixed(4)),
    rawP: Number(rawP.toFixed(4)),
    z: Number(liveRes.z.toFixed(4)),
    bias: Number(bias.toFixed(4)),
    label: ruleOutcome.finalLabel,
    modelLabel,
    contributions: liveRes.contributions,
    appliedRules,
    thresholdUsed: thresholds,
    activeMode: params.activeMode ?? 'GLOBAL_DEFAULT',
    escalationCapped,
    ageBoostApplied,
    decayApplied: Number(decayApplied.toFixed(4)),
    features: featuresWithAge,
    scoredAt: new Date().toISOString(),
  };
}

export function toLegacyNotificationPriority(
  label: SigmoidPriorityLabel
): LegacyNotificationPriority {
  if (label === 'NORMAL') return 'MEDIUM';
  return label;
}

export function fromLegacyPriority(
  label?: string | null
): SigmoidPriorityLabel {
  const upper = String(label || 'NORMAL').trim().toUpperCase();
  if (upper === 'CRITICAL') return 'CRITICAL';
  if (upper === 'HIGH') return 'HIGH';
  if (upper === 'LOW') return 'LOW';
  return 'NORMAL';
}
