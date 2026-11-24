import {
  DEFAULT_BIAS,
  DEFAULT_PRIORITY_ARTIFACT,
  DEFAULT_THRESHOLDS,
  DEFAULT_WEIGHTS,
  assertFiniteFeatures,
  clamp,
  computeLogitAndContributions,
  sigmoid,
} from './math.js';
import {
  PRIORITY_FEATURE_NAMES,
  type FeatureVector,
  type PriorityFeedbackKind,
  type PriorityLearningResult,
  type UserPriorityModelState,
  type WeightVector,
} from './types.js';

export function feedbackKindToTargetY(kind: PriorityFeedbackKind): number {
  switch (kind) {
    case 'MORE_IMPORTANT':
    case 'ACKED_FAST':
      return 1;
    case 'LESS_IMPORTANT':
    case 'IGNORED':
    case 'MARKED_SPAM':
      return 0;
  }
}

export function shouldUsePersonalizedWeights(
  feedbackCount: number,
  personalizationEnabled: boolean
): boolean {
  const coldStart = DEFAULT_PRIORITY_ARTIFACT.hyperparams.coldStartFeedbackThreshold;
  return Boolean(personalizationEnabled && feedbackCount >= coldStart);
}

export function computeWeightDrift(
  weights: WeightVector,
  referenceWeights: WeightVector = DEFAULT_WEIGHTS
): { l2Distance: number; driftWarning: boolean } {
  let sumSq = 0;
  for (const name of PRIORITY_FEATURE_NAMES) {
    const diff = (weights[name] ?? 0) - (referenceWeights[name] ?? 0);
    sumSq += diff * diff;
  }
  const l2Distance = Number(Math.sqrt(sumSq).toFixed(4));
  const threshold = DEFAULT_PRIORITY_ARTIFACT.hyperparams.driftL2WarningThreshold;
  return {
    l2Distance,
    driftWarning: l2Distance > threshold,
  };
}

/**
 * Computes binary cross-entropy loss with L2 penalty for gradient verification:
 *   L(w, b) = -[y * log(p) + (1 - y) * log(1 - p)] + (lambda / 2) * ||w||^2
 */
export function computeRegularizedLogLoss(
  features: FeatureVector,
  weights: WeightVector,
  bias: number,
  targetY: number,
  l2Lambda = DEFAULT_PRIORITY_ARTIFACT.hyperparams.l2Regularization
): number {
  const { z } = computeLogitAndContributions(features, weights, bias);
  const p = clamp(sigmoid(z), 1e-12, 1 - 1e-12);
  const bce = -(targetY * Math.log(p) + (1 - targetY) * Math.log(1 - p));
  let l2 = 0;
  for (const name of PRIORITY_FEATURE_NAMES) {
    const w = weights[name];
    l2 += w * w;
  }
  return bce + 0.5 * l2Lambda * l2;
}

/**
 * Single bounded online SGD logistic regression update:
 *   grad_w_i = clip((p - y) * x_i + lambda * w_i, -clip, +clip)
 *   w_i <- clamp(w_i - lr * grad_w_i, -4, 4)
 * With security floor lock so category_security weight never falls below default minimum,
 * and senderClaimedPriority stays bounded as a weak signal.
 */
export function stepOnlineLogisticRegression(params: {
  state: UserPriorityModelState;
  features: FeatureVector;
  feedbackKind: PriorityFeedbackKind;
  l2Lambda?: number;
  baseLearningRate?: number;
}): PriorityLearningResult {
  const validated = assertFiniteFeatures(params.features);
  const hp = DEFAULT_PRIORITY_ARTIFACT.hyperparams;
  const l2Lambda = params.l2Lambda ?? hp.l2Regularization;
  const baseLr = params.baseLearningRate ?? hp.learningRate;

  const y = feedbackKindToTargetY(params.feedbackKind);
  const nextFeedbackCount = params.state.feedbackCount + 1;

  // Gentle schedule decay so early feedback adapts briskly and late weights stabilize
  const effectiveLr = Number(
    clamp(baseLr / (1 + 0.02 * params.state.feedbackCount), 0.01, baseLr).toFixed(5)
  );

  const beforeRes = computeLogitAndContributions(validated, params.state.weights, params.state.bias);
  const pBefore = sigmoid(beforeRes.z);
  const err = pBefore - y; // d(BCE)/dz

  const nextWeights: WeightVector = { ...params.state.weights };
  let maxAbsWeightDelta = 0;
  let securityFloorLocked = false;

  for (const name of PRIORITY_FEATURE_NAMES) {
    const x = validated[name];
    const w = params.state.weights[name];
    const rawGrad = err * x + l2Lambda * w;
    const clippedGrad = clamp(rawGrad, -hp.gradientClip, hp.gradientClip);
    let updated = w - effectiveLr * clippedGrad;

    // Hard bounds [-4, 4]
    updated = clamp(updated, hp.weightMin, hp.weightMax);

    // Protect security alerts from adversarial negative-feedback poisoning
    if (name === 'category_security' && updated < hp.securityFloorMinWeight) {
      updated = Math.max(hp.securityFloorMinWeight, DEFAULT_WEIGHTS.category_security * 0.75);
      securityFloorLocked = true;
    }

    // Keep senderClaimedPriority as a weak signal even if feedback tries to boost it
    if (name === 'senderClaimedPriority') {
      updated = clamp(updated, -0.35, 0.35);
    }

    const delta = Math.abs(updated - w);
    if (delta > maxAbsWeightDelta) {
      maxAbsWeightDelta = delta;
    }
    nextWeights[name] = Number(updated.toFixed(5));
  }

  // Bias gradient (no L2 decay on bias, gently clipped)
  const biasGrad = clamp(err, -hp.gradientClip, hp.gradientClip);
  const nextBias = Number(
    clamp(params.state.bias - effectiveLr * 0.5 * biasGrad, -6, 6).toFixed(5)
  );

  const afterRes = computeLogitAndContributions(validated, nextWeights, nextBias);
  const pAfter = sigmoid(afterRes.z);

  const { l2Distance, driftWarning } = computeWeightDrift(nextWeights, DEFAULT_WEIGHTS);
  const nowIso = new Date().toISOString();

  const snapshot = {
    step: nextFeedbackCount,
    timestamp: nowIso,
    feedbackKind: params.feedbackKind,
    deltaL2FromDefault: l2Distance,
    weights: { ...nextWeights },
    bias: nextBias,
  };

  const nextHistory = [...(params.state.weightHistory || []), snapshot].slice(-60);

  const updatedState: UserPriorityModelState = {
    ...params.state,
    version: params.state.version + 1,
    feedbackCount: nextFeedbackCount,
    bias: nextBias,
    weights: nextWeights,
    driftWarning,
    driftL2Distance: l2Distance,
    updatedAt: nowIso,
    weightHistory: nextHistory,
  };

  return {
    updatedState,
    targetY: y,
    predictedPBefore: Number(pBefore.toFixed(4)),
    predictedPAfter: Number(pAfter.toFixed(4)),
    effectiveLearningRate: effectiveLr,
    maxAbsWeightDelta: Number(maxAbsWeightDelta.toFixed(5)),
    driftWarning,
    driftL2Distance: l2Distance,
    securityFloorLocked,
  };
}

export function createDefaultUserPriorityModelState(
  userId: string
): UserPriorityModelState {
  return {
    userId,
    version: 1,
    personalizationEnabled: true,
    feedbackCount: 0,
    bias: DEFAULT_BIAS,
    weights: { ...DEFAULT_WEIGHTS },
    thresholds: { ...DEFAULT_THRESHOLDS },
    urgentKeywords: ['otp', '2fa', 'breach', 'unauthorized', 'outage', 'incident', 'wire'],
    quietHours: {
      enabled: false,
      startHourUtc: 22,
      endHourUtc: 7,
      dndActive: false,
    },
    sourceReliability: {
      direct: 0.9,
      security: 0.98,
      'app-github': 0.85,
      'app-slack': 0.8,
      'app-discord': 0.65,
      'app-telegram': 0.72,
      webhook: 0.75,
      marketing: 0.2,
    },
    driftWarning: false,
    driftL2Distance: 0,
    updatedAt: new Date().toISOString(),
    weightHistory: [],
  };
}
