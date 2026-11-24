import { describe, it, expect, beforeEach } from 'vitest';
import jwt from 'jsonwebtoken';
import { getJwtSecret } from '../../auth/jwtSecret.js';
import {
  DEFAULT_BIAS,
  DEFAULT_WEIGHTS,
  TFIDF_DEFAULT_MODEL_SUMMARY,
  assertFiniteFeatures,
  computeAgeFactor,
  computeDecayPenalty,
  computeLogitAndContributions,
  computeRepetitionFeature,
  logit,
  mapScoreToLabelWithHysteresis,
  scoreNotification,
  sigmoid,
} from '../math.js';
import { classifyTextWithDefaultWeights } from '../tfidfModel.js';
import {
  computeRegularizedLogLoss,
  computeWeightDrift,
  createDefaultUserPriorityModelState,
  shouldUsePersonalizedWeights,
  stepOnlineLogisticRegression,
} from '../learning.js';
import { applyHardSafetyRules } from '../rules.js';
import {
  computeTextImportanceScore,
  extractFeaturesFromContent,
  validateNumericOnlyScoreInput,
} from '../features.js';
import { runPrioritySimulationSuite } from '../simulator.js';
import { resetUserPriorityModel, scoreForUser } from '../store.js';
import { rescorePriorityOnRecipientDevice } from '../../provenance/clientVerify.js';
import { GET as getPriorityModelRoute } from '../../../app/api/v1/priority/model/route.js';
import { GET as getPriorityStatsRoute } from '../../../app/api/v1/priority/stats/route.js';
import { PRIORITY_FEATURE_NAMES, type FeatureVector } from '../types.js';

const JWT_SECRET = getJwtSecret();

function makeFeatures(overrides: Partial<FeatureVector> = {}): FeatureVector {
  return {
    textScore: 0.45,
    keywordUrgency: 0.2,
    senderTrust: 0.8,
    sourceReliability: 0.8,
    category_security: 0,
    category_finance: 0,
    category_work: 1,
    category_social: 0,
    category_promo: 0,
    ageFactor: 0,
    userContext: 0.75,
    repetition: 0,
    userAffinity: 0.6,
    senderClaimedPriority: 0.45,
    ...overrides,
  };
}

describe('Dynamic Sigmoid Priority Engine — Math, Learning, Safety & Privacy', () => {
  beforeEach(() => {
    resetUserPriorityModel('test-user-priority-suite', { reason: 'unit test reset' });
  });

  it('computes sigmoid symmetrically with overflow/underflow protection', () => {
    expect(sigmoid(0)).toBe(0.5);
    expect(sigmoid(1000)).toBeLessThanOrEqual(1);
    expect(sigmoid(1000)).toBeGreaterThan(0.9999);
    expect(sigmoid(-1000)).toBeGreaterThanOrEqual(0);
    expect(sigmoid(-1000)).toBeLessThan(0.0001);
    expect(Number.isNaN(sigmoid(1000))).toBe(false);
    expect(Number.isNaN(sigmoid(-1000))).toBe(false);

    for (const z of [-7.5, -2.1, 0, 1.35, 5.8]) {
      expect(sigmoid(-z)).toBeCloseTo(1 - sigmoid(z), 12);
    }

    for (const p of [0.05, 0.25, 0.5, 0.75, 0.95]) {
      expect(sigmoid(logit(p))).toBeCloseTo(p, 10);
    }
  });

  it('rejects NaN, Infinity, and out-of-range features and forbids raw text payloads', () => {
    const valid = makeFeatures();
    expect(() => assertFiniteFeatures({ ...valid, textScore: Number.NaN })).toThrow();
    expect(() => assertFiniteFeatures({ ...valid, senderTrust: Number.POSITIVE_INFINITY })).toThrow();
    expect(() => assertFiniteFeatures({ ...valid, userContext: 1.4 })).toThrow();
    expect(() => assertFiniteFeatures({ ...valid, userAffinity: -0.1 })).toThrow();

    const rejectedMessage = validateNumericOnlyScoreInput({
      message: 'Secret OTP 999111 inside body',
      ...valid,
    });
    expect(rejectedMessage.ok).toBe(false);

    const rejectedNestedBody = validateNumericOnlyScoreInput({
      features: { ...valid, plaintext: 'hello' },
    });
    expect(rejectedNestedBody.ok).toBe(false);

    const acceptedNumeric = validateNumericOnlyScoreInput({ features: valid });
    expect(acceptedNumeric.ok).toBe(true);
  });

  it('implements monotonic time escalation capped at +0.25/0.99 and stops immediately on ACK', () => {
    const features = makeFeatures({
      textScore: 0.45,
      keywordUrgency: 0.25,
      category_work: 1,
      senderTrust: 0.7,
    });

    const t0 = scoreNotification({ features, elapsedSeconds: 0, isAcked: false });
    const t60 = scoreNotification({ features, elapsedSeconds: 60, isAcked: false });
    const t240 = scoreNotification({ features, elapsedSeconds: 240, isAcked: false });
    const t3600 = scoreNotification({ features, elapsedSeconds: 3600, isAcked: false });
    const ackedAt3600 = scoreNotification({ features, elapsedSeconds: 3600, isAcked: true });

    expect(computeAgeFactor(0, false)).toBe(0);
    expect(computeAgeFactor(3600, true)).toBe(0);
    expect(t60.p).toBeGreaterThanOrEqual(t0.p);
    expect(t240.p).toBeGreaterThanOrEqual(t60.p);
    expect(t3600.p).toBeLessThanOrEqual(Math.min(0.99, t0.pBase + 0.25) + 1e-6);
    expect(ackedAt3600.p).toBe(t0.pBase);
    expect(ackedAt3600.ageBoostApplied).toBe(0);

    // Gentle staleness decay on stale LOW items
    const decay = computeDecayPenalty(7200, 'LOW', false);
    expect(decay).toBeGreaterThan(0);
    expect(computeDecayPenalty(7200, 'LOW', true)).toBe(0);
  });

  it('prevents label flickering near boundaries via hysteresis', () => {
    const thresholds = { critical: 0.85, high: 0.65, normal: 0.35, hysteresis: 0.04 };
    // Inside [0.83, 0.87] stays sticky to previous band
    expect(mapScoreToLabelWithHysteresis(0.84, thresholds, 'CRITICAL')).toBe('CRITICAL');
    expect(mapScoreToLabelWithHysteresis(0.86, thresholds, 'HIGH')).toBe('HIGH');
    // Clearly past half-hysteresis flips cleanly
    expect(mapScoreToLabelWithHysteresis(0.88, thresholds, 'HIGH')).toBe('CRITICAL');
    expect(mapScoreToLabelWithHysteresis(0.81, thresholds, 'CRITICAL')).toBe('HIGH');
  });

  it('matches finite-difference numerical gradient of regularized logistic loss', () => {
    const features = makeFeatures({
      textScore: 0.72,
      keywordUrgency: 0.4,
      senderTrust: 0.9,
      category_finance: 1,
      category_work: 0,
    });
    const weights = { ...DEFAULT_WEIGHTS };
    const bias = DEFAULT_BIAS;
    const lambda = 0.01;
    const targetY = 1;

    const { z } = computeLogitAndContributions(features, weights, bias);
    const p = sigmoid(z);
    const eps = 1e-6;

    for (const name of PRIORITY_FEATURE_NAMES) {
      const analyticGrad = (p - targetY) * features[name] + lambda * weights[name];
      const plus = { ...weights, [name]: weights[name] + eps };
      const minus = { ...weights, [name]: weights[name] - eps };
      const lossPlus = computeRegularizedLogLoss(features, plus, bias, targetY, lambda);
      const lossMinus = computeRegularizedLogLoss(features, minus, bias, targetY, lambda);
      const numericGrad = (lossPlus - lossMinus) / (2 * eps);
      expect(analyticGrad).toBeCloseTo(numericGrad, 5);
    }
  });

  it('updates SGD in the right direction, enforces bounds [-4, 4] and security floor, and respects cold-start threshold', () => {
    let state = createDefaultUserPriorityModelState('sgd-test');
    const feat = makeFeatures({ textScore: 0.65, category_finance: 1, category_work: 0 });

    const before = scoreNotification({ features: feat, weights: state.weights, bias: state.bias }).p;
    const up = stepOnlineLogisticRegression({
      state,
      features: feat,
      feedbackKind: 'MORE_IMPORTANT',
    });
    expect(up.predictedPAfter).toBeGreaterThan(before);

    // Cold-start gate stays GLOBAL_DEFAULT until 20 feedbacks
    state = up.updatedState;
    expect(shouldUsePersonalizedWeights(state.feedbackCount, true)).toBe(false);

    // Repeated negative feedback on security alert must keep security weight >= 1.0 and within [-4, 4]
    let secState = createDefaultUserPriorityModelState('sec-poison-test');
    const secFeat = makeFeatures({ category_security: 1, category_work: 0, textScore: 0.9 });
    for (let i = 0; i < 40; i++) {
      secState = stepOnlineLogisticRegression({
        state: secState,
        features: secFeat,
        feedbackKind: 'LESS_IMPORTANT',
      }).updatedState;
    }

    expect(shouldUsePersonalizedWeights(secState.feedbackCount, true)).toBe(true);
    expect(secState.weights.category_security).toBeGreaterThanOrEqual(1.0);
    for (const name of PRIORITY_FEATURE_NAMES) {
      expect(secState.weights[name]).toBeGreaterThanOrEqual(-4);
      expect(secState.weights[name]).toBeLessThanOrEqual(4);
    }

    const drift = computeWeightDrift(secState.weights);
    expect(drift.l2Distance).toBeGreaterThanOrEqual(0);
  });

  it('enforces all 4 hard deterministic safety rules cleanly', () => {
    // 1. SECURITY_FLOOR
    const r1 = applyHardSafetyRules({
      modelLabel: 'LOW',
      p: 0.12,
      features: makeFeatures({ category_security: 1, category_work: 0 }),
      context: { isSecurityAlert: true, isAccountAtRisk: true },
    });
    expect(r1.finalLabel).toBe('CRITICAL');
    expect(r1.appliedRules.some((r) => r.rule === 'SECURITY_FLOOR')).toBe(true);

    // 2. UNSIGNED_PROMO_CAP
    const r2 = applyHardSafetyRules({
      modelLabel: 'CRITICAL',
      p: 0.92,
      features: makeFeatures({ category_promo: 1, category_work: 0, senderTrust: 0.2 }),
      context: { isPromo: true, isProvenanceVerified: false, senderTrust: 0.2 },
    });
    expect(r2.finalLabel).toBe('NORMAL');
    expect(r2.appliedRules.some((r) => r.rule === 'UNSIGNED_PROMO_CAP')).toBe(true);

    // 3. SENDER_CLAIM_WEAK
    const r3 = applyHardSafetyRules({
      modelLabel: 'NORMAL',
      p: 0.48,
      features: makeFeatures({ senderClaimedPriority: 1.0, senderTrust: 0.3, textScore: 0.25 }),
    });
    expect(r3.appliedRules.some((r) => r.rule === 'SENDER_CLAIM_WEAK')).toBe(true);

    // 4. HOURLY_CRITICAL_BUDGET
    const r4 = applyHardSafetyRules({
      modelLabel: 'CRITICAL',
      p: 0.93,
      features: makeFeatures(),
      context: {
        source: 'noisy-ci',
        hourlyCriticalCountForSource: 8,
        hourlyCriticalBudget: 8,
        isAccountAtRisk: false,
      },
    });
    expect(r4.finalLabel).toBe('HIGH');
    expect(r4.appliedRules.some((r) => r.rule === 'HOURLY_CRITICAL_BUDGET')).toBe(true);
  });

  it('damps high burst repetition and rescores on recipient device without exceeding signed ceiling + 1', () => {
    expect(computeRepetitionFeature(3)).toBeGreaterThan(computeRepetitionFeature(1));
    expect(computeRepetitionFeature(15)).toBeLessThan(computeRepetitionFeature(4));

    const signal = computeTextImportanceScore('Unauthorized new device login OTP required!');
    expect(signal.detectedCategory).toBe('security');
    expect(signal.textScore).toBeGreaterThan(0.6);

    const extracted = extractFeaturesFromContent({
      plaintextInMemory: 'Flash discount coupon sale!!',
      provenanceTrustScore: 0.2,
    });
    expect(extracted.category_promo).toBe(1);

    const rescored = rescorePriorityOnRecipientDevice({
      baseFeatures: makeFeatures({ textScore: 0.2, category_work: 1, senderTrust: 0.8 }),
      provenanceVerified: true,
      provenanceEnvelope: {
        v: 1,
        payload: {
          v: 1,
          alg: 'Ed25519',
          messageId: 'm1',
          senderId: 's1',
          recipientId: 'u1',
          source: 'direct',
          priority: 'LOW',
          ciphertextHash: 'abc',
          createdAt: new Date().toISOString(),
          nonce: 'n1',
          kid: 'k1',
          textScore: 0.2,
          signedPriorityLabel: 'LOW',
        },
        chain: [],
      },
      elapsedSeconds: 300,
      isAcked: false,
    });
    // Signed label was LOW -> max allowed local escalation is +1 level (NORMAL)
    expect(['LOW', 'NORMAL']).toContain(rescored.label);

    const scored = scoreForUser({
      userId: 'test-user-priority-suite',
      features: makeFeatures({ category_work: 1 }),
      source: 'test-source',
      recordStats: false,
    });
    expect(scored.p).toBeGreaterThan(0);
    expect(scored.p).toBeLessThan(1);
  });

  it('loads the imported Colab defaultWeights.json TF-IDF multiclass weights and scores messages cleanly', () => {
    expect(TFIDF_DEFAULT_MODEL_SUMMARY.loaded).toBe(true);
    expect(TFIDF_DEFAULT_MODEL_SUMMARY.modelType).toBe('tfidf_logistic_regression_multiclass');
    expect(TFIDF_DEFAULT_MODEL_SUMMARY.vocabularySize).toBeGreaterThan(2000);
    expect(TFIDF_DEFAULT_MODEL_SUMMARY.evaluationMetrics.test_accuracy).toBeCloseTo(0.9717, 4);
    expect(TFIDF_DEFAULT_MODEL_SUMMARY.evaluationMetrics.test_f1_macro).toBeCloseTo(0.9741, 4);
    expect(TFIDF_DEFAULT_MODEL_SUMMARY.evaluationMetrics.test_roc_auc_ovr_macro).toBeCloseTo(0.9825, 4);

    const sec = classifyTextWithDefaultWeights(
      'Unauthorized login attempt detected, OTP required immediately',
      'security'
    );
    expect(sec.matchedTermsCount).toBeGreaterThan(0);
    expect(['Critical', 'High']).toContain(sec.predictedClass);
    expect(sec.tfidfImportanceScore).toBeGreaterThan(0.6);

    const promo = classifyTextWithDefaultWeights(
      'Flash sale 50% discount coupon cashback offer limited time',
      'promo'
    );
    expect(['Low', 'Normal']).toContain(promo.predictedClass);
  });

  it('exposes the imported defaultWeights.json summary on /api/v1/priority/model and /api/v1/priority/stats', async () => {
    const adminToken = jwt.sign(
      { userId: 'priority-test-admin', role: 'ADMIN', email: 'admin@test.local' },
      JWT_SECRET,
      { expiresIn: '1h' }
    );

    const modelRes = await getPriorityModelRoute(
      new Request('http://localhost/api/v1/priority/model', {
        headers: { Authorization: `Bearer ${adminToken}` },
      })
    );
    expect(modelRes.status).toBe(200);
    const modelJson = await modelRes.json();
    expect(modelJson.data.tfidfDefaultModel.loaded).toBe(true);
    expect(modelJson.data.tfidfDefaultModel.vocabularySize).toBe(TFIDF_DEFAULT_MODEL_SUMMARY.vocabularySize);
    expect(modelJson.data.tfidfDefaultModel.evaluationMetrics.test_accuracy).toBeCloseTo(0.9717, 4);

    const statsRes = await getPriorityStatsRoute(
      new Request('http://localhost/api/v1/priority/stats', {
        headers: { Authorization: `Bearer ${adminToken}` },
      })
    );
    expect(statsRes.status).toBe(200);
    const statsJson = await statsRes.json();
    expect(statsJson.data.tfidfDefaultModel.loaded).toBe(true);
    expect(statsJson.data.tfidfDefaultModel.classes).toEqual(['Critical', 'High', 'Low', 'Normal']);
  });

  it('passes all 9 isolated attack & robustness simulator scenarios (a-i)', () => {
    const suite = runPrioritySimulationSuite({ actorUserId: 'vitest-admin' });
    expect(suite.scenarios).toHaveLength(9);
    expect(suite.allPassed).toBe(true);
    for (const s of suite.scenarios) {
      expect(s.passed).toBe(true);
    }
  });
});
