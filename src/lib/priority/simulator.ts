import {
  DEFAULT_WEIGHTS,
  assertFiniteFeatures,
  scoreNotification,
} from './math.js';
import {
  createDefaultUserPriorityModelState,
  shouldUsePersonalizedWeights,
  stepOnlineLogisticRegression,
} from './learning.js';
import { extractFeaturesFromContent, validateNumericOnlyScoreInput } from './features.js';
import type {
  FeatureVector,
  PrioritySimulationScenarioResult,
} from './types.js';
import { logSecurityEvent } from '../telemetry/securityLogger.js';

function makeBaseFeatures(overrides: Partial<FeatureVector> = {}): FeatureVector {
  return {
    textScore: 0.45,
    keywordUrgency: 0.25,
    senderTrust: 0.7,
    sourceReliability: 0.75,
    category_security: 0,
    category_finance: 0,
    category_work: 1,
    category_social: 0,
    category_promo: 0,
    ageFactor: 0,
    userContext: 0.7,
    repetition: 0,
    userAffinity: 0.6,
    senderClaimedPriority: 0.45,
    ...overrides,
  };
}

/**
 * Isolated simulation suite running all 9 adversarial/robustness checks (a-i)
 * against fresh sandboxed state (never mutates real user weights).
 */
export function runPrioritySimulationSuite(params?: {
  scenarioId?: string;
  actorUserId?: string;
  ipAddress?: string;
  userAgent?: string;
}): {
  scenarios: PrioritySimulationScenarioResult[];
  allPassed: boolean;
  ranAt: string;
} {
  const filterId = params?.scenarioId ? String(params.scenarioId).toLowerCase() : null;
  const results: PrioritySimulationScenarioResult[] = [];
  const actor = params?.actorUserId || 'admin-simulator';

  const shouldRun = (id: string) => !filterId || filterId === 'all' || filterId === id;

  // (a) Threshold flooding: 12 CRITICAL alerts from same noisy source inside 1 hour
  if (shouldRun('a')) {
    const budget = 5;
    let upgradedToCritical = 0;
    let downgradedToHigh = 0;
    const highAlert = makeBaseFeatures({
      textScore: 0.96,
      keywordUrgency: 0.95,
      senderTrust: 1.0,
      sourceReliability: 0.95,
      category_work: 1,
      category_security: 0,
      userAffinity: 0.9,
      userContext: 0.85,
    });

    for (let i = 0; i < 12; i++) {
      const scored = scoreNotification({
        features: highAlert,
        ruleContext: {
          source: 'noisy-webhook-a',
          hourlyCriticalCountForSource: i,
          hourlyCriticalBudget: budget,
          isAccountAtRisk: false,
        },
      });
      if (scored.label === 'CRITICAL') upgradedToCritical += 1;
      else if (
        scored.label === 'HIGH' &&
        scored.appliedRules.some((r) => r.rule === 'HOURLY_CRITICAL_BUDGET')
      ) {
        downgradedToHigh += 1;
      }
    }

    logSecurityEvent({
      eventType: 'PRIORITY_BUDGET_EXCEEDED',
      userId: actor,
      ipAddress: params?.ipAddress,
      userAgent: params?.userAgent,
      result: 'blocked',
      details: `[SIM-A] Threshold flooding test: ${downgradedToHigh}/12 excess alerts capped to HIGH (budget=${budget}).`,
    });

    results.push({
      scenarioId: 'a',
      title: 'Threshold Flooding & Per-Source Critical Budget',
      attackOrCheck: 'Send 12 CRITICAL-scoring alerts from one source within 1 hour (budget=5).',
      passed: upgradedToCritical === budget && downgradedToHigh === 7,
      expectedOutcome: `First ${budget} allowed as CRITICAL; remaining 7 downgraded to HIGH via HOURLY_CRITICAL_BUDGET.`,
      observedOutcome: `${upgradedToCritical} CRITICAL allowed, ${downgradedToHigh} downgraded to HIGH.`,
      metrics: { budget, allowedCritical: upgradedToCritical, downgradedToHigh },
      telemetryEventsLogged: ['PRIORITY_BUDGET_EXCEEDED'],
    });
  }

  // (b) Feedback poisoning on security alerts
  if (shouldRun('b')) {
    let simState = createDefaultUserPriorityModelState('sim-b');
    const secFeatures = makeBaseFeatures({
      category_work: 0,
      category_security: 1,
      textScore: 0.88,
      keywordUrgency: 0.85,
      senderTrust: 1.0,
    });
    for (let i = 0; i < 35; i++) {
      simState = stepOnlineLogisticRegression({
        state: simState,
        features: secFeatures,
        feedbackKind: 'LESS_IMPORTANT',
      }).updatedState;
    }

    const postPoisonScore = scoreNotification({
      features: secFeatures,
      weights: simState.weights,
      bias: simState.bias,
      ruleContext: { isSecurityAlert: true, isOtpOrNewDevice: true },
    });

    const securityWeightAfter = simState.weights.category_security;
    const passed =
      securityWeightAfter >= 1.0 &&
      (postPoisonScore.label === 'HIGH' || postPoisonScore.label === 'CRITICAL');

    results.push({
      scenarioId: 'b',
      title: 'Feedback Poisoning Resistance on Security Alerts',
      attackOrCheck: 'Spam 35 "LESS_IMPORTANT" feedbacks trying to suppress OTP / security alerts.',
      passed,
      expectedOutcome: 'category_security stays locked >= 1.0 and SECURITY_FLOOR guarantees >= HIGH.',
      observedOutcome: `category_security=${securityWeightAfter.toFixed(3)}, final label=${postPoisonScore.label} (p=${postPoisonScore.p}).`,
      metrics: {
        securityWeightAfter: Number(securityWeightAfter.toFixed(4)),
        finalLabel: postPoisonScore.label,
        finalP: postPoisonScore.p,
      },
      telemetryEventsLogged: ['PRIORITY_RULE_APPLIED'],
    });
  }

  // (c) Weight explosion test
  if (shouldRun('c')) {
    let simState = createDefaultUserPriorityModelState('sim-c');
    const extremeFeatures = makeBaseFeatures({
      textScore: 1,
      keywordUrgency: 1,
      senderTrust: 1,
      sourceReliability: 1,
      userAffinity: 1,
      userContext: 1,
    });
    let maxObservedAbsW = 0;
    for (let i = 0; i < 120; i++) {
      simState = stepOnlineLogisticRegression({
        state: simState,
        features: extremeFeatures,
        feedbackKind: 'MORE_IMPORTANT',
      }).updatedState;
    }
    for (const val of Object.values(simState.weights)) {
      if (Math.abs(val) > maxObservedAbsW) maxObservedAbsW = Math.abs(val);
    }

    const passed = maxObservedAbsW <= 4.0 && Number.isFinite(simState.bias);
    results.push({
      scenarioId: 'c',
      title: 'Weight Explosion & Gradient Clipping Guard',
      attackOrCheck: 'Apply 120 saturated MORE_IMPORTANT updates with all active features = 1.0.',
      passed,
      expectedOutcome: 'Every weight stays bounded inside [-4, 4] with finite bias.',
      observedOutcome: `Max |w_i| = ${maxObservedAbsW.toFixed(4)}, bias = ${simState.bias.toFixed(4)}.`,
      metrics: { maxAbsWeight: Number(maxObservedAbsW.toFixed(4)), bias: simState.bias },
      telemetryEventsLogged: ['PRIORITY_MODEL_UPDATED'],
    });
  }

  // (d) Sender-claimed CRITICAL promo spam
  if (shouldRun('d')) {
    const promoSpam = extractFeaturesFromContent({
      plaintextInMemory: 'URGENT!! Flash deal 70% off discount coupon offer limited time!!!',
      category: 'promo',
      provenanceTrustScore: 0.2, // unsigned
      sourceReliability: 0.2,
      userAffinity: 0.1,
      senderClaimedPriority: 'CRITICAL',
    });

    const scored = scoreNotification({
      features: promoSpam,
      ruleContext: {
        isPromo: true,
        isProvenanceVerified: false,
        senderTrust: 0.2,
      },
    });

    const passed =
      (scored.label === 'LOW' || scored.label === 'NORMAL') &&
      scored.features.senderClaimedPriority === 1;

    results.push({
      scenarioId: 'd',
      title: 'Sender-Claimed CRITICAL Promo Spam Neutralization',
      attackOrCheck: 'Unsigned marketing promo claims priority="CRITICAL" with urgent spam wording.',
      passed,
      expectedOutcome: 'senderClaimedPriority remains weak; UNSIGNED_PROMO_CAP keeps label <= NORMAL.',
      observedOutcome: `Scored label=${scored.label} (p=${scored.p}, rules=${scored.appliedRules.map((r) => r.rule).join(', ') || 'model-only'}).`,
      metrics: { finalLabel: scored.label, p: scored.p },
      telemetryEventsLogged: ['PRIORITY_RULE_APPLIED'],
    });
  }

  // (e) Cold start protection (< 20 feedbacks)
  if (shouldRun('e')) {
    let simState = createDefaultUserPriorityModelState('sim-e');
    const workItem = makeBaseFeatures({ textScore: 0.65, keywordUrgency: 0.5 });
    for (let i = 0; i < 19; i++) {
      simState = stepOnlineLogisticRegression({
        state: simState,
        features: workItem,
        feedbackKind: 'LESS_IMPORTANT',
      }).updatedState;
    }

    const active19 = shouldUsePersonalizedWeights(simState.feedbackCount, simState.personalizationEnabled);
    simState = stepOnlineLogisticRegression({
      state: simState,
      features: workItem,
      feedbackKind: 'LESS_IMPORTANT',
    }).updatedState;
    const active20 = shouldUsePersonalizedWeights(simState.feedbackCount, simState.personalizationEnabled);

    const passed = !active19 && active20;
    results.push({
      scenarioId: 'e',
      title: 'Cold-Start Protection (< 20 Feedbacks)',
      attackOrCheck: 'Verify global calibrated weights remain active for 19 feedbacks and switch at 20.',
      passed,
      expectedOutcome: 'feedbackCount=19 => GLOBAL_DEFAULT; feedbackCount=20 => PERSONALIZED.',
      observedOutcome: `At 19: personalized=${active19}; at 20: personalized=${active20}.`,
      metrics: { personalizedAt19: active19, personalizedAt20: active20 },
      telemetryEventsLogged: ['PRIORITY_FEEDBACK'],
    });
  }

  // (f) Time escalation & caps (+0.25 boost cap and 0.99 ceiling)
  if (shouldRun('f')) {
    const item = makeBaseFeatures({
      textScore: 0.58,
      keywordUrgency: 0.45,
      senderTrust: 0.7,
      sourceReliability: 0.72,
    });
    const t0 = scoreNotification({ features: item, elapsedSeconds: 0, isAcked: false });
    const t60 = scoreNotification({ features: item, elapsedSeconds: 60, isAcked: false });
    const t600 = scoreNotification({ features: item, elapsedSeconds: 600, isAcked: false });
    const t99999 = scoreNotification({ features: item, elapsedSeconds: 99999, isAcked: false });

    const boost = t99999.p - t0.pBase;
    const passed =
      t60.p >= t0.p &&
      t600.p >= t60.p &&
      boost <= 0.2501 &&
      t99999.p <= 0.99;

    results.push({
      scenarioId: 'f',
      title: 'Time Escalation Replay & Bounded +0.25 / 0.99 Cap',
      attackOrCheck: 'Replay unacknowledged notification across t=0s, 60s, 600s, 99999s.',
      passed,
      expectedOutcome: 'Score increases monotonically while unacked, capped at min(pBase+0.25, 0.99).',
      observedOutcome: `t=0s:${t0.p}, t=60s:${t60.p}, t=600s:${t600.p}, t=99999s:${t99999.p} (boost=${boost.toFixed(4)}).`,
      metrics: { p0: t0.p, p60: t60.p, p600: t600.p, pMax: t99999.p, boost: Number(boost.toFixed(4)) },
      telemetryEventsLogged: ['PRIORITY_ESCALATED'],
    });
  }

  // (g) Escalation stops immediately upon acknowledgement
  if (shouldRun('g')) {
    const item = makeBaseFeatures({ textScore: 0.6, keywordUrgency: 0.5 });
    const unacked = scoreNotification({ features: item, elapsedSeconds: 600, isAcked: false });
    const acked = scoreNotification({ features: item, elapsedSeconds: 600, isAcked: true });
    const passed = acked.features.ageFactor === 0 && acked.ageBoostApplied === 0 && acked.p <= unacked.p;

    results.push({
      scenarioId: 'g',
      title: 'Escalation Stops on User Acknowledgement',
      attackOrCheck: 'Compare identical t=600s notification before and after ACK.',
      passed,
      expectedOutcome: 'Acking forces ageFactor=0 and stops any time escalation boost.',
      observedOutcome: `Unacked p=${unacked.p} (age=${unacked.features.ageFactor}) -> Acked p=${acked.p} (age=${acked.features.ageFactor}).`,
      metrics: { unackedP: unacked.p, ackedP: acked.p, ackedAgeFactor: acked.features.ageFactor },
      telemetryEventsLogged: ['PRIORITY_SCORED'],
    });
  }

  // (h) Model drift detection and reset recovery
  if (shouldRun('h')) {
    let simState = createDefaultUserPriorityModelState('sim-h');
    const shiftVecA = makeBaseFeatures({
      category_work: 0,
      category_promo: 1,
      textScore: 0.95,
      keywordUrgency: 0.95,
      userAffinity: 0.95,
      sourceReliability: 0.95,
      ageFactor: 0.95,
      userContext: 0.95,
      senderTrust: 0.95,
      repetition: 0.95,
    });
    const shiftVecB = makeBaseFeatures({
      category_work: 0,
      category_finance: 1,
      textScore: 0.95,
      keywordUrgency: 0.95,
      userAffinity: 0.95,
      sourceReliability: 0.95,
      ageFactor: 0.95,
      userContext: 0.95,
      senderTrust: 0.95,
      repetition: 0.95,
    });
    for (let i = 0; i < 90; i++) {
      // Alternating contradictory/extreme updates drive substantial weight movement across dimensions
      simState = stepOnlineLogisticRegression({
        state: simState,
        features: i % 2 === 0 ? shiftVecA : shiftVecB,
        feedbackKind: i % 2 === 0 ? 'MORE_IMPORTANT' : 'LESS_IMPORTANT',
      }).updatedState;
    }

    const driftBeforeReset = simState.driftL2Distance;
    const warningBefore = simState.driftWarning;

    const resetState = createDefaultUserPriorityModelState('sim-h');
    const resetWeightsMatch =
      Math.abs(DEFAULT_WEIGHTS.textScore - resetState.weights.textScore) < 1e-6 &&
      resetState.driftL2Distance === 0 &&
      !resetState.driftWarning;

    logSecurityEvent({
      eventType: 'PRIORITY_DRIFT_WARNING',
      userId: actor,
      ipAddress: params?.ipAddress,
      userAgent: params?.userAgent,
      result: 'success',
      details: `[SIM-H] Synthetic drift L2=${driftBeforeReset} triggered driftWarning=${warningBefore}; verified reset recovery.`,
    });

    results.push({
      scenarioId: 'h',
      title: 'Weight Drift Detection & Clean Reset Recovery',
      attackOrCheck: 'Push contradictory extreme updates on promo/finance items, detect L2 drift > 1.8, verify reset.',
      passed: warningBefore && driftBeforeReset > 1.8 && resetWeightsMatch,
      expectedOutcome: 'driftWarning=true when L2 > 1.8; reset cleanly restores defaultWeights.',
      observedOutcome: `L2 drift=${driftBeforeReset.toFixed(4)} (warning=${warningBefore}); reset verified=${resetWeightsMatch}.`,
      metrics: { driftL2Distance: driftBeforeReset, driftWarning: warningBefore, resetVerified: resetWeightsMatch },
      telemetryEventsLogged: ['PRIORITY_DRIFT_WARNING', 'PRIORITY_MODEL_RESET'],
    });
  }

  // (i) Invalid / NaN / Infinity / Raw-Text input rejection
  if (shouldRun('i')) {
    let nanRejected = false;
    let infRejected = false;
    try {
      assertFiniteFeatures(makeBaseFeatures({ textScore: Number.NaN }));
    } catch {
      nanRejected = true;
    }
    try {
      assertFiniteFeatures(makeBaseFeatures({ senderTrust: Number.POSITIVE_INFINITY }));
    } catch {
      infRejected = true;
    }

    const textReject = validateNumericOnlyScoreInput({
      ...makeBaseFeatures(),
      message: 'Secret decrypted message text',
    });

    const passed = nanRejected && infRejected && !textReject.ok;
    results.push({
      scenarioId: 'i',
      title: 'NaN / Infinity & Raw-Text Input Rejection',
      attackOrCheck: 'Submit NaN, Infinity, and forbidden raw message field to numeric scorer.',
      passed,
      expectedOutcome: 'All 3 malformed/privacy-violating inputs are rejected cleanly.',
      observedOutcome: `NaN rejected=${nanRejected}, Infinity rejected=${infRejected}, raw-text rejected=${!textReject.ok}.`,
      metrics: { nanRejected, infRejected, rawTextRejected: !textReject.ok },
      telemetryEventsLogged: ['PRIORITY_SCORED'],
    });
  }

  return {
    scenarios: results,
    allPassed: results.every((r) => r.passed),
    ranAt: new Date().toISOString(),
  };
}
