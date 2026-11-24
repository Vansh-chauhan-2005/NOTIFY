import type {
  AppliedHardRule,
  FeatureVector,
  HardRuleContext,
  SigmoidPriorityLabel,
} from './types.js';

const PRIORITY_RANK: Record<SigmoidPriorityLabel, number> = {
  LOW: 0,
  NORMAL: 1,
  HIGH: 2,
  CRITICAL: 3,
};

function maxPriority(a: SigmoidPriorityLabel, b: SigmoidPriorityLabel): SigmoidPriorityLabel {
  return PRIORITY_RANK[a] >= PRIORITY_RANK[b] ? a : b;
}

function minPriority(a: SigmoidPriorityLabel, b: SigmoidPriorityLabel): SigmoidPriorityLabel {
  return PRIORITY_RANK[a] <= PRIORITY_RANK[b] ? a : b;
}

/**
 * Pure deterministic safety rules applied AFTER logistic regression scoring.
 * Never depends on I/O, timestamps, or raw message text.
 */
export function applyHardSafetyRules(params: {
  modelLabel: SigmoidPriorityLabel;
  p: number;
  features: FeatureVector;
  context?: HardRuleContext;
}): {
  finalLabel: SigmoidPriorityLabel;
  appliedRules: AppliedHardRule[];
} {
  const ctx = params.context ?? {};
  const appliedRules: AppliedHardRule[] = [];
  let label: SigmoidPriorityLabel = params.modelLabel;

  const isSecurity =
    Boolean(ctx.isSecurityAlert) || params.features.category_security >= 0.5;
  const isOtpOrNewDevice = Boolean(ctx.isOtpOrNewDevice);
  const provenanceFailedOrRevoked = Boolean(ctx.provenanceFailedOrRevoked);
  const isAccountAtRisk = Boolean(ctx.isAccountAtRisk) || provenanceFailedOrRevoked;

  // Rule 1: SECURITY_FLOOR
  // Security alerts (OTP, new-device login, key revoked, provenance failure) NEVER drop below HIGH;
  // account-at-risk or provenance failure forces CRITICAL.
  if (isSecurity || isOtpOrNewDevice || provenanceFailedOrRevoked) {
    const floor: SigmoidPriorityLabel = isAccountAtRisk ? 'CRITICAL' : 'HIGH';
    const next = maxPriority(label, floor);
    if (next !== label) {
      appliedRules.push({
        rule: 'SECURITY_FLOOR',
        action: 'UPGRADED',
        beforeLabel: label,
        afterLabel: next,
        reason: isAccountAtRisk
          ? 'Account-at-risk or provenance verification failure enforces CRITICAL floor.'
          : 'Security/OTP/new-device event enforces minimum HIGH priority floor.',
      });
      label = next;
    }
  }

  // Rule 2: UNSIGNED_PROMO_CAP
  // Promotional/low-trust unsigned notifications cannot exceed NORMAL even if they spoof urgent words.
  const isPromo = Boolean(ctx.isPromo) || params.features.category_promo >= 0.5;
  const senderTrust = ctx.senderTrust ?? params.features.senderTrust;
  const isUnsignedOrLowTrust =
    ctx.isProvenanceVerified === false || senderTrust < 0.65;

  if (isPromo && isUnsignedOrLowTrust) {
    const next = minPriority(label, 'NORMAL');
    if (next !== label) {
      appliedRules.push({
        rule: 'UNSIGNED_PROMO_CAP',
        action: 'CAPPED',
        beforeLabel: label,
        afterLabel: next,
        reason: 'Unsigned or low-trust promotional item capped at NORMAL.',
      });
      label = next;
    }
  }

  // Rule 3: SENDER_CLAIM_WEAK
  // Flag whenever sender claimed high/critical priority without corroborating trust/signals.
  if (
    params.features.senderClaimedPriority >= 0.85 &&
    senderTrust < 0.65 &&
    params.features.textScore < 0.65
  ) {
    appliedRules.push({
      rule: 'SENDER_CLAIM_WEAK',
      action: 'ATTENUATED',
      beforeLabel: label,
      afterLabel: label,
      reason: 'Sender claimed urgency treated as weak feature only (uncorroborated by provenance or signals).',
    });
  }

  // Rule 4: HOURLY_CRITICAL_BUDGET
  // Per-source hourly CRITICAL cap downgrades excess CRITICAL -> HIGH to prevent alert-storm fatigue
  // unless an active security/account-at-risk floor strictly demands CRITICAL.
  if (
    label === 'CRITICAL' &&
    typeof ctx.hourlyCriticalCountForSource === 'number' &&
    typeof ctx.hourlyCriticalBudget === 'number' &&
    ctx.hourlyCriticalBudget > 0 &&
    ctx.hourlyCriticalCountForSource >= ctx.hourlyCriticalBudget &&
    !isAccountAtRisk
  ) {
    const before = label;
    label = 'HIGH';
    appliedRules.push({
      rule: 'HOURLY_CRITICAL_BUDGET',
      action: 'DOWNGRADED',
      beforeLabel: before,
      afterLabel: label,
      reason: `Source "${ctx.source || 'unknown'}" exceeded hourly CRITICAL budget (${ctx.hourlyCriticalCountForSource}/${ctx.hourlyCriticalBudget}); downgraded to HIGH.`,
    });
  }

  return {
    finalLabel: label,
    appliedRules,
  };
}
