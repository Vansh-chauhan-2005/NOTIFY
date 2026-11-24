import fs from 'fs';
import os from 'os';
import path from 'path';
import {
  DEFAULT_BIAS,
  DEFAULT_PRIORITY_ARTIFACT,
  DEFAULT_THRESHOLDS,
  DEFAULT_WEIGHTS,
  TFIDF_DEFAULT_MODEL_SUMMARY,
  clamp,
  normalizePriorityThresholds,
  scoreNotification,
} from './math.js';
import {
  createDefaultUserPriorityModelState,
  shouldUsePersonalizedWeights,
  stepOnlineLogisticRegression,
} from './learning.js';
import {
  type FeatureVector,
  type HardRuleCode,
  type HardRuleContext,
  type PriorityFeedbackKind,
  type PriorityLearningResult,
  type PriorityScoreBreakdown,
  type PriorityThresholds,
  type QuietHoursConfig,
  type SigmoidPriorityLabel,
  type UserPriorityModelState,
} from './types.js';
import { logSecurityEvent } from '../telemetry/securityLogger.js';

const DEFAULT_HOURLY_CRITICAL_BUDGET = 8;

interface HourlyBucket {
  hourKey: string;
  count: number;
}

interface PriorityPersistedData {
  users: Record<string, UserPriorityModelState>;
  stats: {
    totalScored: number;
    totalFeedback: number;
    escalationCount: number;
    sumP: number;
    labelCounts: Record<SigmoidPriorityLabel, number>;
    ruleCounts: Record<HardRuleCode, number>;
    scoreHistogram: number[]; // 10 bins [0..0.1) ... [0.9..1.0]
  };
  hourlyCriticalBudgets: Record<string, HourlyBucket>;
}

declare global {
  var __aegisPriorityStoreData: PriorityPersistedData | undefined;
}

function getStoreFilePath(): string {
  if (process.env.VITEST === 'true' || process.env.NODE_ENV === 'test') {
    return path.join(os.tmpdir(), `.aegis-priority-models.vitest.${process.pid}.json`);
  }
  return path.resolve(process.cwd(), '.aegis-priority-models.json');
}

function emptyStoreData(): PriorityPersistedData {
  return {
    users: {},
    stats: {
      totalScored: 0,
      totalFeedback: 0,
      escalationCount: 0,
      sumP: 0,
      labelCounts: { CRITICAL: 0, HIGH: 0, NORMAL: 0, LOW: 0 },
      ruleCounts: {
        SECURITY_FLOOR: 0,
        UNSIGNED_PROMO_CAP: 0,
        SENDER_CLAIM_WEAK: 0,
        HOURLY_CRITICAL_BUDGET: 0,
      },
      scoreHistogram: Array(10).fill(0),
    },
    hourlyCriticalBudgets: {},
  };
}

function loadStore(): PriorityPersistedData {
  if (global.__aegisPriorityStoreData) {
    return global.__aegisPriorityStoreData;
  }
  const filePath = getStoreFilePath();
  let data = emptyStoreData();
  try {
    if (fs.existsSync(filePath)) {
      const raw = fs.readFileSync(filePath, 'utf8');
      const parsed = JSON.parse(raw);
      if (parsed && typeof parsed === 'object') {
        data = {
          users: parsed.users && typeof parsed.users === 'object' ? parsed.users : {},
          stats: {
            ...emptyStoreData().stats,
            ...(parsed.stats || {}),
            labelCounts: {
              ...emptyStoreData().stats.labelCounts,
              ...(parsed.stats?.labelCounts || {}),
            },
            ruleCounts: {
              ...emptyStoreData().stats.ruleCounts,
              ...(parsed.stats?.ruleCounts || {}),
            },
            scoreHistogram:
              Array.isArray(parsed.stats?.scoreHistogram) && parsed.stats.scoreHistogram.length === 10
                ? parsed.stats.scoreHistogram
                : Array(10).fill(0),
          },
          hourlyCriticalBudgets:
            parsed.hourlyCriticalBudgets && typeof parsed.hourlyCriticalBudgets === 'object'
              ? parsed.hourlyCriticalBudgets
              : {},
        };
      }
    }
  } catch {
    data = emptyStoreData();
  }
  global.__aegisPriorityStoreData = data;
  return data;
}

function persistStore(data: PriorityPersistedData): void {
  try {
    fs.writeFileSync(getStoreFilePath(), JSON.stringify(data, null, 2), 'utf8');
  } catch {
    // non-fatal on read-only fs
  }
}

export function clearPriorityStoreForTests(): void {
  global.__aegisPriorityStoreData = emptyStoreData();
  try {
    const filePath = getStoreFilePath();
    if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
  } catch {
    // ignore
  }
}

export function getUserPriorityModelState(userId: string): UserPriorityModelState {
  const cleanId = String(userId || 'anonymous').trim() || 'anonymous';
  const data = loadStore();
  if (!data.users[cleanId]) {
    data.users[cleanId] = createDefaultUserPriorityModelState(cleanId);
    persistStore(data);
  }
  return data.users[cleanId];
}

export function updateUserPrioritySettings(
  userId: string,
  patch: {
    personalizationEnabled?: boolean;
    urgentKeywords?: string[];
    quietHours?: Partial<QuietHoursConfig>;
    sourceReliability?: Record<string, number>;
    thresholds?: Partial<PriorityThresholds>;
  }
): UserPriorityModelState {
  const data = loadStore();
  const current = getUserPriorityModelState(userId);

  const nextKeywords = Array.isArray(patch.urgentKeywords)
    ? patch.urgentKeywords
        .map((k) => String(k || '').trim().toLowerCase())
        .filter((k) => k.length >= 2 && k.length <= 40)
        .slice(0, 30)
    : current.urgentKeywords;

  const nextSourceRel: Record<string, number> = { ...current.sourceReliability };
  if (patch.sourceReliability && typeof patch.sourceReliability === 'object') {
    for (const [k, v] of Object.entries(patch.sourceReliability)) {
      const cleanKey = String(k || '').trim().slice(0, 64);
      if (cleanKey && typeof v === 'number' && Number.isFinite(v)) {
        nextSourceRel[cleanKey] = Number(clamp(v, 0.05, 1.0).toFixed(2));
      }
    }
  }

  const nextQuiet: QuietHoursConfig = {
    enabled:
      typeof patch.quietHours?.enabled === 'boolean'
        ? patch.quietHours.enabled
        : current.quietHours.enabled,
    startHourUtc:
      typeof patch.quietHours?.startHourUtc === 'number' &&
      Number.isFinite(patch.quietHours.startHourUtc)
        ? Math.max(0, Math.min(23, Math.round(patch.quietHours.startHourUtc)))
        : current.quietHours.startHourUtc,
    endHourUtc:
      typeof patch.quietHours?.endHourUtc === 'number' &&
      Number.isFinite(patch.quietHours.endHourUtc)
        ? Math.max(0, Math.min(23, Math.round(patch.quietHours.endHourUtc)))
        : current.quietHours.endHourUtc,
    dndActive:
      typeof patch.quietHours?.dndActive === 'boolean'
        ? patch.quietHours.dndActive
        : current.quietHours.dndActive,
  };

  const updated: UserPriorityModelState = {
    ...current,
    personalizationEnabled:
      typeof patch.personalizationEnabled === 'boolean'
        ? patch.personalizationEnabled
        : current.personalizationEnabled,
    urgentKeywords: nextKeywords,
    quietHours: nextQuiet,
    sourceReliability: nextSourceRel,
    thresholds: patch.thresholds
      ? normalizePriorityThresholds({ ...current.thresholds, ...patch.thresholds })
      : current.thresholds,
    updatedAt: new Date().toISOString(),
  };

  data.users[current.userId] = updated;
  persistStore(data);
  return updated;
}

export function resetUserPriorityModel(
  userId: string,
  opts?: { ipAddress?: string; userAgent?: string; reason?: string }
): UserPriorityModelState {
  const data = loadStore();
  const current = getUserPriorityModelState(userId);
  const nowIso = new Date().toISOString();

  const resetState: UserPriorityModelState = {
    ...current,
    version: current.version + 1,
    feedbackCount: 0,
    bias: DEFAULT_BIAS,
    weights: { ...DEFAULT_WEIGHTS },
    thresholds: { ...DEFAULT_THRESHOLDS },
    driftWarning: false,
    driftL2Distance: 0,
    updatedAt: nowIso,
    lastResetAt: nowIso,
    weightHistory: [],
  };

  data.users[current.userId] = resetState;
  persistStore(data);

  logSecurityEvent({
    eventType: 'PRIORITY_MODEL_RESET',
    userId: current.userId,
    ipAddress: opts?.ipAddress,
    userAgent: opts?.userAgent,
    result: 'success',
    details: opts?.reason || 'User priority weights reset to calibrated global defaults.',
  });

  return resetState;
}

function getCurrentHourKey(): string {
  return new Date().toISOString().slice(0, 13); // YYYY-MM-DDTHH
}

export function getSourceCriticalHourlyCount(userId: string, source: string): number {
  const data = loadStore();
  const hourKey = getCurrentHourKey();
  const bucketKey = `${userId}::${source || 'direct'}`;
  const entry = data.hourlyCriticalBudgets[bucketKey];
  if (!entry || entry.hourKey !== hourKey) return 0;
  return entry.count;
}

function incrementSourceCriticalHourlyCount(userId: string, source: string): void {
  const data = loadStore();
  const hourKey = getCurrentHourKey();
  const bucketKey = `${userId}::${source || 'direct'}`;
  const entry = data.hourlyCriticalBudgets[bucketKey];
  if (!entry || entry.hourKey !== hourKey) {
    data.hourlyCriticalBudgets[bucketKey] = { hourKey, count: 1 };
  } else {
    entry.count += 1;
  }
}

export function scoreForUser(params: {
  userId: string;
  features: FeatureVector;
  source?: string;
  previousLabel?: SigmoidPriorityLabel;
  elapsedSeconds?: number;
  isAcked?: boolean;
  ruleContext?: HardRuleContext;
  recordStats?: boolean;
  ipAddress?: string;
  userAgent?: string;
}): PriorityScoreBreakdown {
  const data = loadStore();
  const state = getUserPriorityModelState(params.userId);
  const usePersonal = shouldUsePersonalizedWeights(
    state.feedbackCount,
    state.personalizationEnabled
  );
  const weights = usePersonal ? state.weights : DEFAULT_WEIGHTS;
  const bias = usePersonal ? state.bias : DEFAULT_BIAS;
  const activeMode = usePersonal ? 'PERSONALIZED' : 'GLOBAL_DEFAULT';

  const source = params.source || params.ruleContext?.source || 'direct';
  const currentCriticalCount = getSourceCriticalHourlyCount(state.userId, source);
  const hourlyBudget = params.ruleContext?.hourlyCriticalBudget ?? DEFAULT_HOURLY_CRITICAL_BUDGET;

  const breakdown = scoreNotification({
    features: params.features,
    weights,
    bias,
    thresholds: state.thresholds,
    previousLabel: params.previousLabel,
    elapsedSeconds: params.elapsedSeconds,
    isAcked: params.isAcked,
    activeMode,
    ruleContext: {
      source,
      hourlyCriticalCountForSource:
        params.ruleContext?.hourlyCriticalCountForSource ?? currentCriticalCount,
      hourlyCriticalBudget: hourlyBudget,
      ...params.ruleContext,
    },
  });

  if (params.recordStats !== false) {
    data.stats.totalScored += 1;
    data.stats.sumP += breakdown.p;
    data.stats.labelCounts[breakdown.label] = (data.stats.labelCounts[breakdown.label] || 0) + 1;
    const binIdx = Math.min(9, Math.max(0, Math.floor(breakdown.p * 10)));
    data.stats.scoreHistogram[binIdx] = (data.stats.scoreHistogram[binIdx] || 0) + 1;

    if (breakdown.label === 'CRITICAL') {
      incrementSourceCriticalHourlyCount(state.userId, source);
    }
    if (breakdown.ageBoostApplied > 0.05 && breakdown.label !== breakdown.modelLabel) {
      // ignore
    }
    if (params.previousLabel && breakdown.label !== params.previousLabel && breakdown.ageBoostApplied > 0) {
      data.stats.escalationCount += 1;
      logSecurityEvent({
        eventType: 'PRIORITY_ESCALATED',
        userId: state.userId,
        ipAddress: params.ipAddress,
        userAgent: params.userAgent,
        result: 'success',
        details: `Unacked notification escalated ${params.previousLabel} -> ${breakdown.label} (p=${breakdown.p}).`,
      });
    }

    for (const rule of breakdown.appliedRules) {
      data.stats.ruleCounts[rule.rule] = (data.stats.ruleCounts[rule.rule] || 0) + 1;
      if (rule.rule === 'HOURLY_CRITICAL_BUDGET') {
        logSecurityEvent({
          eventType: 'PRIORITY_BUDGET_EXCEEDED',
          userId: state.userId,
          ipAddress: params.ipAddress,
          userAgent: params.userAgent,
          result: 'blocked',
          details: rule.reason,
        });
      } else {
        logSecurityEvent({
          eventType: 'PRIORITY_RULE_APPLIED',
          userId: state.userId,
          ipAddress: params.ipAddress,
          userAgent: params.userAgent,
          result: 'success',
          details: `${rule.rule} (${rule.beforeLabel} -> ${rule.afterLabel}): ${rule.reason}`,
        });
      }
    }

    logSecurityEvent({
      eventType: 'PRIORITY_SCORED',
      userId: state.userId,
      ipAddress: params.ipAddress,
      userAgent: params.userAgent,
      result: 'success',
      details: `Scored ${breakdown.label} (p=${breakdown.p}, z=${breakdown.z}, mode=${breakdown.activeMode})`,
    });

    persistStore(data);
  }

  return breakdown;
}

export function recordUserPriorityFeedback(params: {
  userId: string;
  features: FeatureVector;
  feedbackKind: PriorityFeedbackKind;
  ipAddress?: string;
  userAgent?: string;
}): PriorityLearningResult {
  const data = loadStore();
  const state = getUserPriorityModelState(params.userId);
  const prevDrift = state.driftWarning;

  const result = stepOnlineLogisticRegression({
    state,
    features: params.features,
    feedbackKind: params.feedbackKind,
  });

  data.users[state.userId] = result.updatedState;
  data.stats.totalFeedback += 1;
  persistStore(data);

  logSecurityEvent({
    eventType: 'PRIORITY_FEEDBACK',
    userId: state.userId,
    ipAddress: params.ipAddress,
    userAgent: params.userAgent,
    result: 'success',
    details: `Feedback=${params.feedbackKind} (y=${result.targetY}) -> count=${result.updatedState.feedbackCount}, p=${result.predictedPBefore}->${result.predictedPAfter}`,
  });

  logSecurityEvent({
    eventType: 'PRIORITY_MODEL_UPDATED',
    userId: state.userId,
    ipAddress: params.ipAddress,
    userAgent: params.userAgent,
    result: 'success',
    details: `SGD step #${result.updatedState.feedbackCount} (lr=${result.effectiveLearningRate}, maxDelta=${result.maxAbsWeightDelta}, driftL2=${result.driftL2Distance})`,
  });

  if (result.driftWarning && !prevDrift) {
    logSecurityEvent({
      eventType: 'PRIORITY_DRIFT_WARNING',
      userId: state.userId,
      ipAddress: params.ipAddress,
      userAgent: params.userAgent,
      result: 'success',
      details: `Personalized weight drift L2=${result.driftL2Distance} exceeded safe threshold.`,
    });
  }

  return result;
}

export function getPriorityAdminStats() {
  const data = loadStore();
  const userList = Object.values(data.users);
  const personalizedUsers = userList.filter((u) =>
    shouldUsePersonalizedWeights(u.feedbackCount, u.personalizationEnabled)
  ).length;
  const driftingUsers = userList.filter((u) => u.driftWarning).length;

  return {
    totalScored: data.stats.totalScored,
    totalFeedback: data.stats.totalFeedback,
    escalationCount: data.stats.escalationCount,
    meanScore:
      data.stats.totalScored > 0
        ? Number((data.stats.sumP / data.stats.totalScored).toFixed(4))
        : 0,
    labelCounts: data.stats.labelCounts,
    ruleCounts: data.stats.ruleCounts,
    scoreHistogram: data.stats.scoreHistogram,
    activeUsersCount: userList.length,
    personalizedUsersCount: personalizedUsers,
    driftingUsersCount: driftingUsers,
    defaultModel: {
      version: DEFAULT_PRIORITY_ARTIFACT.version,
      trainedAt: DEFAULT_PRIORITY_ARTIFACT.trainedAt,
      datasetSize: DEFAULT_PRIORITY_ARTIFACT.datasetSize,
      bias: DEFAULT_PRIORITY_ARTIFACT.bias,
      weights: DEFAULT_PRIORITY_ARTIFACT.weights,
      thresholds: DEFAULT_PRIORITY_ARTIFACT.thresholds,
      hyperparams: DEFAULT_PRIORITY_ARTIFACT.hyperparams,
      metrics: DEFAULT_PRIORITY_ARTIFACT.metrics,
      modelCard: DEFAULT_PRIORITY_ARTIFACT.modelCard,
    },
    tfidfDefaultModel: TFIDF_DEFAULT_MODEL_SUMMARY,
    generatedAt: new Date().toISOString(),
  };
}
