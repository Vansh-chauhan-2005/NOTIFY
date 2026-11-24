export const PRIORITY_FEATURE_NAMES = [
  'textScore',
  'keywordUrgency',
  'senderTrust',
  'sourceReliability',
  'category_security',
  'category_finance',
  'category_work',
  'category_social',
  'category_promo',
  'ageFactor',
  'userContext',
  'repetition',
  'userAffinity',
  'senderClaimedPriority',
] as const;

export type PriorityFeatureName = (typeof PRIORITY_FEATURE_NAMES)[number];

export type SigmoidPriorityLabel = 'CRITICAL' | 'HIGH' | 'NORMAL' | 'LOW';

export type LegacyNotificationPriority = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export type PriorityCategory = 'security' | 'finance' | 'work' | 'social' | 'promo';

export type FeatureVector = Record<PriorityFeatureName, number>;
export type WeightVector = Record<PriorityFeatureName, number>;

export interface FeatureContribution {
  feature: PriorityFeatureName;
  label: string;
  value: number;
  weight: number;
  contribution: number; // w_i * x_i
}

export type HardRuleCode =
  | 'SECURITY_FLOOR'
  | 'UNSIGNED_PROMO_CAP'
  | 'SENDER_CLAIM_WEAK'
  | 'HOURLY_CRITICAL_BUDGET';

export interface AppliedHardRule {
  rule: HardRuleCode;
  action: 'UPGRADED' | 'CAPPED' | 'DOWNGRADED' | 'ATTENUATED';
  reason: string;
  beforeLabel: SigmoidPriorityLabel;
  afterLabel: SigmoidPriorityLabel;
}

export interface PriorityThresholds {
  critical: number; // default 0.85
  high: number;     // default 0.65
  normal: number;   // default 0.35
  hysteresis: number; // default 0.04
}

export interface PriorityHyperparams {
  learningRate: number;
  l2Regularization: number;
  gradientClip: number;
  weightMin: number;
  weightMax: number;
  coldStartFeedbackThreshold: number;
  ageTauSeconds: number;
  ageMaxBoost: number;
  ageMaxCeiling: number;
  decayHalfLifeSeconds: number;
  securityFloorMinWeight: number;
  driftL2WarningThreshold: number;
}

export interface CalibrationBin {
  binStart: number;
  binEnd: number;
  predictedMean: number;
  observedFraction: number;
  count: number;
}

export interface ModelEvaluationMetrics {
  cv5AucMean: number;
  cv5AucStd: number;
  cv5AccuracyMean: number;
  testAccuracy: number;
  testPrecision: number;
  testRecall: number;
  testF1: number;
  testRocAuc: number;
  confusionMatrix: [[number, number], [number, number]];
  calibrationBins: CalibrationBin[];
}

export interface ModelCardMetadata {
  modelType: string;
  isDeepLearning: false;
  intendedUse: string;
  trainingData: string;
  limitations: string[];
}

export interface DefaultWeightsArtifact {
  version: string;
  trainedAt: string;
  datasetSize: number;
  trainSize: number;
  testSize: number;
  bias: number;
  weights: WeightVector;
  thresholds: PriorityThresholds;
  hyperparams: PriorityHyperparams;
  metrics: ModelEvaluationMetrics;
  modelCard: ModelCardMetadata;
}

export interface HardRuleContext {
  isSecurityAlert?: boolean;
  isAccountAtRisk?: boolean;
  isOtpOrNewDevice?: boolean;
  provenanceFailedOrRevoked?: boolean;
  isProvenanceVerified?: boolean;
  isPromo?: boolean;
  senderTrust?: number;
  source?: string;
  hourlyCriticalCountForSource?: number;
  hourlyCriticalBudget?: number;
}

export interface PriorityScoreBreakdown {
  p: number; // Final score in [0, 1] after time cap & decay
  pBase: number; // Score at ageFactor=0 before time escalation/decay
  rawP: number; // Direct sigmoid(z) without cap/decay
  z: number; // b + sum(w_i * x_i)
  bias: number;
  label: SigmoidPriorityLabel;
  modelLabel: SigmoidPriorityLabel;
  contributions: FeatureContribution[];
  appliedRules: AppliedHardRule[];
  thresholdUsed: PriorityThresholds;
  activeMode: 'PERSONALIZED' | 'GLOBAL_DEFAULT';
  escalationCapped: boolean;
  ageBoostApplied: number;
  decayApplied: number;
  features: FeatureVector;
  scoredAt: string;
}

export type PriorityFeedbackKind =
  | 'MORE_IMPORTANT'
  | 'LESS_IMPORTANT'
  | 'ACKED_FAST'
  | 'IGNORED'
  | 'MARKED_SPAM';

export interface QuietHoursConfig {
  enabled: boolean;
  startHourUtc: number; // 0..23
  endHourUtc: number;   // 0..23
  dndActive?: boolean;
}

export interface WeightHistorySnapshot {
  step: number;
  timestamp: string;
  feedbackKind: PriorityFeedbackKind;
  deltaL2FromDefault: number;
  weights: WeightVector;
  bias: number;
}

export interface UserPriorityModelState {
  userId: string;
  version: number;
  personalizationEnabled: boolean;
  feedbackCount: number;
  bias: number;
  weights: WeightVector;
  thresholds: PriorityThresholds;
  urgentKeywords: string[];
  quietHours: QuietHoursConfig;
  sourceReliability: Record<string, number>;
  driftWarning: boolean;
  driftL2Distance: number;
  updatedAt: string;
  lastResetAt?: string;
  weightHistory: WeightHistorySnapshot[];
}

export interface PriorityLearningResult {
  updatedState: UserPriorityModelState;
  targetY: number;
  predictedPBefore: number;
  predictedPAfter: number;
  effectiveLearningRate: number;
  maxAbsWeightDelta: number;
  driftWarning: boolean;
  driftL2Distance: number;
  securityFloorLocked: boolean;
}

export interface PrioritySimulationScenarioResult {
  scenarioId: 'a' | 'b' | 'c' | 'd' | 'e' | 'f' | 'g' | 'h' | 'i';
  title: string;
  attackOrCheck: string;
  passed: boolean;
  expectedOutcome: string;
  observedOutcome: string;
  metrics: Record<string, number | string | boolean>;
  telemetryEventsLogged: string[];
}
