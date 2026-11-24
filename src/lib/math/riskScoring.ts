import { redis } from '../db/redis.js';

export type PriorityLevel = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export const PRIORITY_MAP: Record<PriorityLevel, number> = {
  LOW: 0.1,
  MEDIUM: 0.5,
  HIGH: 0.8,
  CRITICAL: 1.0,
};

export interface RiskCalculationInput {
  userId: string;
  priority: PriorityLevel | number;
  riskScore?: number; // R in [0, 1]
  hasActiveSocket?: boolean; // presence Uc in {0.0, 1.0}
  weights?: {
    w1?: number; // priority weight
    w2?: number; // risk factor weight
    w3?: number; // frequency penalty weight
    w4?: number; // presence coefficient weight
  };
}

export interface RiskCalculationResult {
  dispatchWeight: number; // W in [0, 1]
  priorityScore: number;  // P
  riskFactor: number;     // R
  frequencyPenalty: number; // F(t)
  presenceCoeff: number;  // Uc
  logitZ: number;
  rawCountWindow: number;
  formula: string;
  requiresEscalationCandidate: boolean; // W >= 0.75
}

/**
 * Dynamic Priority & Risk Math Engine
 *
 * Implements the Sigmoid Dispatch Weight W:
 * W = 1 / (1 + e^-(w1 * P + w2 * R - w3 * F(t) + w4 * Uc))
 */
export async function calculateDispatchWeight(
  input: RiskCalculationInput
): Promise<RiskCalculationResult> {
  const { userId, priority, riskScore = 0.5, hasActiveSocket = false } = input;

  // 1. Resolve Priority P in [0.1, 1.0]
  let P: number;
  if (typeof priority === 'string') {
    P = PRIORITY_MAP[priority.toUpperCase() as PriorityLevel] ?? 0.5;
  } else {
    P = Math.max(0.1, Math.min(1.0, priority));
  }

  // 2. Risk factor R in [0, 1]
  const R = Math.max(0.0, Math.min(1.0, riskScore));

  // 3. Fetch Frequency Penalty F(t) from Redis key freq:user:<userId>
  const freqKey = `freq:user:${userId}`;
  const freqRaw = await redis.get(freqKey);
  const rawCountWindow = freqRaw ? parseInt(freqRaw, 10) : 0;

  // Normalize frequency penalty F(t) into [0, 1], with saturation at 10 alerts/min
  // F(t) = min(1.0, log(1 + count) / log(11))
  const F_t = Math.min(1.0, Math.log(1 + rawCountWindow) / Math.log(11));

  // Increment user frequency counter in Redis with 60s sliding window
  const currentCount = await redis.incr(freqKey);
  if (currentCount === 1) {
    await redis.expire(freqKey, 60);
  }

  // 4. Map active socket status to presence coefficient Uc in {0.0, 1.0}
  const Uc = hasActiveSocket ? 1.0 : 0.0;

  // 5. Calculate Sigmoid logit
  const w1 = input.weights?.w1 ?? 2.5; // Priority importance
  const w2 = input.weights?.w2 ?? 2.0; // Risk severity
  const w3 = input.weights?.w3 ?? 1.5; // Alert fatigue frequency penalty
  const w4 = input.weights?.w4 ?? 1.0; // Active presence bonus

  const logitZ = w1 * P + w2 * R - w3 * F_t + w4 * Uc;

  // Logistic function W in [0, 1]
  const W = 1 / (1 + Math.exp(-logitZ));
  const roundedW = Number(W.toFixed(4));

  return {
    dispatchWeight: roundedW,
    priorityScore: P,
    riskFactor: R,
    frequencyPenalty: Number(F_t.toFixed(4)),
    presenceCoeff: Uc,
    logitZ: Number(logitZ.toFixed(4)),
    rawCountWindow,
    formula: `W = 1 / (1 + e^-(${w1}·P + ${w2}·R - ${w3}·F(t) + ${w4}·Uc))`,
    requiresEscalationCandidate: roundedW >= 0.75,
  };
}
