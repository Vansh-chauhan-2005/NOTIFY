import { monitorEventLoopDelay, type IntervalHistogram } from 'perf_hooks';
import type { ClockFn, LoadLevel, RoutePolicy } from './types.js';

export interface LoadThresholds {
  elevatedEnterDelayMs: number;
  elevatedExitDelayMs: number;
  highEnterDelayMs: number;
  highExitDelayMs: number;
  criticalEnterDelayMs: number;
  criticalExitDelayMs: number;
  elevatedEnterInFlight: number;
  elevatedExitInFlight: number;
  highEnterInFlight: number;
  highExitInFlight: number;
  criticalEnterInFlight: number;
  criticalExitInFlight: number;
}

export const DEFAULT_LOAD_THRESHOLDS: LoadThresholds = {
  elevatedEnterDelayMs: 35,
  elevatedExitDelayMs: 20,
  highEnterDelayMs: 85,
  highExitDelayMs: 55,
  criticalEnterDelayMs: 180,
  criticalExitDelayMs: 110,
  elevatedEnterInFlight: 80,
  elevatedExitInFlight: 50,
  highEnterInFlight: 200,
  highExitInFlight: 130,
  criticalEnterInFlight: 400,
  criticalExitInFlight: 250,
};

/**
 * Hysteresis Load Controller:
 * Uses separate higher enter thresholds and lower exit thresholds so
 * transient single-tick jitter does not cause load-level flapping.
 */
export class LoadLevelController {
  private level: LoadLevel = 'NORMAL';
  private histogram: IntervalHistogram | null = null;
  private readonly clock: ClockFn;
  private readonly thresholds: LoadThresholds;
  private lastLevelChangeAt = 0;

  constructor(options: {
    enableHistogram?: boolean;
    clock?: ClockFn;
    thresholds?: Partial<LoadThresholds>;
  } = {}) {
    this.clock = options.clock ?? Date.now;
    this.thresholds = { ...DEFAULT_LOAD_THRESHOLDS, ...options.thresholds };
    if (options.enableHistogram) {
      try {
        this.histogram = monitorEventLoopDelay({ resolution: 20 });
        this.histogram.enable();
      } catch {
        this.histogram = null;
      }
    }
  }

  getEventLoopDelayMs(): { mean: number; p95: number; max: number } {
    if (!this.histogram) {
      return { mean: 0, p95: 0, max: 0 };
    }
    const toMs = (ns: number) => (Number.isFinite(ns) && ns > 0 ? Number((ns / 1e6).toFixed(2)) : 0);
    return {
      mean: toMs(this.histogram.mean),
      p95: toMs(this.histogram.percentile(95)),
      max: toMs(this.histogram.max),
    };
  }

  getCurrentLevel(): LoadLevel {
    return this.level;
  }

  /**
   * Evaluates current delay & in-flight counts with hysteresis and returns
   * whether a load-level transition occurred.
   */
  evaluate(params: {
    eventLoopDelayMs: number;
    inFlightRequests: number;
  }): { previous: LoadLevel; current: LoadLevel; changed: boolean } {
    const previous = this.level;
    const delay = Math.max(0, params.eventLoopDelayMs);
    const inFlight = Math.max(0, params.inFlightRequests);
    const t = this.thresholds;

    let next: LoadLevel = previous;

    // Stepwise upward escalation or downward hysteresis release
    if (delay >= t.criticalEnterDelayMs || inFlight >= t.criticalEnterInFlight) {
      next = 'CRITICAL';
    } else if (previous === 'CRITICAL') {
      if (delay < t.criticalExitDelayMs && inFlight < t.criticalExitInFlight) {
        if (delay >= t.highEnterDelayMs || inFlight >= t.highEnterInFlight) {
          next = 'HIGH';
        } else if (delay >= t.elevatedEnterDelayMs || inFlight >= t.elevatedEnterInFlight) {
          next = 'ELEVATED';
        } else {
          next = 'NORMAL';
        }
      }
    } else if (delay >= t.highEnterDelayMs || inFlight >= t.highEnterInFlight) {
      next = 'HIGH';
    } else if (previous === 'HIGH') {
      if (delay < t.highExitDelayMs && inFlight < t.highExitInFlight) {
        if (delay >= t.elevatedEnterDelayMs || inFlight >= t.elevatedEnterInFlight) {
          next = 'ELEVATED';
        } else {
          next = 'NORMAL';
        }
      }
    } else if (delay >= t.elevatedEnterDelayMs || inFlight >= t.elevatedEnterInFlight) {
      next = 'ELEVATED';
    } else if (previous === 'ELEVATED') {
      if (delay < t.elevatedExitDelayMs && inFlight < t.elevatedExitInFlight) {
        next = 'NORMAL';
      }
    }

    if (next !== previous) {
      this.level = next;
      this.lastLevelChangeAt = this.clock();
    }

    return {
      previous,
      current: this.level,
      changed: next !== previous,
    };
  }

  reset(): void {
    this.level = 'NORMAL';
    this.lastLevelChangeAt = this.clock();
    try {
      this.histogram?.reset();
    } catch {}
  }

  getLastChangeAt(): number {
    return this.lastLevelChangeAt;
  }
}

/**
 * Priority-aware load shedding decision:
 * - Auth routes, OTP verify, ACK links, and health checks are NEVER shed.
 * - Authenticated users with CRITICAL notification priority are served ahead of anonymous/low-value traffic.
 * - ELEVATED: anonymous limits tighten (handled in rate policy multiplier), nothing shed.
 * - HIGH: shed low-value routes (shedAtLevel === 'HIGH', e.g. stats, telemetry, simulator).
 * - CRITICAL: serve ONLY auth, ack links, health, admin control, and already-authenticated messaging.
 */
export function shouldShedRequest(params: {
  loadLevel: LoadLevel;
  policy: RoutePolicy;
  isAuthenticated: boolean;
  isCriticalPriority?: boolean;
  isCriticalAuthOrAck?: boolean;
}): { shed: boolean; reason?: string; retryAfterSeconds?: number } {
  const { loadLevel, policy, isAuthenticated, isCriticalPriority, isCriticalAuthOrAck } = params;

  if (loadLevel === 'NORMAL' || loadLevel === 'ELEVATED') {
    return { shed: false };
  }

  // Never shed health checks, ACK links, or OTP/login verification
  if (isCriticalAuthOrAck || policy.isCriticalAuthOrAck || policy.shedAtLevel === 'NEVER') {
    return { shed: false };
  }

  // Priority-aware preservation for authenticated users delivering/reading CRITICAL alerts
  if (isAuthenticated && isCriticalPriority && (policy.group === 'messaging' || policy.group === 'ephemeral')) {
    return { shed: false };
  }

  if (loadLevel === 'HIGH') {
    if (policy.shedAtLevel === 'HIGH') {
      return {
        shed: true,
        reason: `Server under HIGH load: temporarily shedding low-value ${policy.group} route.`,
        retryAfterSeconds: 10,
      };
    }
    return { shed: false };
  }

  // CRITICAL load level: only health, auth/ack, admin recovery, and authenticated messaging survive
  if (policy.group === 'messaging' && isAuthenticated) {
    return { shed: false };
  }

  return {
    shed: true,
    reason: `Server under CRITICAL load: serving only auth, ack links, health, and active messaging.`,
    retryAfterSeconds: 20,
  };
}

declare global {
  var __aegisGatewayLoadController: LoadLevelController | undefined;
}

export function getGlobalLoadController(): LoadLevelController {
  if (!global.__aegisGatewayLoadController) {
    global.__aegisGatewayLoadController = new LoadLevelController({ enableHistogram: true });
  }
  return global.__aegisGatewayLoadController;
}
