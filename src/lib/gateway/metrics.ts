import { getAllBreakerStatuses } from '../delivery/circuitBreaker.js';
import {
  logSecurityEvent,
  type SecurityEventType,
  type SecurityResult,
  type SecuritySeverity,
} from '../telemetry/securityLogger.js';
import { getGlobalLoadController } from './loadShedder.js';
import { getGlobalPenaltyBox } from './penaltyBox.js';
import { getGatewayStore } from './store/index.js';
import type { GatewayStatsSnapshot, PenaltyStage, RouteGroup } from './types.js';

const ALL_GROUPS: RouteGroup[] = [
  'auth',
  'ingest',
  'messaging',
  'ephemeral',
  'provenance',
  'dedup',
  'priority',
  'admin',
  'telemetry',
  'simulator',
  'health',
  'static',
  'general',
];

interface TelemetryAggregateBucket {
  eventType: SecurityEventType;
  severity: SecuritySeverity;
  result: SecurityResult;
  shortIpHash: string;
  routeGroup: RouteGroup;
  count: number;
  sampleDetail: string;
}

interface MinuteCounter {
  minuteMs: number;
  label: string;
  total: number;
  allowed: number;
  throttled: number;
  blocked: number;
  shed: number;
}

class GatewayMetricsCollector {
  private totalRequests = 0;
  private allowedCount = 0;
  private throttledCount = 0;
  private blockedCount = 0;
  private shedCount = 0;
  private oversizeCount = 0;
  private malformedCount = 0;
  private storeErrorCount = 0;
  private inFlightRequests = 0;

  private readonly byGroup = new Map<
    RouteGroup,
    { total: number; allowed: number; throttled: number; blocked: number; shed: number }
  >();
  private readonly minuteBuckets = new Map<number, MinuteCounter>();
  private readonly recentTimestampsMs: number[] = [];
  private readonly latencySamplesMs: number[] = [];
  private readonly throttledKeyStats = new Map<
    string,
    { fullKey: string; shortKey: string; count: number }
  >();

  // Rate-limited / batched telemetry buffer (flushed max once per 1s)
  private readonly telemetryBuffer = new Map<string, TelemetryAggregateBucket>();
  private lastFlushMs = 0;
  private allowSampleCounter = 0;

  constructor() {
    for (const g of ALL_GROUPS) {
      this.byGroup.set(g, { total: 0, allowed: 0, throttled: 0, blocked: 0, shed: 0 });
    }
  }

  incrementInFlight(): void {
    this.inFlightRequests += 1;
  }

  decrementInFlight(): void {
    this.inFlightRequests = Math.max(0, this.inFlightRequests - 1);
  }

  getInFlightCount(): number {
    return this.inFlightRequests;
  }

  recordLatency(durationMs: number): void {
    if (!Number.isFinite(durationMs) || durationMs < 0) return;
    this.latencySamplesMs.push(Number(durationMs.toFixed(2)));
    if (this.latencySamplesMs.length > 500) {
      this.latencySamplesMs.splice(0, this.latencySamplesMs.length - 500);
    }
  }

  recordOutcome(params: {
    routeGroup: RouteGroup;
    outcome: 'allowed' | 'throttled' | 'blocked' | 'shed' | 'oversize' | 'malformed' | 'store_error';
    shortIpHash: string;
    keyHit?: string;
    detail: string;
    nowMs?: number;
  }): void {
    const now = params.nowMs ?? Date.now();
    this.totalRequests += 1;
    this.recentTimestampsMs.push(now);

    // Keep 60s sliding window for RPS calculation
    const cutoff60s = now - 60_000;
    while (this.recentTimestampsMs.length > 0 && this.recentTimestampsMs[0] < cutoff60s) {
      this.recentTimestampsMs.shift();
    }

    const grp = this.byGroup.get(params.routeGroup)!;
    grp.total += 1;

    const minFloor = Math.floor(now / 60_000) * 60_000;
    let bucket = this.minuteBuckets.get(minFloor);
    if (!bucket) {
      const d = new Date(minFloor);
      bucket = {
        minuteMs: minFloor,
        label: `${String(d.getHours()).padStart(2, '0')}:${String(d.getMinutes()).padStart(2, '0')}`,
        total: 0,
        allowed: 0,
        throttled: 0,
        blocked: 0,
        shed: 0,
      };
      this.minuteBuckets.set(minFloor, bucket);
      // Prune buckets older than 20 minutes
      for (const k of this.minuteBuckets.keys()) {
        if (k < minFloor - 20 * 60_000) {
          this.minuteBuckets.delete(k);
        }
      }
    }
    bucket.total += 1;

    let evType: SecurityEventType | null = null;
    let severity: SecuritySeverity = 'info';
    let result: SecurityResult = 'success';

    switch (params.outcome) {
      case 'allowed':
        this.allowedCount += 1;
        grp.allowed += 1;
        bucket.allowed += 1;
        this.allowSampleCounter += 1;
        // Sample 1 in 100 allowed requests to avoid telemetry log floods
        if (this.allowSampleCounter % 100 === 1) {
          evType = 'GATEWAY_ALLOWED_SAMPLE';
        }
        break;
      case 'throttled':
        this.throttledCount += 1;
        grp.throttled += 1;
        bucket.throttled += 1;
        evType = 'GATEWAY_THROTTLED';
        severity = 'warning';
        result = 'blocked';
        if (params.keyHit) {
          const shortKey = params.keyHit.replace(/^(ip|user|conn|acct):/, '').slice(0, 8);
          const prev = this.throttledKeyStats.get(params.keyHit);
          this.throttledKeyStats.set(params.keyHit, {
            fullKey: params.keyHit,
            shortKey: shortKey || params.shortIpHash,
            count: (prev?.count || 0) + 1,
          });
          if (this.throttledKeyStats.size > 500) {
            const first = this.throttledKeyStats.keys().next().value;
            if (first) this.throttledKeyStats.delete(first);
          }
        }
        break;
      case 'blocked':
        this.blockedCount += 1;
        grp.blocked += 1;
        bucket.blocked += 1;
        evType = 'GATEWAY_BLOCKED';
        severity = 'warning';
        result = 'blocked';
        break;
      case 'shed':
        this.shedCount += 1;
        grp.shed += 1;
        bucket.shed += 1;
        evType = 'GATEWAY_SHED';
        severity = 'warning';
        result = 'blocked';
        break;
      case 'oversize':
        this.oversizeCount += 1;
        grp.blocked += 1;
        bucket.blocked += 1;
        evType = 'GATEWAY_OVERSIZE_REJECTED';
        severity = 'warning';
        result = 'blocked';
        break;
      case 'malformed':
        this.malformedCount += 1;
        grp.blocked += 1;
        bucket.blocked += 1;
        evType = 'GATEWAY_MALFORMED_REJECTED';
        severity = 'warning';
        result = 'blocked';
        break;
      case 'store_error':
        this.storeErrorCount += 1;
        evType = 'GATEWAY_STORE_ERROR';
        severity = 'critical';
        result = 'failed';
        break;
    }

    if (evType) {
      this.enqueueTelemetry({
        eventType: evType,
        severity,
        result,
        shortIpHash: params.shortIpHash,
        routeGroup: params.routeGroup,
        detail: params.detail,
        nowMs: now,
      });
    }
  }

  enqueueTelemetry(params: {
    eventType: SecurityEventType;
    severity: SecuritySeverity;
    result: SecurityResult;
    shortIpHash: string;
    routeGroup: RouteGroup;
    detail: string;
    nowMs?: number;
  }): void {
    const now = params.nowMs ?? Date.now();
    const key = `${params.eventType}:${params.routeGroup}:${params.shortIpHash}`;
    const existing = this.telemetryBuffer.get(key);
    if (existing) {
      existing.count += 1;
    } else {
      this.telemetryBuffer.set(key, {
        eventType: params.eventType,
        severity: params.severity,
        result: params.result,
        shortIpHash: params.shortIpHash,
        routeGroup: params.routeGroup,
        count: 1,
        sampleDetail: params.detail,
      });
    }

    if (now - this.lastFlushMs >= 1000) {
      this.flushTelemetry(now);
    }
  }

  flushTelemetry(nowMs: number = Date.now()): void {
    if (this.telemetryBuffer.size === 0) return;
    this.lastFlushMs = nowMs;

    const batch = Array.from(this.telemetryBuffer.values()).slice(0, 25);
    this.telemetryBuffer.clear();

    for (const item of batch) {
      const suffix = item.count > 1 ? ` [${item.count} requests aggregated in 1s]` : '';
      logSecurityEvent({
        eventType: item.eventType,
        severity: item.severity,
        result: item.result,
        ipAddress: `hash:${item.shortIpHash}`,
        userAgent: `gateway:${item.routeGroup}`,
        details: `${item.sampleDetail}${suffix}`,
      });
    }
  }

  getSnapshot(): GatewayStatsSnapshot {
    this.flushTelemetry();
    const now = Date.now();
    const storeStats = getGatewayStore().getStats();
    const loadCtrl = getGlobalLoadController();
    const penaltyBox = getGlobalPenaltyBox();
    const eventLoopDelayMs = loadCtrl.getEventLoopDelayMs();

    // Compute p50 / p95 from measured samples
    let p50 = 0;
    let p95 = 0;
    if (this.latencySamplesMs.length > 0) {
      const sorted = [...this.latencySamplesMs].sort((a, b) => a - b);
      p50 = sorted[Math.floor((sorted.length - 1) * 0.5)] || 0;
      p95 = sorted[Math.floor((sorted.length - 1) * 0.95)] || 0;
    }

    // 10s recent window RPS
    const cutoff10s = now - 10_000;
    const recent10s = this.recentTimestampsMs.filter((t) => t >= cutoff10s).length;
    const rps = Number((recent10s / 10).toFixed(2));

    // Build 15-minute chart buckets
    const currentMin = Math.floor(now / 60_000) * 60_000;
    const byMinute: GatewayStatsSnapshot['byMinute'] = [];
    for (let i = 14; i >= 0; i--) {
      const ts = currentMin - i * 60_000;
      const existing = this.minuteBuckets.get(ts);
      if (existing) {
        byMinute.push({
          minute: new Date(ts).toISOString(),
          label: existing.label,
          total: existing.total,
          allowed: existing.allowed,
          throttled: existing.throttled,
          blocked: existing.blocked,
          shed: existing.shed,
        });
      } else {
        const d = new Date(ts);
        byMinute.push({
          minute: d.toISOString(),
          label: `${String(d.getHours()).padStart(2, '0')}:${String(d.getMinutes()).padStart(2, '0')}`,
          total: 0,
          allowed: 0,
          throttled: 0,
          blocked: 0,
          shed: 0,
        });
      }
    }

    const byRouteGroup = {} as GatewayStatsSnapshot['byRouteGroup'];
    for (const g of ALL_GROUPS) {
      const item = this.byGroup.get(g)!;
      byRouteGroup[g] = { ...item };
    }

    const topThrottledKeys = Array.from(this.throttledKeyStats.values())
      .sort((a, b) => b.count - a.count)
      .slice(0, 12)
      .map((entry) => {
        const strike = penaltyBox.getStrikeInfo(entry.fullKey);
        const stage: PenaltyStage =
          strike && strike.blockedUntil > now
            ? 'BLOCKED'
            : strike && strike.strikes >= 3
            ? 'SLOWDOWN'
            : strike && strike.strikes >= 1
            ? 'WARN'
            : 'NONE';
        return {
          shortKey: entry.shortKey,
          throttledCount: entry.count,
          strikes: strike?.strikes || 0,
          stage,
          blockedUntil:
            strike && strike.blockedUntil > now
              ? new Date(strike.blockedUntil).toISOString()
              : null,
        };
      });

    const breakers = getAllBreakerStatuses('live').map((b) => ({
      channel: b.channel,
      state: b.state,
      consecutiveFailures: b.consecutiveFailures,
    }));

    return {
      totalRequests: this.totalRequests,
      requestsPerSecond: rps,
      outcomes: {
        allowed: this.allowedCount,
        throttled: this.throttledCount,
        blocked: this.blockedCount,
        shed: this.shedCount,
        oversize: this.oversizeCount,
        malformed: this.malformedCount,
        storeError: this.storeErrorCount,
      },
      byRouteGroup,
      byMinute,
      loadLevel: loadCtrl.getCurrentLevel(),
      inFlightRequests: this.inFlightRequests,
      eventLoopDelayMs,
      latencyMs: {
        p50,
        p95,
        sampleCount: this.latencySamplesMs.length,
      },
      store: storeStats,
      topThrottledKeys,
      circuitBreakers: breakers,
      generatedAt: new Date(now).toISOString(),
    };
  }
}

declare global {
  var __aegisGatewayMetrics: GatewayMetricsCollector | undefined;
}

export function getGatewayMetrics(): GatewayMetricsCollector {
  if (!global.__aegisGatewayMetrics) {
    global.__aegisGatewayMetrics = new GatewayMetricsCollector();
  }
  return global.__aegisGatewayMetrics;
}
