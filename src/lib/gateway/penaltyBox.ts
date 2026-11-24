import crypto from 'crypto';
import { shortKeyHash } from './identity.js';
import type {
  ClockFn,
  GatewayAllowlistRecord,
  GatewayAuditEntry,
  GatewayBlockRecord,
  PenaltyStage,
  StrikeRecord,
} from './types.js';

const STRIKE_DECAY_INTERVAL_MS = 10 * 60 * 1000; // 1 strike decays every 10 quiet minutes
const MAX_BLOCK_DURATION_MS = 24 * 60 * 60 * 1000; // Hard cap: 24h
const IP_ONLY_MAX_BLOCK_MS = 5 * 60 * 1000; // Protect shared IPs from long collateral lockouts

const PROGRESSIVE_BLOCK_DURATIONS_MS = [
  60 * 1000, // Level 1: 1 min
  5 * 60 * 1000, // Level 2: 5 min
  30 * 60 * 1000, // Level 3: 30 min
  24 * 60 * 60 * 1000, // Level 4: 24 h (hard cap)
];

export class PenaltyBoxManager {
  private readonly strikes = new Map<string, StrikeRecord>();
  private readonly manualBlocks = new Map<string, GatewayBlockRecord>();
  private readonly allowlist = new Map<string, GatewayAllowlistRecord>();
  private readonly auditLog: GatewayAuditEntry[] = [];
  private readonly clock: ClockFn;

  constructor(options: { clock?: ClockFn } = {}) {
    this.clock = options.clock ?? Date.now;
  }

  private decayStrikes(rec: StrikeRecord, now: number): void {
    const anchor = Math.max(rec.lastStrikeAt, rec.blockedUntil || 0);
    if (now <= anchor) return;
    const elapsed = now - anchor;
    const decaySteps = Math.floor(elapsed / STRIKE_DECAY_INTERVAL_MS);
    if (decaySteps > 0) {
      rec.strikes = Math.max(0, rec.strikes - decaySteps);
      if (rec.strikes === 0) {
        rec.blockLevel = 0;
      } else if (decaySteps >= 2) {
        rec.blockLevel = Math.max(0, rec.blockLevel - Math.floor(decaySteps / 2));
      }
      rec.lastStrikeAt = now;
    }
  }

  /**
   * Checks whether a set of keys matches an active allowlist entry.
   */
  getActiveAllowlist(keys: string[]): GatewayAllowlistRecord | null {
    const now = this.clock();
    for (const [id, entry] of this.allowlist.entries()) {
      const expMs = Date.parse(entry.expiresAt);
      if (Number.isFinite(expMs) && now >= expMs) {
        this.allowlist.delete(id);
        continue;
      }
      for (const k of keys) {
        if (k === entry.hashedKey || k.includes(entry.hashedKey)) {
          return { ...entry };
        }
      }
    }
    return null;
  }

  /**
   * Checks manual blocks and automatic strike blocks for any of the client's keys.
   */
  checkBlocked(keys: string[]): {
    blocked: boolean;
    stage: PenaltyStage;
    retryAfterSeconds: number;
    artificialDelayMs: number;
    reason?: string;
    keyMatched?: string;
  } {
    const now = this.clock();

    // Allowlisted clients bypass auto blocks & slowdowns (manual admin block still overrides if explicitly placed later)
    const allowlisted = this.getActiveAllowlist(keys);

    // 1. Check manual admin blocks
    for (const [id, block] of this.manualBlocks.entries()) {
      const expMs = Date.parse(block.expiresAt);
      if (Number.isFinite(expMs) && now >= expMs) {
        this.manualBlocks.delete(id);
        continue;
      }
      for (const k of keys) {
        if (k === block.hashedKey || k.includes(block.hashedKey)) {
          return {
            blocked: true,
            stage: 'BLOCKED',
            retryAfterSeconds: Math.max(1, Math.ceil((expMs - now) / 1000)),
            artificialDelayMs: 0,
            reason: block.reason || 'Temporarily blocked by administrator policy.',
            keyMatched: block.shortKey,
          };
        }
      }
    }

    if (allowlisted) {
      return {
        blocked: false,
        stage: 'NONE',
        retryAfterSeconds: 0,
        artificialDelayMs: 0,
      };
    }

    // 2. Check automatic strike penalty state
    let worstStage: PenaltyStage = 'NONE';
    let maxDelayMs = 0;

    for (const k of keys) {
      const rec = this.strikes.get(k);
      if (!rec) continue;
      this.decayStrikes(rec, now);

      if (rec.blockedUntil > now) {
        return {
          blocked: true,
          stage: 'BLOCKED',
          retryAfterSeconds: Math.max(1, Math.ceil((rec.blockedUntil - now) / 1000)),
          artificialDelayMs: 0,
          reason: `Penalty box block active (level ${rec.blockLevel}, strikes=${rec.strikes}).`,
          keyMatched: rec.shortKey,
        };
      }

      if (rec.strikes >= 3) {
        worstStage = 'SLOWDOWN';
        maxDelayMs = Math.max(maxDelayMs, Math.min(500, (rec.strikes - 2) * 150));
      } else if (rec.strikes >= 1 && worstStage === 'NONE') {
        worstStage = 'WARN';
      }
    }

    return {
      blocked: false,
      stage: worstStage,
      retryAfterSeconds: 0,
      artificialDelayMs: maxDelayMs,
    };
  }

  /**
   * Records a 429 throttle strike for a key and returns progressive penalty escalation.
   */
  recordStrike(params: { key: string; isIpOnlyKey?: boolean }): {
    record: StrikeRecord;
    stage: PenaltyStage;
    justBlocked: boolean;
    blockDurationSeconds: number;
  } {
    const now = this.clock();
    const shortKey = shortKeyHash(params.key.replace(/^(ip|user|conn|acct):/, ''));
    let rec = this.strikes.get(params.key);

    if (!rec) {
      rec = {
        key: params.key,
        shortKey,
        strikes: 0,
        lastStrikeAt: now,
        blockLevel: 0,
        blockedUntil: 0,
        lastUpdatedAt: now,
      };
      this.strikes.set(params.key, rec);
    } else {
      this.decayStrikes(rec, now);
    }

    rec.strikes += 1;
    rec.lastStrikeAt = now;
    rec.lastUpdatedAt = now;

    // Keep bounded map size in penalty box too (max 20k strike records)
    if (this.strikes.size > 20_000) {
      const oldest = this.strikes.keys().next().value;
      if (oldest) this.strikes.delete(oldest);
    }

    let stage: PenaltyStage = 'WARN';
    let justBlocked = false;
    let blockDurationSeconds = 0;

    if (rec.strikes >= 5) {
      stage = 'BLOCKED';
      const idx = Math.min(PROGRESSIVE_BLOCK_DURATIONS_MS.length - 1, rec.blockLevel);
      let durationMs = PROGRESSIVE_BLOCK_DURATIONS_MS[idx];
      if (params.isIpOnlyKey) {
        // Shared IP protection: IP-only auto blocks stay short
        durationMs = Math.min(durationMs, IP_ONLY_MAX_BLOCK_MS);
      }
      durationMs = Math.min(durationMs, MAX_BLOCK_DURATION_MS);
      rec.blockLevel = Math.min(PROGRESSIVE_BLOCK_DURATIONS_MS.length, rec.blockLevel + 1);
      rec.blockedUntil = now + durationMs;
      justBlocked = true;
      blockDurationSeconds = Math.ceil(durationMs / 1000);
    } else if (rec.strikes >= 3) {
      stage = 'SLOWDOWN';
    }

    return {
      record: { ...rec },
      stage,
      justBlocked,
      blockDurationSeconds,
    };
  }

  /**
   * Rewards good authenticated behaviour by reducing strikes gently without resetting manual blocks.
   */
  recordGoodBehavior(key: string): void {
    const rec = this.strikes.get(key);
    if (!rec) return;
    const now = this.clock();
    this.decayStrikes(rec, now);
    rec.strikes = Math.max(0, rec.strikes - 1);
    rec.lastUpdatedAt = now;
    if (rec.strikes === 0 && rec.blockedUntil <= now) {
      this.strikes.delete(key);
    }
  }

  addManualBlock(params: {
    hashedKey: string;
    scope?: GatewayBlockRecord['scope'];
    reason: string;
    durationMinutes: number;
    adminId: string;
  }): GatewayBlockRecord {
    const now = this.clock();
    const safeMinutes = Math.max(1, Math.min(24 * 60, Math.floor(params.durationMinutes)));
    const expiresAt = new Date(now + safeMinutes * 60 * 1000).toISOString();
    const id = `blk_${crypto.randomBytes(6).toString('hex')}`;
    const shortKey = shortKeyHash(params.hashedKey.replace(/^(ip|user|conn|acct):/, ''));

    const record: GatewayBlockRecord = {
      id,
      hashedKey: params.hashedKey.trim(),
      shortKey,
      scope: params.scope || 'manual',
      reason: params.reason.trim().slice(0, 200) || 'Manual administrator block',
      manual: true,
      createdByAdminId: params.adminId,
      createdAt: new Date(now).toISOString(),
      expiresAt,
    };

    this.manualBlocks.set(id, record);
    this.appendAudit({
      adminId: params.adminId,
      action: 'MANUAL_BLOCK',
      targetShortKey: shortKey,
      details: `Blocked key ${shortKey} for ${safeMinutes}m (${record.reason})`,
    });
    return { ...record };
  }

  removeBlock(blockIdOrKey: string, adminId: string): boolean {
    let removed = false;
    let targetShort = shortKeyHash(blockIdOrKey);

    if (this.manualBlocks.has(blockIdOrKey)) {
      const existing = this.manualBlocks.get(blockIdOrKey)!;
      targetShort = existing.shortKey;
      this.manualBlocks.delete(blockIdOrKey);
      removed = true;
    }

    for (const [k, rec] of this.strikes.entries()) {
      if (k === blockIdOrKey || rec.shortKey === blockIdOrKey) {
        targetShort = rec.shortKey;
        this.strikes.delete(k);
        removed = true;
      }
    }

    if (removed) {
      this.appendAudit({
        adminId,
        action: 'UNBLOCK',
        targetShortKey: targetShort,
        details: `Removed gateway block for ${targetShort}`,
      });
    }
    return removed;
  }

  addAllowlist(params: {
    hashedKey: string;
    label: string;
    durationMinutes: number;
    multiplier?: number;
    adminId: string;
  }): GatewayAllowlistRecord {
    const now = this.clock();
    const safeMinutes = Math.max(1, Math.min(7 * 24 * 60, Math.floor(params.durationMinutes)));
    const expiresAt = new Date(now + safeMinutes * 60 * 1000).toISOString();
    const id = `alw_${crypto.randomBytes(6).toString('hex')}`;
    const shortKey = shortKeyHash(params.hashedKey.replace(/^(ip|user|conn|acct):/, ''));
    const multiplier = Math.max(1.5, Math.min(10, Number(params.multiplier ?? 3)));

    const record: GatewayAllowlistRecord = {
      id,
      hashedKey: params.hashedKey.trim(),
      shortKey,
      label: params.label.trim().slice(0, 80) || 'Trusted Allowlist Entry',
      multiplier,
      createdByAdminId: params.adminId,
      createdAt: new Date(now).toISOString(),
      expiresAt,
    };

    this.allowlist.set(id, record);
    this.appendAudit({
      adminId: params.adminId,
      action: 'ALLOWLIST_ADD',
      targetShortKey: shortKey,
      details: `Allowlisted ${shortKey} (${record.label}) for ${safeMinutes}m (${multiplier}x ceiling)`,
    });
    return { ...record };
  }

  removeAllowlist(id: string, adminId: string): boolean {
    const existing = this.allowlist.get(id);
    if (!existing) return false;
    this.allowlist.delete(id);
    this.appendAudit({
      adminId,
      action: 'ALLOWLIST_REMOVE',
      targetShortKey: existing.shortKey,
      details: `Removed allowlist entry ${existing.shortKey} (${existing.label})`,
    });
    return true;
  }

  appendAudit(entry: Omit<GatewayAuditEntry, 'id' | 'timestamp'>): GatewayAuditEntry {
    const record: GatewayAuditEntry = {
      id: `aud_${crypto.randomBytes(6).toString('hex')}`,
      timestamp: new Date(this.clock()).toISOString(),
      ...entry,
    };
    this.auditLog.unshift(record);
    if (this.auditLog.length > 200) {
      this.auditLog.length = 200;
    }
    return record;
  }

  listActiveBlocks(): GatewayBlockRecord[] {
    const now = this.clock();
    const list: GatewayBlockRecord[] = [];

    for (const [id, block] of this.manualBlocks.entries()) {
      if (Date.parse(block.expiresAt) <= now) {
        this.manualBlocks.delete(id);
        continue;
      }
      list.push({ ...block });
    }

    for (const [k, rec] of this.strikes.entries()) {
      this.decayStrikes(rec, now);
      if (rec.blockedUntil > now) {
        list.push({
          id: k,
          hashedKey: rec.key,
          shortKey: rec.shortKey,
          scope: k.startsWith('ip:') ? 'ip' : k.startsWith('user:') ? 'user' : 'connection',
          reason: `Auto penalty box (level ${rec.blockLevel}, ${rec.strikes} strikes)`,
          manual: false,
          createdAt: new Date(rec.lastStrikeAt).toISOString(),
          expiresAt: new Date(rec.blockedUntil).toISOString(),
        });
      }
    }

    return list.sort((a, b) => Date.parse(b.createdAt) - Date.parse(a.createdAt));
  }

  listAllowlist(): GatewayAllowlistRecord[] {
    const now = this.clock();
    const list: GatewayAllowlistRecord[] = [];
    for (const [id, item] of this.allowlist.entries()) {
      if (Date.parse(item.expiresAt) <= now) {
        this.allowlist.delete(id);
        continue;
      }
      list.push({ ...item });
    }
    return list.sort((a, b) => Date.parse(b.createdAt) - Date.parse(a.createdAt));
  }

  listAuditLog(): GatewayAuditEntry[] {
    return this.auditLog.map((e) => ({ ...e }));
  }

  getStrikeInfo(key: string): StrikeRecord | null {
    const rec = this.strikes.get(key);
    if (!rec) return null;
    this.decayStrikes(rec, this.clock());
    return { ...rec };
  }
}

declare global {
  var __aegisGatewayPenaltyBox: PenaltyBoxManager | undefined;
}

export function getGlobalPenaltyBox(): PenaltyBoxManager {
  if (!global.__aegisGatewayPenaltyBox) {
    global.__aegisGatewayPenaltyBox = new PenaltyBoxManager();
  }
  return global.__aegisGatewayPenaltyBox;
}
