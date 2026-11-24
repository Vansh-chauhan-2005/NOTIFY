import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import { parseTrustedClientIp } from '../gateway/identity.js';

export const SECURITY_EVENT_TYPES = [
  'OTP_SENT',
  'OTP_VERIFIED',
  'OTP_FAILED',
  'OTP_LOCKED',
  'SMS_OTP_SENT',
  'SMS_OTP_VERIFIED',
  'SMS_OTP_FAILED',
  'SMS_OTP_LOCKED',
  'SMS_RATE_LIMIT_HIT',
  'SMS_MOCK_USED',
  'LOGIN_SUCCESS',
  'LOGIN_FAILED',
  'RATE_LIMIT_HIT',
  'MESSAGE_SENT',
  'MESSAGE_DECRYPT_FAILED',
  'SIGNATURE_INVALID',
  'CONSENT_GRANTED',
  'CONSENT_DENIED',
  'CONNECTION_CREATED',
  'CONNECTION_REMOVED',
  'INGEST_ACCEPTED',
  'INGEST_REJECTED',
  'DEVICE_SCAN_RUN',
  'DELIVERY_CREATED',
  'DELIVERY_ATTEMPT',
  'DELIVERY_ACKED',
  'DELIVERY_FALLBACK',
  'DELIVERY_FAILED',
  'CHANNEL_CIRCUIT_OPEN',
  'ACK_LINK_INVALID',
  'EPHEMERAL_CREATED',
  'EPHEMERAL_READ',
  'EPHEMERAL_BURNED',
  'EPHEMERAL_EXPIRED',
  'EPHEMERAL_ACCESS_DENIED_EXPIRED',
  'EPHEMERAL_SWEEP_RUN',
  'PROVENANCE_KEY_REGISTERED',
  'PROVENANCE_KEY_ROTATED',
  'PROVENANCE_KEY_REVOKED',
  'PROVENANCE_VERIFIED',
  'PROVENANCE_REJECTED',
  'PROVENANCE_REPLAY_BLOCKED',
  'KEY_PIN_MISMATCH',
  'KEYLOG_CHAIN_VERIFIED',
  'KEYLOG_CHAIN_BROKEN',
  'PRIORITY_SCORED',
  'PRIORITY_RULE_APPLIED',
  'PRIORITY_BUDGET_EXCEEDED',
  'PRIORITY_FEEDBACK',
  'PRIORITY_MODEL_UPDATED',
  'PRIORITY_MODEL_RESET',
  'PRIORITY_DRIFT_WARNING',
  'PRIORITY_ESCALATED',
  'DEDUP_MODEL_LOADED',
  'DEDUP_FALLBACK_USED',
  'DEDUP_MERGED',
  'DEDUP_SUGGESTED',
  'DEDUP_GUARD_BLOCKED',
  'DEDUP_UNGROUPED',
  'DEDUP_FEEDBACK',
  'DEDUP_THREAD_CAP_HIT',
  'GATEWAY_ALLOWED_SAMPLE',
  'GATEWAY_THROTTLED',
  'GATEWAY_BLOCKED',
  'GATEWAY_STRIKE',
  'GATEWAY_SHED',
  'GATEWAY_LOAD_LEVEL_CHANGED',
  'GATEWAY_OVERSIZE_REJECTED',
  'GATEWAY_MALFORMED_REJECTED',
  'GATEWAY_STORE_ERROR',
  'GATEWAY_MANUAL_BLOCK',
  'GATEWAY_POLICY_CHANGED',
  'SIGNUP_STARTED',
  'SIGNUP_COMPLETED',
  'RETURNING_DEVICE_DETECTED',
  'NEW_DEVICE_LOGIN',
  'QUARANTINE_BULK_DELETED',
] as const;

export type SecurityEventType = (typeof SECURITY_EVENT_TYPES)[number];
export type SecuritySeverity = 'info' | 'warning' | 'critical';
export type SecurityResult = 'success' | 'blocked' | 'failed';
export type ThreatLevel = 'Low' | 'Medium' | 'High';

export interface SecurityTelemetryEvent {
  id: string;
  timestamp: string;
  eventType: SecurityEventType;
  severity: SecuritySeverity;
  userId?: string;
  email?: string;
  ipAddress: string;
  userAgent: string;
  result: SecurityResult;
  details: string;
}

export interface LogSecurityEventInput {
  eventType: SecurityEventType;
  severity?: SecuritySeverity;
  userId?: string;
  email?: string;
  destination?: string;
  ipAddress?: string;
  userAgent?: string;
  result: SecurityResult;
  details: string;
}

export interface SecurityStatsPayload {
  totalEvents: number;
  blockedAttacks: number;
  countsByType: Record<SecurityEventType, number>;
  countsBySeverity: Record<SecuritySeverity, number>;
  blockedVsAllowed: {
    blocked: number;
    allowed: number;
    failed: number;
  };
  failedLogins: {
    last1h: number;
    last24h: number;
  };
  activeThreatLevel: ThreatLevel;
  eventsPerMinute: Array<{
    minute: string;
    label: string;
    total: number;
    blocked: number;
    failed: number;
    success: number;
  }>;
  generatedAt: string;
}

const AUDIT_LOG_PATH = path.resolve(process.cwd(), 'otp-audit.log');
const MAX_TELEMETRY_EVENTS = 2000;

declare global {
  var __aegisSecurityTelemetryEvents: SecurityTelemetryEvent[] | undefined;
  var __aegisSecurityTelemetryHydrated: boolean | undefined;
}

export function maskEmail(rawEmail: string): string {
  const clean = String(rawEmail || '').trim().toLowerCase();
  const atIndex = clean.indexOf('@');
  if (atIndex < 0) return clean;
  const local = clean.slice(0, atIndex);
  const domain = clean.slice(atIndex + 1);
  if (!domain) return '***';
  const visibleChar = local.length > 0 ? local[0] : '*';
  return `${visibleChar}***@${domain}`;
}

export function maskPhone(rawPhone: string): string {
  const clean = String(rawPhone || '').trim();
  const digits = clean.replace(/\D/g, '');
  if (digits.length <= 4) return '****';
  const suffix = digits.slice(-4);
  if (clean.startsWith('+') && digits.length > 6) {
    // Keep 1-2 digit country code prefix (e.g. +91******1234)
    const ccLen = digits.startsWith('1') ? 1 : 2;
    const prefix = `+${digits.slice(0, ccLen)}`;
    const maskedCount = Math.max(4, digits.length - ccLen - 4);
    return `${prefix}${'*'.repeat(maskedCount)}${suffix}`;
  }
  return `${'*'.repeat(Math.max(4, digits.length - 4))}${suffix}`;
}

export function maskIdentifier(raw?: string): string | undefined {
  if (!raw) return undefined;
  const clean = String(raw).trim();
  if (!clean) return undefined;
  if (/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(clean)) {
    return maskEmail(clean);
  }
  if (/^\+?[\d\s\-()]{7,20}$/.test(clean) && clean.replace(/\D/g, '').length >= 7) {
    return maskPhone(clean);
  }
  return clean.slice(0, 64);
}

function sanitizeDetails(raw: string): string {
  let clean = String(raw || '').replace(/[\r\n\t]+/g, ' ').trim();
  // Redact any accidental credential/secret patterns
  clean = clean
    .replace(/-----BEGIN [A-Z ]+-----[\s\S]*?-----END [A-Z ]+-----/g, '[REDACTED_KEY]')
    .replace(/Bearer\s+[A-Za-z0-9\-._~+/]+=*/gi, 'Bearer [REDACTED]')
    .replace(/\b(otp|otpCode|code|password|passwd|secret|privateKey|apiKey|token)\s*[:=]\s*[^\s,;]+/gi, '$1=[REDACTED]')
    .replace(/[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g, (match) => maskEmail(match));
  if (clean.length > 240) {
    clean = `${clean.slice(0, 237)}...`;
  }
  return clean || 'Security event recorded.';
}

function inferDefaultSeverity(eventType: SecurityEventType, result: SecurityResult): SecuritySeverity {
  if (
    eventType === 'OTP_LOCKED' ||
    eventType === 'SMS_OTP_LOCKED' ||
    eventType === 'SIGNATURE_INVALID' ||
    eventType === 'MESSAGE_DECRYPT_FAILED' ||
    eventType === 'DELIVERY_FAILED' ||
    eventType === 'KEY_PIN_MISMATCH' ||
    eventType === 'KEYLOG_CHAIN_BROKEN' ||
    eventType === 'PROVENANCE_KEY_REVOKED' ||
    eventType === 'GATEWAY_STORE_ERROR'
  ) {
    return 'critical';
  }
  if (
    eventType === 'OTP_FAILED' ||
    eventType === 'SMS_OTP_FAILED' ||
    eventType === 'SMS_RATE_LIMIT_HIT' ||
    eventType === 'SMS_MOCK_USED' ||
    eventType === 'LOGIN_FAILED' ||
    eventType === 'RATE_LIMIT_HIT' ||
    eventType === 'CONSENT_DENIED' ||
    eventType === 'INGEST_REJECTED' ||
    eventType === 'DELIVERY_FALLBACK' ||
    eventType === 'CHANNEL_CIRCUIT_OPEN' ||
    eventType === 'ACK_LINK_INVALID' ||
    eventType === 'EPHEMERAL_ACCESS_DENIED_EXPIRED' ||
    eventType === 'PROVENANCE_REJECTED' ||
    eventType === 'PROVENANCE_REPLAY_BLOCKED' ||
    eventType === 'PRIORITY_BUDGET_EXCEEDED' ||
    eventType === 'PRIORITY_DRIFT_WARNING' ||
    eventType === 'PRIORITY_ESCALATED' ||
    eventType === 'DEDUP_FALLBACK_USED' ||
    eventType === 'DEDUP_THREAD_CAP_HIT' ||
    eventType === 'GATEWAY_THROTTLED' ||
    eventType === 'GATEWAY_BLOCKED' ||
    eventType === 'GATEWAY_STRIKE' ||
    eventType === 'GATEWAY_SHED' ||
    eventType === 'GATEWAY_LOAD_LEVEL_CHANGED' ||
    eventType === 'GATEWAY_OVERSIZE_REJECTED' ||
    eventType === 'GATEWAY_MALFORMED_REJECTED' ||
    eventType === 'GATEWAY_MANUAL_BLOCK' ||
    eventType === 'NEW_DEVICE_LOGIN' ||
    result === 'blocked' ||
    result === 'failed'
  ) {
    return 'warning';
  }
  return 'info';
}

function mapLegacyAuditLine(parsed: any): SecurityTelemetryEvent | null {
  if (!parsed || typeof parsed !== 'object') return null;

  if (parsed.recordKind === 'SECURITY_TELEMETRY' && SECURITY_EVENT_TYPES.includes(parsed.eventType)) {
    return {
      id: String(parsed.id || crypto.randomUUID()),
      timestamp: String(parsed.timestamp || new Date().toISOString()),
      eventType: parsed.eventType as SecurityEventType,
      severity: (['info', 'warning', 'critical'].includes(parsed.severity)
        ? parsed.severity
        : 'info') as SecuritySeverity,
      ...(parsed.userId ? { userId: maskIdentifier(String(parsed.userId)) } : {}),
      ...(parsed.email ? { email: maskEmail(String(parsed.email)) } : {}),
      ipAddress: String(parsed.ipAddress || parsed.ip || 'unknown').slice(0, 100),
      userAgent: String(parsed.userAgent || 'unknown').slice(0, 200),
      result: (['success', 'blocked', 'failed'].includes(parsed.result)
        ? parsed.result
        : 'success') as SecurityResult,
      details: sanitizeDetails(String(parsed.details || '')),
    };
  }

  // Hydrate legacy OTP_REQUEST / OTP_VERIFY lines already stored in otp-audit.log
  if (parsed.eventType === 'OTP_REQUEST' || parsed.eventType === 'OTP_VERIFY') {
    const action = String(parsed.action || '');
    let mappedType: SecurityEventType = 'OTP_FAILED';
    let result: SecurityResult = 'failed';
    let severity: SecuritySeverity = 'warning';

    if (action === 'OTP_SENT') {
      mappedType = 'OTP_SENT';
      result = 'success';
      severity = 'info';
    } else if (action === 'OTP_VERIFY_SUCCESS' || action === 'FIREBASE_VERIFY_SUCCESS') {
      mappedType = 'OTP_VERIFIED';
      result = 'success';
      severity = 'info';
    } else if (action === 'FIREBASE_GOOGLE_SIGNIN') {
      mappedType = 'LOGIN_SUCCESS';
      result = 'success';
      severity = 'info';
    } else if (action === 'FIREBASE_GOOGLE_SIGNIN_FAILED') {
      mappedType = 'LOGIN_FAILED';
      result = 'failed';
      severity = 'warning';
    } else if (
      action === 'OTP_LOCKED_MAX_ATTEMPTS' ||
      action === 'OTP_REQUEST_BLOCKED_LOCKED' ||
      action === 'OTP_VERIFY_BLOCKED_LOCKED'
    ) {
      mappedType = 'OTP_LOCKED';
      result = 'blocked';
      severity = 'critical';
    } else if (
      action === 'OTP_REQUEST_BLOCKED_COOLDOWN' ||
      action === 'OTP_REQUEST_BLOCKED_DAILY_LIMIT'
    ) {
      mappedType = 'RATE_LIMIT_HIT';
      result = 'blocked';
      severity = 'warning';
    } else {
      mappedType = 'OTP_FAILED';
      result = parsed.outcome === 'BLOCKED' ? 'blocked' : 'failed';
      severity = 'warning';
    }

    const dest = String(parsed.destination || '').trim();
    const isEmail = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(dest);

    return {
      id: String(parsed.id || crypto.randomUUID()),
      timestamp: String(parsed.timestamp || new Date().toISOString()),
      eventType: mappedType,
      severity,
      ...(isEmail
        ? { email: maskEmail(dest) }
        : dest
        ? { userId: maskIdentifier(dest) }
        : {}),
      ipAddress: String(parsed.ip || 'unknown').slice(0, 100),
      userAgent: String(parsed.userAgent || 'unknown').slice(0, 200),
      result,
      details: sanitizeDetails(String(parsed.reason || action || 'Audit event')),
    };
  }

  return null;
}

function getTelemetryStore(): SecurityTelemetryEvent[] {
  if (!global.__aegisSecurityTelemetryEvents) {
    global.__aegisSecurityTelemetryEvents = [];
  }

  if (!global.__aegisSecurityTelemetryHydrated) {
    global.__aegisSecurityTelemetryHydrated = true;
    try {
      if (fs.existsSync(AUDIT_LOG_PATH)) {
        const raw = fs.readFileSync(AUDIT_LOG_PATH, 'utf8');
        const lines = raw.split('\n').filter((line) => line.trim().length > 0);
        const recent = lines.slice(-MAX_TELEMETRY_EVENTS);
        const parsedLines: any[] = [];
        for (const line of recent) {
          try {
            parsedLines.push(JSON.parse(line));
          } catch {
            // Skip malformed line
          }
        }

        // Prefer structured SECURITY_TELEMETRY records; only map legacy OTP_REQUEST/OTP_VERIFY
        // entries when no SECURITY_TELEMETRY record shares the same timestamp+action window
        const telemetryTimestamps = new Set<string>();
        for (const row of parsedLines) {
          if (row?.recordKind === 'SECURITY_TELEMETRY' && row.timestamp) {
            telemetryTimestamps.add(String(row.timestamp).slice(0, 19));
          }
        }

        for (const row of parsedLines) {
          if (row?.recordKind !== 'SECURITY_TELEMETRY') {
            const secBucket = String(row?.timestamp || '').slice(0, 19);
            if (secBucket && telemetryTimestamps.has(secBucket)) {
              continue;
            }
          }
          const mapped = mapLegacyAuditLine(row);
          if (mapped) {
            global.__aegisSecurityTelemetryEvents.push(mapped);
          }
        }
      }
    } catch {
      // Non-fatal if audit file is unavailable
    }
  }

  return global.__aegisSecurityTelemetryEvents;
}

export function extractRequestContext(request?: Request | null): {
  ipAddress: string;
  userAgent: string;
} {
  if (!request) {
    return { ipAddress: 'internal', userAgent: 'server' };
  }
  const forwarded = request.headers.get('x-forwarded-for');
  const realIp = request.headers.get('x-real-ip');
  const ipRaw = parseTrustedClientIp({
    socketRemoteAddress: realIp || '127.0.0.1',
    xForwardedFor: forwarded,
  });
  const uaRaw = request.headers.get('user-agent') || 'unknown';
  return {
    ipAddress: ipRaw.trim().slice(0, 100) || 'local',
    userAgent: uaRaw.trim().slice(0, 200) || 'unknown',
  };
}

export function logSecurityEvent(input: LogSecurityEventInput): SecurityTelemetryEvent {
  const store = getTelemetryStore();
  const timestamp = new Date().toISOString();
  const id = crypto.randomUUID();
  const severity = input.severity || inferDefaultSeverity(input.eventType, input.result);

  const rawEmail =
    input.email ||
    (input.destination && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(input.destination.trim())
      ? input.destination.trim()
      : undefined);

  const maskedEmail = rawEmail ? maskEmail(rawEmail) : undefined;
  const maskedUserId = input.userId
    ? maskIdentifier(input.userId)
    : !maskedEmail && input.destination
    ? maskIdentifier(input.destination)
    : undefined;

  const event: SecurityTelemetryEvent = {
    id,
    timestamp,
    eventType: input.eventType,
    severity,
    ...(maskedUserId ? { userId: maskedUserId } : {}),
    ...(maskedEmail ? { email: maskedEmail } : {}),
    ipAddress: String(input.ipAddress || 'local').trim().slice(0, 100) || 'local',
    userAgent: String(input.userAgent || 'unknown').trim().slice(0, 200) || 'unknown',
    result: input.result,
    details: sanitizeDetails(input.details),
  };

  store.push(event);
  if (store.length > MAX_TELEMETRY_EVENTS) {
    store.splice(0, store.length - MAX_TELEMETRY_EVENTS);
  }

  // Persist into the existing audit log storage (otp-audit.log) with masked identifiers only
  try {
    const auditRecord = {
      recordKind: 'SECURITY_TELEMETRY',
      ...event,
      destination: maskedEmail || maskedUserId || 'system',
    };
    fs.appendFileSync(AUDIT_LOG_PATH, `${JSON.stringify(auditRecord)}\n`, 'utf8');
  } catch {
    // Keep in-memory telemetry operational even if disk is read-only
  }

  return event;
}

export function getSecurityEvents(filters: {
  limit?: number;
  severity?: string;
  type?: string;
} = {}): { events: SecurityTelemetryEvent[]; totalMatching: number } {
  const store = getTelemetryStore();
  const limit = Math.min(500, Math.max(1, Number(filters.limit) || 100));
  const severityFilter = (filters.severity || '').trim().toLowerCase();
  const typeFilter = (filters.type || '').trim().toUpperCase();

  let filtered = [...store];

  if (severityFilter && ['info', 'warning', 'critical'].includes(severityFilter)) {
    filtered = filtered.filter((ev) => ev.severity === severityFilter);
  }

  if (typeFilter && SECURITY_EVENT_TYPES.includes(typeFilter as SecurityEventType)) {
    filtered = filtered.filter((ev) => ev.eventType === typeFilter);
  }

  const totalMatching = filtered.length;
  const events = filtered.reverse().slice(0, limit);

  return { events, totalMatching };
}

export function getSecurityStats(): SecurityStatsPayload {
  const store = getTelemetryStore();
  const now = Date.now();
  const oneHourAgo = now - 60 * 60 * 1000;
  const twentyFourHoursAgo = now - 24 * 60 * 60 * 1000;
  const fifteenMinsAgo = now - 15 * 60 * 1000;

  const countsByType = {} as Record<SecurityEventType, number>;
  for (const t of SECURITY_EVENT_TYPES) {
    countsByType[t] = 0;
  }

  const countsBySeverity: Record<SecuritySeverity, number> = {
    info: 0,
    warning: 0,
    critical: 0,
  };

  let blocked = 0;
  let allowed = 0;
  let failed = 0;
  let blockedAttacks = 0;
  let failedLogins1h = 0;
  let failedLogins24h = 0;
  let critical1h = 0;
  let recentFailures15m = 0;
  let blocked1h = 0;

  // Build 15-minute rolling bucket map (last 15 minutes inclusive)
  const bucketCount = 15;
  const currentMinuteFloor = Math.floor(now / 60000) * 60000;
  const buckets = new Map<
    number,
    { minute: string; label: string; total: number; blocked: number; failed: number; success: number }
  >();

  for (let i = bucketCount - 1; i >= 0; i--) {
    const ts = currentMinuteFloor - i * 60000;
    const d = new Date(ts);
    const hh = String(d.getHours()).padStart(2, '0');
    const mm = String(d.getMinutes()).padStart(2, '0');
    buckets.set(ts, {
      minute: d.toISOString(),
      label: `${hh}:${mm}`,
      total: 0,
      blocked: 0,
      failed: 0,
      success: 0,
    });
  }

  for (const ev of store) {
    if (countsByType[ev.eventType] !== undefined) {
      countsByType[ev.eventType] += 1;
    }
    if (countsBySeverity[ev.severity] !== undefined) {
      countsBySeverity[ev.severity] += 1;
    }

    if (ev.result === 'blocked') {
      blocked += 1;
    } else if (ev.result === 'success') {
      allowed += 1;
    } else {
      failed += 1;
    }

    if (
      ev.result === 'blocked' ||
      ev.eventType === 'SIGNATURE_INVALID' ||
      ev.eventType === 'INGEST_REJECTED' ||
      ev.eventType === 'OTP_LOCKED' ||
      ev.eventType === 'SMS_OTP_LOCKED' ||
      ev.eventType === 'RATE_LIMIT_HIT' ||
      ev.eventType === 'SMS_RATE_LIMIT_HIT' ||
      ev.eventType === 'PROVENANCE_REJECTED' ||
      ev.eventType === 'PROVENANCE_REPLAY_BLOCKED' ||
      ev.eventType === 'KEY_PIN_MISMATCH' ||
      ev.eventType === 'GATEWAY_THROTTLED' ||
      ev.eventType === 'GATEWAY_BLOCKED' ||
      ev.eventType === 'GATEWAY_SHED' ||
      ev.eventType === 'GATEWAY_OVERSIZE_REJECTED' ||
      ev.eventType === 'GATEWAY_MALFORMED_REJECTED'
    ) {
      blockedAttacks += 1;
    }

    const evTime = Date.parse(ev.timestamp);
    if (!Number.isNaN(evTime)) {
      const isAuthFailure =
        ev.eventType === 'LOGIN_FAILED' ||
        ev.eventType === 'OTP_FAILED' ||
        ev.eventType === 'OTP_LOCKED' ||
        ev.eventType === 'SMS_OTP_FAILED' ||
        ev.eventType === 'SMS_OTP_LOCKED';

      if (isAuthFailure && evTime >= twentyFourHoursAgo) {
        failedLogins24h += 1;
        if (evTime >= oneHourAgo) {
          failedLogins1h += 1;
        }
      }

      if (evTime >= oneHourAgo) {
        if (ev.severity === 'critical') critical1h += 1;
        if (ev.result === 'blocked') blocked1h += 1;
      }

      if (evTime >= fifteenMinsAgo && (ev.result === 'failed' || ev.result === 'blocked')) {
        recentFailures15m += 1;
      }

      const evMinute = Math.floor(evTime / 60000) * 60000;
      const bucket = buckets.get(evMinute);
      if (bucket) {
        bucket.total += 1;
        if (ev.result === 'blocked') bucket.blocked += 1;
        else if (ev.result === 'failed') bucket.failed += 1;
        else bucket.success += 1;
      }
    }
  }

  let activeThreatLevel: ThreatLevel = 'Low';
  if (critical1h >= 5 || recentFailures15m >= 10 || blocked1h >= 8) {
    activeThreatLevel = 'High';
  } else if (critical1h >= 1 || recentFailures15m >= 3 || blocked1h >= 3 || failedLogins1h >= 3) {
    activeThreatLevel = 'Medium';
  }

  return {
    totalEvents: store.length,
    blockedAttacks,
    countsByType,
    countsBySeverity,
    blockedVsAllowed: {
      blocked,
      allowed,
      failed,
    },
    failedLogins: {
      last1h: failedLogins1h,
      last24h: failedLogins24h,
    },
    activeThreatLevel,
    eventsPerMinute: Array.from(buckets.values()),
    generatedAt: new Date(now).toISOString(),
  };
}
